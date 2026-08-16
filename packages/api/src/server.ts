import path from "node:path";
import { fileURLToPath } from "node:url";
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import {
  VulnerabilityScanner,
  IntelligenceAnalyzer,
  Evaluator,
  getDB,
  disconnectDB,
} from "@vuln-shield/core";
import type {
  EvalMetrics,
  RepositoryProfile,
  RSISScore,
  ScanReport,
} from "@vuln-shield/core";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load env from the actual workspace root, not from the process CWD.
dotenv.config({ path: path.resolve(__dirname, "../../../.env") });

const app = express();
const PORT = Number(process.env.PORT) || 3005;
const allowedOrigins = new Set(
  (process.env.WEB_ORIGIN || "http://localhost:3000")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean)
);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      callback(null, true);
      return;
    }
    callback(new Error("Origin not allowed by CORS"));
  },
}));
app.use(express.json());

function parseJson<T>(value: string | null | undefined, fallback: T): T {
  if (!value) return fallback;
  try {
    return JSON.parse(value) as T;
  } catch {
    return fallback;
  }
}

function toScanReport(scan: any): ScanReport {
  const severityCounts: ScanReport["severityCounts"] = {
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0,
  };
  const results = (scan.dependencies ?? []).map((dep: any) => ({
    dependency: { name: dep.name, version: dep.version, ecosystem: dep.ecosystem, isDev: dep.isDev, manifestPath: dep.manifestPath },
    vulnerabilities: (dep.vulnerabilities ?? []).map((v: any) => {
      const severity = severityCounts[v.severity as keyof typeof severityCounts] === undefined ? "UNKNOWN" : v.severity;
      severityCounts[severity as keyof typeof severityCounts] += 1;
      return {
        cveId: v.cveId, osvId: v.osvId ?? undefined, githubAdvisoryId: v.githubAdvisoryId ?? undefined,
        severity, cvssScore: v.cvssScore ?? null, cvssVector: v.cvssVector ?? null,
        summary: v.summary, details: v.details ?? null, publishedDate: v.publishedDate ?? null, modifiedDate: v.modifiedDate ?? null,
        fixedVersions: parseJson<string[]>(v.fixedVersions, []), references: parseJson<string[]>(v.references, []),
        source: v.source, affectedRange: v.affectedRange ?? null, kev: Boolean(v.kev), mitigationGuidance: v.mitigationGuidance ?? null,
      };
    }),
  }));
  return {
    scanId: scan.id, repoUrl: scan.repoUrl, repoOwner: scan.repoOwner, repoName: scan.repoName,
    scannedAt: (scan.completedAt ?? scan.createdAt ?? new Date()).toISOString(),
    totalDependencies: scan.totalDeps ?? results.length,
    totalVulnerabilities: scan.totalVulns ?? results.reduce((total: number, result: any) => total + result.vulnerabilities.length, 0),
    severityCounts, results,
  } as ScanReport;
}

function toProfile(metadata: any): RepositoryProfile | null {
  if (!metadata) return null;
  return {
    language: metadata.language ?? null, languages: parseJson(metadata.languages, {}), framework: metadata.framework ?? null,
    purpose: metadata.purpose ?? null, topics: parseJson(metadata.topics, []), description: metadata.description ?? null,
    folderHierarchy: parseJson(metadata.folderHierarchy, []), totalFiles: metadata.totalFiles ?? 0,
    hasDockerfile: Boolean(metadata.hasDockerfile), hasCiCd: Boolean(metadata.hasCiCd), hasTests: Boolean(metadata.hasTests),
    stars: metadata.stars ?? 0, forks: metadata.forks ?? 0, openIssues: metadata.openIssues ?? 0,
    lastPushed: metadata.lastPushed?.toISOString?.() ?? null, architecture: metadata.architecture ?? null,
    repositoryType: metadata.repositoryType ?? "unknown", database: metadata.database ?? null, orm: metadata.orm ?? null,
    authentication: metadata.authentication ?? null, deployment: metadata.deployment ?? null,
    ciCdPlatform: metadata.ciCdPlatform ?? null, testingFramework: metadata.testingFramework ?? null,
    packageManagers: parseJson(metadata.packageManagers, []), primaryDependencies: parseJson(metadata.primaryDependencies, []),
  } as RepositoryProfile;
}

function toRsis(record: any): RSISScore {
  const weights = parseJson(record?.weights, { security: 0.3, retrieval: 0.2, validation: 0.2, maintainability: 0.15, compatibility: 0.15 });
  const signals = parseJson(record?.signals, { criticalVulns: 0, highVulns: 0, mediumVulns: 0, lowVulns: 0, totalVulns: 0, totalDeps: 0, highConfidenceCandidates: 0, totalCandidates: 0, meanRetrievalSimilarity: 0, hybridMRR: 0, validatedCandidates: 0, totalValidated: 0, recentDeps: 0, kevCount: 0, semverCompatRate: 0 });
  const totalScore = record?.totalScore ?? 0;
  return {
    totalScore, securityScore: record?.severityScore ?? 0, retrievalScore: record?.retrievalScore ?? 0,
    validationScore: record?.validationScore ?? 0, maintainabilityScore: record?.maintainabilityScore ?? 0,
    compatibilityScore: record?.compatibilityScore ?? record?.remediationScore ?? 0, weights, signals,
    rationale: { formula: "", citations: [], ablationNotes: "" },
    grade: totalScore >= 85 ? "A" : totalScore >= 70 ? "B" : totalScore >= 55 ? "C" : totalScore >= 40 ? "D" : "F",
  };
}

// ─── Health Check ───────────────────────────────────────────────────────────

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", service: "vuln-shield-api", timestamp: new Date().toISOString() });
});

// ─── Start a New Basic Scan (Phase 1) ───────────────────────────────────────

app.post("/api/scan", async (req, res) => {
  const { repoUrl, useNVD, skipDev } = req.body;

  if (!repoUrl || typeof repoUrl !== "string") {
    res.status(400).json({ error: "repoUrl is required" });
    return;
  }

  try {
    const scanner = new VulnerabilityScanner();
    const report = await scanner.scan(repoUrl, {
      useNVD: useNVD || false,
      skipDev: skipDev || false,
      persist: true,
    });

    res.json(report);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed";
    const statusCode = message.includes("No dependency manifest files found") ? 400 : 500;
    res.status(statusCode).json({ error: message });
  }
});

// ─── Get Scan by ID ─────────────────────────────────────────────────────────

app.get("/api/scan/:id", async (req, res) => {
  try {
    const db = getDB();
    const scan = await db.scan.findUnique({
      where: { id: req.params.id },
      include: {
        dependencies: {
          include: {
            vulnerabilities: true,
          },
        },
      },
    });

    if (!scan) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }

    res.json(toScanReport(scan));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to fetch scan";
    res.status(500).json({ error: message });
  }
});

// ─── List All Scans ─────────────────────────────────────────────────────────

app.get("/api/scans", async (_req, res) => {
  try {
    const db = getDB();
    const scans = await db.scan.findMany({
      orderBy: { createdAt: "desc" },
      take: 50,
    });

    res.json(scans);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to fetch scans";
    res.status(500).json({ error: message });
  }
});

// ─── Phase 2: Full Intelligence Analysis ───────────────────────────────────

app.post("/api/analyze", async (req, res) => {
  const { repoUrl, useNVD, skipDev, skipEmbedding, skipSimilarRepos, skipReasoning, maxRemediations } = req.body;

  if (!repoUrl || typeof repoUrl !== "string") {
    res.status(400).json({ error: "repoUrl is required" });
    return;
  }

  try {
    const analyzer = new IntelligenceAnalyzer();
    const result = await analyzer.analyze(repoUrl, {
      useNVD: useNVD || false,
      skipDev: skipDev || false,
      skipEmbedding: skipEmbedding || false,
      skipSimilarRepos: skipSimilarRepos || false,
      skipReasoning: skipReasoning || false,
      maxRemediations: maxRemediations || 10,
      persist: true,
    });

    res.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Analysis failed";
    const statusCode = message.includes("No dependency manifest files found") ? 400 : 500;
    res.status(statusCode).json({ error: message });
  }
});

// ─── Get Full Analysis by Scan ID ──────────────────────────────────────────

app.get("/api/analyze/:id", async (req, res) => {
  try {
    const db = getDB();
    const scanId = req.params.id;

    const scan = await db.scan.findUnique({
      where: { id: scanId },
      include: {
        dependencies: {
          include: {
            vulnerabilities: true,
          },
        },
        metadata: true,
        similarRepos: true,
        remediations: true,
        rsisScore: true,
      },
    });

    if (!scan) {
      res.status(404).json({ error: "Analysis not found for this scan ID" });
      return;
    }

    const chunksIndexed = await db.repositoryChunk.count({ where: { scanId } });
    const profile = toProfile(scan.metadata);
    const rsis = toRsis(scan.rsisScore);
    res.json({
      scanId: scan.id,
      scan: toScanReport(scan),
      metadata: profile,
      repositoryProfile: profile,
      knowledgeGraph: parseJson(scan.knowledgeGraph, { nodes: [], edges: [] }),
      chunksIndexed,
      similarRepos: scan.similarRepos.map((repo: any) => ({ ...repo, topics: parseJson(repo.topics, []) })),
      remediations: scan.remediations.map((report: any) => ({
        scanId: report.scanId, cveId: report.cveId, packageName: report.packageName, ecosystem: report.ecosystem,
        candidates: parseJson(report.candidates, []), reasoningTrace: report.reasoningTrace,
        contextChunks: [], validationPassed: report.validationPassed,
      })),
      rsis,
      intelligenceSummary: parseJson(scan.intelligenceSummary, null),
      aiEnabled: Boolean(process.env.GROQ_API_KEY || process.env.GEMINI_API_KEY),
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to fetch analysis";
    res.status(500).json({ error: message });
  }
});

// ─── Get RSIS Score Breakdown ───────────────────────────────────────────────

app.get("/api/analyze/:id/rsis", async (req, res) => {
  try {
    const db = getDB();
    const rsis = await db.rSISScore.findUnique({
      where: { scanId: req.params.id },
    });

    if (!rsis) {
      res.status(404).json({ error: "RSIS score not found for this scan ID" });
      return;
    }

    res.json(toRsis(rsis));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to fetch RSIS score";
    res.status(500).json({ error: message });
  }
});

// ─── Get Discovered Similar Repositories ───────────────────────────────────

app.get("/api/similar/:id", async (req, res) => {
  try {
    const db = getDB();
    const similarRepos = await db.similarRepository.findMany({
      where: { scanId: req.params.id },
      orderBy: { similarityScore: "desc" },
    });

    res.json(similarRepos.map((r: any) => ({ ...r, topics: parseJson(r.topics, []) })));
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to fetch similar repositories";
    res.status(500).json({ error: message });
  }
});

// ─── Run ML Evaluation on an Analyzed Repository ────────────────────────────

app.post("/api/evaluate", async (req, res) => {
  const { scanId } = req.body;

  if (!scanId || typeof scanId !== "string") {
    res.status(400).json({ error: "scanId is required" });
    return;
  }

  try {
    const db = getDB();
    const scan = await db.scan.findUnique({
      where: { id: scanId },
      include: {
        dependencies: {
          include: {
            vulnerabilities: true,
          },
        },
        remediations: true,
      },
    });

    if (!scan) {
      res.status(404).json({ error: "Scan not found" });
      return;
    }

    const evaluator = new Evaluator();

    const scanResults = scan.dependencies.map((d: any) => ({
      dependency: {
        name: d.name,
        version: d.version,
        ecosystem: d.ecosystem as any,
        isDev: d.isDev,
        manifestPath: d.manifestPath,
      },
      vulnerabilities: d.vulnerabilities.map((v: any) => ({
        cveId: v.cveId,
        severity: v.severity as any,
        cvssScore: v.cvssScore,
        cvssVector: v.cvssVector,
        summary: v.summary,
        details: v.details,
        publishedDate: v.publishedDate,
        modifiedDate: v.modifiedDate,
        fixedVersions: v.fixedVersions ? JSON.parse(v.fixedVersions) : [],
        references: v.references ? JSON.parse(v.references) : [],
        source: v.source as any,
        affectedRange: v.affectedRange,
        kev: v.kev,
        mitigationGuidance: v.mitigationGuidance,
      })),
    }));

    const remediations = scan.remediations.map((r: any) => ({
      scanId: r.scanId,
      cveId: r.cveId,
      packageName: r.packageName,
      ecosystem: r.ecosystem as any,
      candidates: JSON.parse(r.candidates),
      reasoningTrace: r.reasoningTrace,
      contextChunks: [],
      validationPassed: r.validationPassed,
    }));

    const metrics = await evaluator.evaluate(scanId, scanResults, remediations);

    res.json({ scanId, metrics });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Evaluation failed";
    res.status(500).json({ error: message });
  }
});

// ─── Get ML Evaluation Results for a Scan ──────────────────────────────────

app.get("/api/evaluate/:id", async (req, res) => {
  try {
    const db = getDB();
    const evalResult = await db.evaluationResult.findFirst({
      where: { scanId: req.params.id },
      orderBy: { runAt: "desc" },
    });

    if (!evalResult) {
      res.status(404).json({ error: "Evaluation results not found for this scan ID" });
      return;
    }

    const metrics: EvalMetrics = {
      retrieval: {
        precisionAtK: evalResult.precisionAtK ?? 0,
        recallAtK: evalResult.recallAtK ?? 0,
        mrr: evalResult.mrr ?? 0,
        ndcg: evalResult.ndcg ?? 0,
        k: evalResult.kValue,
      },
      recommendation: {
        top1Accuracy: evalResult.top1Accuracy ?? 0,
        top3Accuracy: evalResult.top3Accuracy ?? 0,
      },
      validation: {
        buildSuccessRate: evalResult.buildSuccessRate ?? 0,
        vulnReductionRate: evalResult.vulnReductionRate ?? 0,
      },
    };
    res.json({ scanId: evalResult.scanId, metrics, runAt: evalResult.runAt });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Failed to fetch evaluation results";
    res.status(500).json({ error: message });
  }
});

// ─── Start Server ───────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n  🛡️  VulnShield Intelligence API running on http://localhost:${PORT}`);
  console.log(`  📚  Endpoints:`);
  console.log(`     GET  /api/health`);
  console.log(`     POST /api/scan            { repoUrl: "owner/repo" }`);
  console.log(`     GET  /api/scan/:id`);
  console.log(`     GET  /api/scans`);
  console.log(`     POST /api/analyze         { repoUrl: "owner/repo" }`);
  console.log(`     GET  /api/analyze/:id`);
  console.log(`     GET  /api/analyze/:id/rsis`);
  console.log(`     GET  /api/similar/:id`);
  console.log(`     POST /api/evaluate        { scanId: "..." }`);
  console.log(`     GET  /api/evaluate/:id\n`);
});

// Graceful shutdown
process.on("SIGINT", async () => {
  await disconnectDB();
  process.exit(0);
});
