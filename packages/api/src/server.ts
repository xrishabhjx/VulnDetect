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

// Load env from project root
dotenv.config({ path: "../../.env" });

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

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

    res.json({
      scanId: report.scanId,
      repoUrl: report.repoUrl,
      totalDependencies: report.totalDependencies,
      totalVulnerabilities: report.totalVulnerabilities,
      severityCounts: report.severityCounts,
      results: report.results,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Scan failed";
    res.status(500).json({ error: message });
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

    res.json(scan);
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
    res.status(500).json({ error: message });
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

    res.json(scan);
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

    res.json({
      ...rsis,
      weights: JSON.parse(rsis.weights),
      signals: JSON.parse(rsis.signals),
    });
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

    res.json(similarRepos.map((r: any) => ({
      ...r,
      topics: r.topics ? JSON.parse(r.topics) : [],
    })));
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

    res.json(evalResult);
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
