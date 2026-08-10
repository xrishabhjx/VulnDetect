import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  VulnerabilityScanner,
  IntelligenceAnalyzer,
  Evaluator,
  getDB,
  disconnectDB,
} from "@vuln-shield/core";

// Load env from the repo root .env (and an optional package-local override).
// src/server.ts → ../../.. → repo root
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const repoRoot   = path.resolve(__dirname, "../../../");

dotenv.config({ path: path.join(repoRoot, ".env") });
dotenv.config({ path: path.join(repoRoot, "packages/api/.env") });

const app: express.Express = express();
// Default 3011 to avoid colliding with system Postgres installs that bind 3001.
// Override via the `PORT` env var (or `packages/api/.env`).
const PORT = process.env.PORT || 3011;

app.use(cors());
app.use(express.json());

// ─── Helpers ────────────────────────────────────────────────────────────────

// GitHub owner/repo rules: 1-39 chars, alphanumeric + single hyphens, no
// leading/trailing hyphen. Repo names may also contain a single `.` for
// extensions like `.git` (stripped before validation).
const GH_OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const GH_REPO_RE  = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Normalise any supported repo reference to `{ owner, repo }` or return null
 * if the input is malformed. Accepts:
 *   - "owner/repo"
 *   - "https://github.com/owner/repo"
 *   - "https://github.com/owner/repo.git"
 *   - "git@github.com:owner/repo.git"
 *   - "github.com/owner/repo"
 */
function parseRepoInput(input: unknown): { owner: string; repo: string } | null {
  if (typeof input !== "string") return null;
  let s = input.trim();
  if (!s) return null;

  // SSH form: git@github.com:owner/repo(.git)
  const ssh = s.match(/^git@github\.com:([^/]+)\/([^/]+?)(?:\.git)?$/);
  if (ssh) {
    return validateOwnerRepo(ssh[1], ssh[2]);
  }

  // Strip protocol + host
  s = s.replace(/^https?:\/\//i, "");
  s = s.replace(/^github\.com\//i, "");
  // Drop query/fragment
  s = s.split("?")[0].split("#")[0];
  // Drop trailing .git
  s = s.replace(/\.git$/, "");

  const parts = s.split("/").filter(Boolean);
  if (parts.length < 2) return null;
  return validateOwnerRepo(parts[0], parts[1]);
}

function validateOwnerRepo(owner: string, repo: string): { owner: string; repo: string } | null {
  if (!GH_OWNER_RE.test(owner)) return null;
  if (!GH_REPO_RE.test(repo)) return null;
  return { owner, repo };
}

// ─── Health Check ───────────────────────────────────────────────────────────

app.get("/api/health", (_req, res) => {
  res.json({ status: "ok", service: "vuln-shield-api", timestamp: new Date().toISOString() });
});

// ─── Start a New Basic Scan (Phase 1) ───────────────────────────────────────

app.post("/api/scan", async (req, res) => {
  const { repoUrl, useNVD, skipDev } = req.body;

  const parsed = parseRepoInput(repoUrl);
  if (!parsed) {
    res.status(400).json({
      error:
        "Invalid repoUrl. Expected 'owner/repo' or a full GitHub URL " +
        "(e.g. 'https://github.com/owner/repo').",
    });
    return;
  }
  const normalised = `${parsed.owner}/${parsed.repo}`;

  try {
    const scanner = new VulnerabilityScanner();
    const report = await scanner.scan(normalised, {
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

  const parsed = parseRepoInput(repoUrl);
  if (!parsed) {
    res.status(400).json({
      error:
        "Invalid repoUrl. Expected 'owner/repo' or a full GitHub URL " +
        "(e.g. 'https://github.com/owner/repo').",
    });
    return;
  }
  const normalised = `${parsed.owner}/${parsed.repo}`;

  try {
    const analyzer = new IntelligenceAnalyzer();
    const result = await analyzer.analyze(normalised, {
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
// Only start the listener when this file is the entrypoint. When tests
// import the app via `import { app } from "./server.js"`, we skip the
// listen() and signal handlers.

export { app, parseRepoInput };

const isEntrypoint =
  process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename);

let server: import("http").Server | null = null;

if (isEntrypoint) {
  server = app.listen(PORT, () => {
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
}

// ─── Global Error Handler ────────────────────────────────────────────────────
// Express 5 propagates async route errors here. Without this, a single
// throw will crash the process. Must be the LAST `app.use`.

app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  const message = err instanceof Error ? err.message : "Internal server error";
  console.error("[API] Unhandled error:", err);
  if (res.headersSent) {
    // Can't send a new response — destroy the socket so the client knows.
    return;
  }
  res.status(500).json({ error: message });
});

// ─── Graceful Shutdown ───────────────────────────────────────────────────────

let shuttingDown = false;

async function shutdown(signal: string): Promise<void> {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`\n[API] Received ${signal}, shutting down gracefully...`);

  // Stop accepting new connections; let in-flight requests finish.
  if (server) {
    server.close((err) => {
      if (err) console.error("[API] Error closing HTTP server:", err);
    });
  }

  try {
    await disconnectDB();
    console.log("[API] Prisma disconnected.");
  } catch (err) {
    console.error("[API] Error disconnecting Prisma:", err);
  } finally {
    process.exit(0);
  }

  // Hard exit if shutdown takes too long.
  setTimeout(() => {
    console.error("[API] Forced exit after 10s shutdown timeout.");
    process.exit(1);
  }, 10_000).unref();
}

if (isEntrypoint) {
  process.on("SIGINT",  () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

// Surface unhandled errors instead of dying silently.
process.on("unhandledRejection", (reason) => {
  console.error("[API] Unhandled promise rejection:", reason);
});
process.on("uncaughtException", (err) => {
  console.error("[API] Uncaught exception:", err);
  void shutdown("uncaughtException");
});
