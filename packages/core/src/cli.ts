#!/usr/bin/env node

import chalk from "chalk";
import ora from "ora";
import dotenv from "dotenv";
import * as readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { VulnerabilityScanner } from "./scanner.js";
import { IntelligenceAnalyzer } from "./analyzer.js";
import { RSISScorer } from "./intelligence/rsis-scorer.js";
import { BenchmarkRunner } from "./benchmark/benchmark-runner.js";
import { BENCHMARK_REPOS } from "./benchmark/benchmark-repos.js";
import { formatBenchmarkReport } from "./benchmark/benchmark-report.js";
import { disconnectDB } from "./db.js";
import { writeFileSync } from "node:fs";
import type { ScanReport, Severity } from "./types.js";

// Load env from the repo root .env (and an optional package-local override).
// src/cli.ts → ../../.. → repo root
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const repoRoot   = path.resolve(__dirname, "../../../");

dotenv.config({ path: path.join(repoRoot, ".env") });
dotenv.config({ path: path.join(repoRoot, "packages/core/.env") });

// ─── Constants ────────────────────────────────────────────────────────────────

const W = 62;
const SEV_COLOR: Record<Severity, (t: string) => string> = {
  CRITICAL: chalk.bgRed.white.bold,
  HIGH:     chalk.red.bold,
  MEDIUM:   chalk.yellow.bold,
  LOW:      chalk.cyan,
  UNKNOWN:  chalk.gray,
};
const SEV_ICON: Record<Severity, string> = {
  CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🔵", UNKNOWN: "⚪",
};
const SEV_ORDER: Record<Severity, number> = {
  CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4,
};

// ─── Display Helpers ──────────────────────────────────────────────────────────

const thick = () => chalk.cyan("═".repeat(W));
const line  = () => chalk.gray("─".repeat(W));

function bar(score: number, width = 24): string {
  const filled = Math.round((score / 100) * width);
  const color = score >= 80 ? chalk.green : score >= 60 ? chalk.yellow : score >= 40 ? chalk.red : chalk.bgRed.white;
  return color("█".repeat(filled)) + chalk.gray("░".repeat(width - filled)) + chalk.white.bold(` ${score.toFixed(1)}/100`);
}

function grade(score: number): string {
  if (score >= 85) return chalk.green.bold("A");
  if (score >= 70) return chalk.greenBright.bold("B");
  if (score >= 55) return chalk.yellow.bold("C");
  if (score >= 40) return chalk.red.bold("D");
  return chalk.bgRed.white.bold("F");
}

function riskLabel(score: number): string {
  if (score >= 85) return chalk.green("LOW RISK — repository is well-maintained");
  if (score >= 70) return chalk.yellow("MODERATE RISK — some issues to address");
  if (score >= 50) return chalk.red("HIGH RISK — significant vulnerabilities present");
  return chalk.bgRed.white("CRITICAL RISK — immediate action required");
}

function truncate(s: string, n = 68): string {
  return s.length <= n ? s : s.slice(0, n - 1) + "…";
}

function miniBar(score: number): string {
  const filled = Math.round((score / 100) * 12);
  const color = score >= 80 ? chalk.green : score >= 55 ? chalk.yellow : chalk.red;
  return color("█".repeat(filled)) + chalk.gray("░".repeat(12 - filled));
}

// ─── Report Printer ───────────────────────────────────────────────────────────

function printReport(report: ScanReport): void {
  const scorer     = new RSISScorer();
  const rsis       = scorer.compute(report.results, [], 0);
  const vulnerable = report.results.filter(r => r.vulnerabilities.length > 0);
  const allVulns   = report.results.flatMap(r => r.vulnerabilities);
  const fixable    = allVulns.filter(v => v.fixedVersions.length > 0);
  const critical   = allVulns.filter(v => v.severity === "CRITICAL");
  const high       = allVulns.filter(v => v.severity === "HIGH");

  console.log();
  console.log(thick());
  console.log(chalk.cyan.bold("  🛡️  VulnShield — Repository Security Intelligence Report"));
  console.log(thick());
  console.log();

  // Overview
  console.log(chalk.bold("  📂  REPOSITORY OVERVIEW"));
  console.log(line());
  console.log("  " + chalk.gray("Repository:".padEnd(22))   + chalk.white.bold(`${report.repoOwner}/${report.repoName}`));
  console.log("  " + chalk.gray("Scanned at:".padEnd(22))   + chalk.white(new Date(report.scannedAt).toLocaleString("en-IN")));
  console.log("  " + chalk.gray("Dependencies:".padEnd(22)) + chalk.white.bold(`${report.totalDependencies} total  •  ${vulnerable.length} affected`));
  console.log("  " + chalk.gray("Vulnerabilities:".padEnd(22)) + chalk.white.bold(`${report.totalVulnerabilities} found  •  ${fixable.length} fixable`));
  console.log();

  // RSIS Score
  console.log(chalk.bold("  📊  RSIS — Repository Security Intelligence Score"));
  console.log(line());
  console.log();
  console.log(`  Overall Score   ${bar(rsis.totalScore)}   Grade: ${grade(rsis.totalScore)}`);
  console.log();
  console.log(`  ${"→"}  ${riskLabel(rsis.totalScore)}`);
  console.log();
  console.log(chalk.gray("  Score dimensions:"));
  console.log();
  for (const [lbl, val, desc] of [
    ["  Security",        rsis.securityScore,        "CVSS severity & exploitation weight"],
    ["  Retrieval",       rsis.retrievalScore,       "Code evidence & context quality"],
    ["  Validation",      rsis.validationScore,      "Registry + patch availability"],
    ["  Maintainability", rsis.maintainabilityScore, "Dependency health & age"],
    ["  Compatibility",   rsis.compatibilityScore,   "SemVer upgrade safety"],
  ] as [string, number, string][]) {
    console.log(
      "  " + chalk.gray(lbl.padEnd(18)) +
      miniBar(val) +
      chalk.white(` ${val.toFixed(1).padStart(5)}/100`) +
      chalk.gray(`   ${desc}`)
    );
  }
  console.log();

  // Severity Breakdown
  console.log(chalk.bold("  🚨  SEVERITY BREAKDOWN"));
  console.log(line());
  console.log();
  for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] as Severity[]) {
    const count = report.severityCounts[sev] ?? 0;
    if (count === 0) continue;
    const pct    = ((count / report.totalVulnerabilities) * 100).toFixed(0);
    const blocks = "■".repeat(Math.max(1, Math.round((count / report.totalVulnerabilities) * 20)));
    console.log(
      `  ${SEV_ICON[sev]}  ${SEV_COLOR[sev](sev.padEnd(10))}  ` +
      chalk.white.bold(String(count).padStart(3)) +
      chalk.gray(` (${pct}%)  `) +
      SEV_COLOR[sev](blocks)
    );
  }
  console.log();

  // Priority Plan
  if (report.totalVulnerabilities > 0) {
    console.log(chalk.bold("  ⚡  PRIORITY ACTION PLAN"));
    console.log(line());
    console.log();

    if (critical.length > 0) {
      console.log(chalk.bgRed.white.bold(`  🔴 STEP 1 — Fix ${critical.length} CRITICAL issue(s) IMMEDIATELY`));
      for (const v of critical.slice(0, 3)) {
        const dep = report.results.find(r => r.vulnerabilities.includes(v))?.dependency;
        const id  = v.cveId || (v as any).osvId || "N/A";
        console.log(chalk.gray(`     • ${dep?.name}@${dep?.version}  `) + chalk.cyan(id));
        console.log(v.fixedVersions.length > 0
          ? chalk.green(`       ✔ Fix: upgrade to ${v.fixedVersions[0]}`)
          : chalk.yellow("       ✘ No patch — consider replacing this package"));
      }
      console.log();
    }

    if (high.length > 0) {
      const step = critical.length > 0 ? 2 : 1;
      console.log(chalk.red.bold(`  🟠 STEP ${step} — Fix ${high.length} HIGH issue(s) this week`));
      for (const v of high.slice(0, 3)) {
        const dep = report.results.find(r => r.vulnerabilities.includes(v))?.dependency;
        const id  = v.cveId || (v as any).osvId || "N/A";
        console.log(chalk.gray(`     • ${dep?.name}@${dep?.version}  `) + chalk.cyan(id));
        if (v.fixedVersions.length > 0) console.log(chalk.green(`       ✔ Fix: upgrade to ${v.fixedVersions[0]}`));
      }
      if (high.length > 3) console.log(chalk.gray(`     … and ${high.length - 3} more HIGH issues`));
      console.log();
    }

    if (fixable.length > 0) {
      const pct = ((fixable.length / allVulns.length) * 100).toFixed(0);
      console.log(chalk.green(`  ✅  ${fixable.length}/${allVulns.length} (${pct}%) vulnerabilities have known patches`));
      console.log();
    }
  }

  // Full package list
  if (vulnerable.length > 0) {
    console.log(chalk.bold("  📦  AFFECTED PACKAGES — FULL DETAIL"));
    console.log(line());
    console.log();

    for (const result of vulnerable) {
      const { dependency: dep, vulnerabilities: vulns } = result;
      const sorted = [...vulns].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
      const worst  = sorted[0];

      console.log(
        chalk.white.bold(`  ┌─ ${dep.name}`) +
        chalk.gray(`@${dep.version}`) +
        chalk.dim(`  [${dep.ecosystem.toUpperCase()}]  ${dep.manifestPath}`)
      );
      console.log(
        chalk.gray(`  │`) +
        `  ${SEV_ICON[worst.severity]} Worst: ${SEV_COLOR[worst.severity](worst.severity)}` +
        chalk.gray(`  •  ${vulns.length} issue${vulns.length > 1 ? "s" : ""}`)
      );
      console.log(chalk.gray("  │"));

      for (const vuln of sorted) {
        const id    = ((vuln.cveId || (vuln as any).osvId || "N/A") as string).padEnd(26);
        const score = vuln.cvssScore !== null ? chalk.gray(`CVSS ${vuln.cvssScore.toFixed(1)}`) : chalk.gray("CVSS N/A");
        console.log(chalk.gray("  ├──") + ` ${SEV_ICON[vuln.severity]} ${SEV_COLOR[vuln.severity](vuln.severity.padEnd(9))}  ${chalk.cyan(id)}  ${score}`);
        console.log(chalk.gray(`  │     ${truncate(vuln.summary)}`));
        console.log(vuln.fixedVersions.length > 0
          ? chalk.green(`  │     ✔ Fix: upgrade to ${vuln.fixedVersions.join(" or ")}`)
          : chalk.yellow("  │     ✘ No patch available — review manually"));
        console.log(chalk.gray("  │"));
      }
      console.log(chalk.gray("  └" + "─".repeat(W - 3)));
      console.log();
    }
  } else {
    console.log(chalk.green.bold("\n  ✅  No vulnerabilities found!\n"));
  }

  // Footer
  console.log(thick());
  const sid = report.scanId ? `  Scan ID: ${chalk.white(report.scanId)}` : "";
  console.log(chalk.gray("  VulnShield — AI-Powered Repository Security Intelligence") + "  " + chalk.gray(sid));
  console.log(thick());
}

// ─── Interactive Menu ─────────────────────────────────────────────────────────

async function showPostScanMenu(report: ScanReport): Promise<void> {
  const rl = readline.createInterface({ input, output });

  try {
    while (true) {
      console.log();
      console.log(chalk.cyan.bold("  ╔══════════════════════════════════════╗"));
      console.log(chalk.cyan.bold("  ║       What would you like to do?     ║"));
      console.log(chalk.cyan.bold("  ╚══════════════════════════════════════╝"));
      console.log();
      console.log(`  ${chalk.white.bold("1")}  ${chalk.white("Run AI-powered deep analysis")}         ${chalk.gray("← remediation plans + knowledge graph")}`);
      console.log(`  ${chalk.white.bold("2")}  ${chalk.white("Run benchmark suite")}                  ${chalk.gray("← compare with 8 known-vulnerable repos")}`);
      console.log(`  ${chalk.white.bold("3")}  ${chalk.white("Start the API server")}                 ${chalk.gray("← REST endpoints at localhost:3001")}`);
      console.log(`  ${chalk.white.bold("4")}  ${chalk.white("Run test suite")}                       ${chalk.gray("← 40 unit tests")}`);
      console.log(`  ${chalk.white.bold("5")}  ${chalk.white("Scan a different repository")}`)
      console.log(`  ${chalk.white.bold("0")}  ${chalk.white("Exit")}`);
      console.log();

      const answer = (await rl.question(chalk.cyan("  Enter option › "))).trim();
      console.log();

      if (answer === "0") {
        console.log(chalk.gray("  Goodbye!\n"));
        break;
      }

      if (answer === "1") {
        console.log(chalk.cyan(`  Running AI-powered analysis on ${report.repoOwner}/${report.repoName}…`));
        console.log(chalk.gray("  This takes 1–3 minutes depending on repo size.\n"));
        await runAnalysis(`${report.repoOwner}/${report.repoName}`);
        continue;
      }

      if (answer === "2") {
        const howMany = await rl.question(chalk.cyan("  How many repos? (1–8, default 3) › "));
        const n = parseInt(howMany.trim() || "3", 10);
        await runBenchmark(Math.min(8, Math.max(1, isNaN(n) ? 3 : n)));
        continue;
      }

      if (answer === "3") {
        rl.close();
        startApiServer();
        return;
      }

      if (answer === "4") {
        await runTests();
        continue;
      }

      if (answer === "5") {
        const repo = await rl.question(chalk.cyan("  GitHub repo (owner/repo or URL) › "));
        if (repo.trim()) {
          rl.close();
          await scanAndMenu(repo.trim());
          return;
        }
        continue;
      }

      console.log(chalk.yellow("  Please enter 0–5.\n"));
    }
  } finally {
    rl.close();
  }
}

async function showMainMenu(): Promise<void> {
  const rl = readline.createInterface({ input, output });

  try {
    while (true) {
      console.log();
      console.log(thick());
      console.log(chalk.cyan.bold("  🛡️  VulnShield — Repository Security Intelligence Platform"));
      console.log(thick());
      console.log();
      console.log(`  ${chalk.white.bold("1")}  ${chalk.white("Scan a repository")}                    ${chalk.gray("← check for vulnerabilities")}`);
      console.log(`  ${chalk.white.bold("2")}  ${chalk.white("Run full AI-powered analysis")}         ${chalk.gray("← remediation + knowledge graph + RSIS")}`);
      console.log(`  ${chalk.white.bold("3")}  ${chalk.white("Run benchmark suite")}                  ${chalk.gray("← RSIS before/after across 8 repos")}`);
      console.log(`  ${chalk.white.bold("4")}  ${chalk.white("Start API server")}                     ${chalk.gray("← REST endpoints at localhost:3001")}`);
      console.log(`  ${chalk.white.bold("5")}  ${chalk.white("Run test suite")}                       ${chalk.gray("← 40 unit tests")}`);
      console.log(`  ${chalk.white.bold("0")}  ${chalk.white("Exit")}`);
      console.log();

      const answer = (await rl.question(chalk.cyan("  Enter option › "))).trim();
      console.log();

      if (answer === "0") {
        console.log(chalk.gray("  Goodbye!\n"));
        break;
      }

      if (answer === "1") {
        const repo = await rl.question(chalk.cyan("  GitHub repo (owner/repo or URL) › "));
        if (repo.trim()) {
          rl.close();
          await scanAndMenu(repo.trim());
          return;
        }
        continue;
      }

      if (answer === "2") {
        const repo = await rl.question(chalk.cyan("  GitHub repo (owner/repo or URL) › "));
        if (repo.trim()) {
          await runAnalysis(repo.trim());
        }
        continue;
      }

      if (answer === "3") {
        const howMany = await rl.question(chalk.cyan("  How many repos? (1–8, default 3) › "));
        const n = parseInt(howMany.trim() || "3", 10);
        await runBenchmark(Math.min(8, Math.max(1, isNaN(n) ? 3 : n)));
        continue;
      }

      if (answer === "4") {
        rl.close();
        startApiServer();
        return;
      }

      if (answer === "5") {
        await runTests();
        continue;
      }

      console.log(chalk.yellow("  Please enter 0–5.\n"));
    }
  } finally {
    rl.close();
  }
}

// ─── Action Runners ───────────────────────────────────────────────────────────

async function scanAndMenu(repoUrl: string): Promise<void> {
  if (!process.env.GITHUB_TOKEN) {
    console.warn(chalk.yellow("\n  ⚠  GITHUB_TOKEN not set — rate limits apply.\n"));
  }

  const scanner = new VulnerabilityScanner();
  const spinner = ora({ text: chalk.cyan("  Fetching repository manifests…"), color: "cyan" }).start();

  try {
    const report = await scanner.scan(repoUrl, { useNVD: false, skipDev: false, persist: true });
    spinner.succeed(chalk.green(`  Scan complete — ${report.totalVulnerabilities} vulnerabilities in ${report.totalDependencies} dependencies`));
    printReport(report);
    await showPostScanMenu(report);
  } catch (err) {
    spinner.fail(chalk.red("  Scan failed"));
    if (err instanceof Error) console.error(chalk.red(`\n  Error: ${err.message}\n`));
  } finally {
    await disconnectDB();
  }
}

async function runAnalysis(repoUrl: string): Promise<void> {
  const analyzer = new IntelligenceAnalyzer();
  const spinner  = ora({ text: chalk.cyan("  Running 13-step intelligence pipeline…"), color: "cyan" }).start();

  try {
    const result = await analyzer.analyze(repoUrl, {
      useNVD: false,
      skipDev: false,
      skipEmbedding: false,
      skipSimilarRepos: false,
      skipReasoning: false,
      maxRemediations: 5,
      persist: true,
    });

    spinner.succeed(chalk.green("  Analysis complete!"));
    console.log();

    const { repositoryProfile: prof, intelligenceSummary: intel, rsis, remediations, similarRepos, knowledgeGraph } = result;

    // ── 1. Repository Profile ─────────────────────────────────────────────
    console.log(thick());
    console.log(chalk.cyan.bold("  🏛️  REPOSITORY PROFILE"));
    console.log(thick());
    console.log();
    if (prof) {
      const rows: [string, string][] = [
        ["Repository",    `${result.scan.repoOwner}/${result.scan.repoName}`],
        ["Language",      prof.language ?? "unknown"],
        ["Framework",     prof.framework ?? "none detected"],
        ["Architecture",  prof.architecture ?? "unknown"],
        ["Type",          prof.repositoryType],
        ["Database",      prof.database ?? "none detected"],
        ["ORM",           prof.orm ?? "none detected"],
        ["Auth",          prof.authentication ?? "none detected"],
        ["Deployment",    prof.deployment ?? "none detected"],
        ["CI/CD",         prof.ciCdPlatform ?? "none detected"],
        ["Testing",       prof.testingFramework ?? "none detected"],
        ["Pkg Managers",  prof.packageManagers.join(", ") || "unknown"],
      ];
      for (const [k, v] of rows) {
        console.log("  " + chalk.gray(k.padEnd(16)) + chalk.white(v));
      }
      if (prof.purpose) {
        console.log();
        console.log("  " + chalk.gray("Purpose:"));
        console.log("  " + chalk.white.italic(truncate(prof.purpose, 80)));
      }
    } else {
      console.log(chalk.gray("  Profile not available"));
    }
    console.log();

    // ── 2. Knowledge Graph Stats ──────────────────────────────────────────
    if (intel) {
      const g = intel.graphStats;
      console.log(chalk.bold("  🕸️  KNOWLEDGE GRAPH"));
      console.log(line());
      console.log("  " + chalk.gray("Nodes:".padEnd(14)) + chalk.white.bold(`${g.totalNodes}`) + chalk.gray(`  (Files: ${g.fileCount}  Modules: ${g.moduleCount}  Packages: ${g.packageCount}  Threats: ${g.threatCount})`));
      console.log("  " + chalk.gray("Edges:".padEnd(14)) + chalk.white.bold(`${g.totalEdges}`) + chalk.gray("  (dependency chains, import relationships, threat intel edges)"));
      if (g.kevCount > 0) {
        console.log("  " + chalk.red.bold(`⚠️  ${g.kevCount} CISA KEV nodes — actively exploited CVEs in this graph`));
      }
      console.log();
    }

    // ── 3. Threat Intelligence Summary ────────────────────────────────────
    if (intel) {
      console.log(chalk.bold("  ⚡  THREAT INTELLIGENCE"));
      console.log(line());
      console.log("  " + chalk.white(intel.threatIntelSummary));
      console.log();
    }

    // ── 4. Similar Repository Evidence ────────────────────────────────────
    if (similarRepos.length > 0) {
      console.log(chalk.bold("  🔗  SIMILAR REPOSITORIES & EVIDENCE"));
      console.log(line());
      if (intel) console.log("  " + chalk.gray(intel.similarRepoInfluence));
      console.log();
      for (const r of similarRepos.slice(0, 5)) {
        process.stdout.write(
          "  " + chalk.white(`${r.fullName}`.padEnd(35)) +
          chalk.gray(` ★${String(r.stars).padStart(6)}  `) +
          healthLabel(r.healthScore) +
          chalk.gray(`  sim: ${(r.similarityScore * 100).toFixed(0)}%`) +
          "\n"
        );
      }
      console.log();
    }

    // ── 5. RSIS Score ─────────────────────────────────────────────────────
    if (rsis) {
      console.log(thick());
      console.log(chalk.bold("  📊  REPOSITORY SECURITY INTELLIGENCE SCORE (RSIS)"));
      console.log(thick());
      console.log();
      console.log(`  Overall          ${bar(rsis.totalScore)}   Grade: ${grade(rsis.totalScore)}`);
      console.log(`  ${chalk.gray("→")}  ${riskLabel(rsis.totalScore)}`);
      console.log();
      console.log("  " + chalk.gray("Component breakdown:"));
      console.log(`  ${chalk.gray("Security")}         ${miniBar(rsis.securityScore)}  ${chalk.white(rsis.securityScore.toFixed(1))}`);
      console.log(`  ${chalk.gray("Retrieval")}        ${miniBar(rsis.retrievalScore)}  ${chalk.white(rsis.retrievalScore.toFixed(1))}`);
      console.log(`  ${chalk.gray("Validation")}       ${miniBar(rsis.validationScore)}  ${chalk.white(rsis.validationScore.toFixed(1))}`);
      console.log(`  ${chalk.gray("Maintainability")}  ${miniBar(rsis.maintainabilityScore)}  ${chalk.white(rsis.maintainabilityScore.toFixed(1))}`);
      console.log(`  ${chalk.gray("Compatibility")}    ${miniBar(rsis.compatibilityScore)}  ${chalk.white(rsis.compatibilityScore.toFixed(1))}`);
      if (intel) {
        console.log();
        const proj = intel.projectedRsisAfterRemediation;
        const diff = proj - rsis.totalScore;
        console.log(`  ${chalk.gray("Projected after remediation:")} ${chalk.green.bold(proj.toFixed(1) + "/100")} ${diff > 0 ? chalk.green(`(+${diff.toFixed(0)} points)`) : ""}`);
      }
      console.log();
    }

    // ── 6. AI Remediation Recommendations (full detail) ───────────────────
    if (remediations.length > 0) {
      console.log(thick());
      console.log(chalk.bold("  💊  AI-POWERED REMEDIATION RECOMMENDATIONS"));
      console.log(thick());
      console.log();

      for (const [idx, rem] of remediations.slice(0, 5).entries()) {
        const top = rem.candidates?.[0];
        if (!top) continue;
        const id = rem.cveId ?? "N/A";

        // Header
        console.log(chalk.white.bold(`  [${idx + 1}] ${rem.packageName}`) + chalk.gray(`  •  CVE: ${chalk.cyan(id)}  •  Ecosystem: ${rem.ecosystem}`));
        console.log(line());

        // Action + version
        const actionColor = top.action === "upgrade" ? chalk.green : top.action === "replace" ? chalk.yellow : chalk.gray;
        process.stdout.write(
          "  " + chalk.gray("Action: ") + actionColor.bold(top.action.toUpperCase()) +
          (top.proposedVersion ? chalk.green(` → v${top.proposedVersion}`) : "") +
          "  " + chalk.gray("Risk: ") + (top.compatibilityRisk === "low" ? chalk.green("LOW") : top.compatibilityRisk === "medium" ? chalk.yellow("MEDIUM") : chalk.red("HIGH")) +
          "\n"
        );

        // Confidence from evidence
        console.log("  " + chalk.gray("Confidence: ") + confidenceBar(top.confidence ?? 0) + chalk.gray("  (evidence-derived)"));

        // Explanation
        if (top.explanation) {
          console.log("  " + chalk.white(truncate(top.explanation, 76)));
        }

        // Chain of reasoning (abbreviated)
        if (top.chainOfReasoning?.length) {
          console.log();
          console.log("  " + chalk.gray.bold("Chain of Reasoning:"));
          for (const step of top.chainOfReasoning.slice(0, 3)) {
            console.log("  " + chalk.gray(`  ${step.stepNumber}. Observed: `) + chalk.white(truncate(step.observation, 60)));
            console.log("  " + chalk.gray(`     Deduced: `) + chalk.cyan(truncate(step.deduction, 60)));
          }
        }

        // Evidence references
        if (top.evidence?.length) {
          console.log();
          console.log("  " + chalk.gray.bold("Evidence References:"));
          for (const ev of top.evidence.slice(0, 2)) {
            const loc = ev.startLine ? `:${ev.startLine}` : "";
            console.log("  " + chalk.gray(`  • ${ev.filePath}${loc}`) + chalk.gray(` — ${truncate(ev.relevance, 50)}`));
          }
        }

        // Ranking features
        if (top.rankingFeatures) {
          const f = top.rankingFeatures;
          console.log();
          console.log("  " + chalk.gray.bold("Ranking (evidence-driven utility score):"));
          console.log(
            "  " +
            chalk.gray(`Security: ${(f.securityGainScore * 100).toFixed(0)}%`) + "  " +
            chalk.gray(`Compat: ${(f.compatibilityScore * 100).toFixed(0)}%`) + "  " +
            chalk.gray(`Evidence: ${(f.evidenceStrengthScore * 100).toFixed(0)}%`) + "  " +
            chalk.gray(`Valid: ${(f.validationScore * 100).toFixed(0)}%`) + "  " +
            chalk.gray(`Pattern: ${(f.patternAlignmentScore * 100).toFixed(0)}%`) + "  " +
            chalk.white.bold(`Utility: ${(f.utilityScore * 100).toFixed(0)}%`)
          );
        }

        // Reasoning trace
        if (rem.reasoningTrace) {
          console.log();
          console.log("  " + chalk.gray("Provider: ") + chalk.white(truncate(rem.reasoningTrace, 72)));
        }

        // Validation
        if (rem.validationPassed) {
          console.log("  " + chalk.green("✔ Validated — proposed version confirmed safe in registry"));
        }

        console.log();
      }
    }

    // ── Footer ────────────────────────────────────────────────────────────
    console.log(thick());
    console.log(chalk.gray(`  Scan ID:   ${chalk.white(result.scanId)}`));
    console.log(chalk.gray(`  Embedder:  ${chalk.white(result.aiEnabled ? "Neural (Gemini text-embedding-004)" : "Local TF-IDF (no Gemini key)")}`));
    console.log(chalk.gray(`  Retrieval: ${chalk.white("pgvector HNSW + BM25 RRF")}`));
    console.log(thick());

  } catch (err) {
    spinner.fail(chalk.red("  Analysis failed"));
    if (err instanceof Error) console.error(chalk.red(`\n  Error: ${err.message}\n`));
  }
}

async function runBenchmark(count: number): Promise<void> {
  const runner  = new BenchmarkRunner();
  const repos   = BENCHMARK_REPOS.slice(0, count);
  const spinner = ora({ text: chalk.cyan(`  Running benchmark on ${count} repositories…`), color: "cyan" }).start();

  try {
    spinner.stop();
    const result = await runner.run(repos);
    const md     = formatBenchmarkReport(result);
    writeFileSync("benchmark-results.md", md, "utf8");
    writeFileSync("benchmark-results.json", JSON.stringify(result, null, 2), "utf8");
    console.log(chalk.green("\n  ✅  Benchmark complete!"));
    console.log(chalk.gray("  Reports saved to:"));
    console.log(chalk.cyan("    packages/core/benchmark-results.md"));
    console.log(chalk.cyan("    packages/core/benchmark-results.json"));
    console.log();
  } catch (err) {
    spinner.fail(chalk.red("  Benchmark failed"));
    if (err instanceof Error) console.error(chalk.red(`\n  ${err.message}\n`));
  }
}

function startApiServer(): void {
  console.log(chalk.cyan("  Starting API server on http://localhost:3001 …"));
  console.log(chalk.gray("  Press Ctrl+C to stop.\n"));

  const proc = spawn("pnpm", ["dev"], {
    cwd: new URL("../../../api", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"),
    stdio: "inherit",
    shell: true,
  });

  proc.on("error", (err) => {
    console.error(chalk.red(`\n  Failed to start API server: ${err.message}\n`));
    console.log(chalk.gray("  Try manually:  cd packages/api && pnpm dev\n"));
  });
}

async function runTests(): Promise<void> {
  console.log(chalk.cyan("  Running test suite…\n"));

  await new Promise<void>((resolve) => {
    const proc = spawn("pnpm", ["test"], {
      cwd: process.cwd(),
      stdio: "inherit",
      shell: true,
    });
    proc.on("close", () => resolve());
  });
}

// ─── Small helpers ────────────────────────────────────────────────────────────

function confidenceBar(c: number): string {
  const pct = (c * 100).toFixed(0);
  const color = c >= 0.8 ? chalk.green : c >= 0.5 ? chalk.yellow : chalk.red;
  return color(`${"█".repeat(Math.round(c * 10))}${"░".repeat(10 - Math.round(c * 10))}`) + chalk.gray(` ${pct}%`);
}

function healthLabel(score: number): string {
  if (score >= 75) return chalk.green(`${score} ✔`);
  if (score >= 50) return chalk.yellow(`${score} ~`);
  return chalk.red(`${score} ✘`);
}

// ─── Entry Point ─────────────────────────────────────────────────────────────

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  // No args → interactive main menu
  if (args.length === 0) {
    await showMainMenu();
    process.exit(0);
  }

  // --help
  if (args[0] === "--help" || args[0] === "-h") {
    printHelp();
    process.exit(0);
  }

  // scan <repo> [opts] → direct scan with post-scan menu
  if (args[0] === "scan") {
    const repoUrl   = args[1];
    if (!repoUrl) {
      console.error(chalk.red("\n  ✗  No repository specified.\n"));
      console.error(chalk.gray("  Example:  pnpm scan scan OWASP/NodeGoat\n"));
      process.exit(1);
    }
    await scanAndMenu(repoUrl);
    process.exit(0);
  }

  console.error(chalk.red(`\n  ✗  Unknown command: "${args[0]}"\n`));
  console.error(chalk.gray("  Run  pnpm scan  (no arguments) for the interactive menu.\n"));
  process.exit(1);
}

function printHelp(): void {
  console.log();
  console.log(thick());
  console.log(chalk.cyan.bold("  🛡️  VulnShield — AI-Powered Repository Security Intelligence"));
  console.log(thick());
  console.log();
  console.log(chalk.bold("  INTERACTIVE MODE (recommended)"));
  console.log(line());
  console.log(chalk.cyan("  pnpm scan") + chalk.gray("                  Opens the interactive menu"));
  console.log();
  console.log(chalk.bold("  DIRECT MODE"));
  console.log(line());
  console.log(chalk.cyan("  pnpm scan scan <repo>") + chalk.gray("      Scan then show post-scan menu"));
  console.log(chalk.cyan("  pnpm benchmark --repos 5") + chalk.gray("   Benchmark 5 repos"));
  console.log(chalk.cyan("  pnpm test") + chalk.gray("                  Run test suite"));
  console.log();
  console.log(chalk.bold("  SCAN OPTIONS"));
  console.log(line());
  console.log(chalk.white("  --use-nvd") + chalk.gray("     Enrich with NVD CVSS data"));
  console.log(chalk.white("  --skip-dev") + chalk.gray("    Skip devDependencies"));
  console.log(chalk.white("  --no-persist") + chalk.gray("  Don't save to database"));
  console.log();
  console.log(thick());
  console.log();
}

main();
