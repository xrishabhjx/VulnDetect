#!/usr/bin/env node
/**
 * run-benchmark.ts — CLI entry point for the RSIS Benchmark Suite.
 *
 * Usage:
 *   pnpm benchmark                       # Run all repos in heuristic mode
 *   pnpm benchmark --repos 3             # Run first 3 repos only
 *   pnpm benchmark --use-nvd             # Enrich with NVD CVSS data
 *   pnpm benchmark --skip-dev            # Skip devDependencies
 *   pnpm benchmark --out results.json    # Save JSON results
 *
 * Requires: GITHUB_TOKEN in .env for GitHub API access.
 * Optional:  GEMINI_API_KEY for full AI reasoning mode.
 *            NVD_API_KEY for NVD CVSS enrichment.
 */
import { writeFileSync } from "node:fs";
import dotenv from "dotenv";
import { BenchmarkRunner } from "../benchmark/benchmark-runner.js";
import { BENCHMARK_REPOS } from "../benchmark/benchmark-repos.js";
import { formatBenchmarkReport } from "../benchmark/benchmark-report.js";

dotenv.config({ path: "../../../.env" });

// ─── Parse CLI args ──────────────────────────────────────────────────────────

const args = process.argv.slice(2);
const getArg = (flag: string): string | undefined => {
  const idx = args.indexOf(flag);
  return idx !== -1 ? args[idx + 1] : undefined;
};

const reposArg = parseInt(getArg("--repos") ?? "0", 10);
const useNVD = args.includes("--use-nvd");
const skipDev = args.includes("--skip-dev");
const outArg = getArg("--out");

// ─── Select repos ────────────────────────────────────────────────────────────

const repos = reposArg > 0
  ? BENCHMARK_REPOS.slice(0, reposArg)
  : BENCHMARK_REPOS;

// ─── Run ─────────────────────────────────────────────────────────────────────

const runner = new BenchmarkRunner();
const result = await runner.run(repos, { useNVD, skipDev });

// ─── Output ──────────────────────────────────────────────────────────────────

const markdown = formatBenchmarkReport(result);
const jsonOutput = JSON.stringify(result, null, 2);

const mdPath = outArg ? outArg.replace(".json", ".md") : "benchmark-results.md";
const jsonPath = outArg ?? "benchmark-results.json";

writeFileSync(mdPath, markdown, "utf8");
writeFileSync(jsonPath, jsonOutput, "utf8");

console.log(`📊 Benchmark report saved to: ${mdPath}`);
console.log(`📦 Benchmark JSON saved to:   ${jsonPath}`);
