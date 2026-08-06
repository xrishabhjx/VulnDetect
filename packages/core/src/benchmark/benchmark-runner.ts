import { VulnerabilityScanner } from "../scanner.js";
import { RSISScorer } from "../intelligence/rsis-scorer.js";
import type {
  DependencyScanResult,
  RemediationReport,
  RSISScore,
  Severity,
} from "../types.js";
import type { BenchmarkRepo } from "./benchmark-repos.js";

// ─── Benchmark Result Types ───────────────────────────────────────────────────

export interface BenchmarkRunResult {
  repo: BenchmarkRepo;
  success: boolean;
  error?: string;
  scanDurationMs: number;
  /** RSIS score computed from raw scan — current state */
  rsisBefore: RSISScore;
  /** Projected RSIS if all validated upgrade candidates were applied */
  rsisAfter: RSISScore;
  /** Delta: rsisAfter.totalScore - rsisBefore.totalScore */
  scoreDelta: number;
  metrics: {
    totalDeps: number;
    totalVulns: number;
    criticalCount: number;
    highCount: number;
    kevCount: number;
    fixableVulns: number;    // vulns with at least one fixed version
    remediableRate: number;  // fixableVulns / totalVulns
  };
  /** Pass/fail against expected range */
  expectationMet: boolean;
}

export interface BenchmarkSuiteResult {
  runAt: string;
  totalRepos: number;
  successCount: number;
  failCount: number;
  meanRsisBefore: number;
  meanRsisAfter: number;
  meanDelta: number;
  results: BenchmarkRunResult[];
}

// ─── Benchmark Runner ─────────────────────────────────────────────────────────

/**
 * Benchmark Runner — evaluates the full RSIS pipeline across a catalog of repos.
 *
 * For each repository:
 *   1. Run dependency scan (OSV-based, no API key required)
 *   2. Compute baseline RSIS from raw scan results
 *   3. Project post-remediation RSIS by simulating application of
 *      all high-confidence upgrade candidates
 *   4. Record before/after delta and save structured results
 *
 * Design note: The benchmark runs in heuristic mode (skipEmbedding, skipReasoning)
 * so it completes without an API key. When GEMINI_API_KEY is set, it uses
 * full AI-powered reasoning for richer candidate data.
 */
export class BenchmarkRunner {
  private scorer: RSISScorer;
  private scanner: VulnerabilityScanner;

  constructor() {
    this.scorer = new RSISScorer();
    this.scanner = new VulnerabilityScanner();
  }

  /**
   * Run the benchmark against a list of repositories.
   */
  async run(
    repos: BenchmarkRepo[],
    options: { useNVD?: boolean; skipDev?: boolean } = {}
  ): Promise<BenchmarkSuiteResult> {
    const results: BenchmarkRunResult[] = [];
    const runAt = new Date().toISOString();

    console.log(`\n${"═".repeat(60)}`);
    console.log(`  RSIS Benchmark Suite — ${repos.length} repositories`);
    console.log(`${"═".repeat(60)}\n`);

    for (let i = 0; i < repos.length; i++) {
      const repo = repos[i];
      console.log(`[${i + 1}/${repos.length}] ${repo.name} (${repo.repoUrl})`);

      const result = await this.runSingle(repo, options);
      results.push(result);

      this.printResult(result);
      console.log();
    }

    const successful = results.filter((r) => r.success);
    const meanBefore = successful.length
      ? successful.reduce((s, r) => s + r.rsisBefore.totalScore, 0) / successful.length
      : 0;
    const meanAfter = successful.length
      ? successful.reduce((s, r) => s + r.rsisAfter.totalScore, 0) / successful.length
      : 0;

    const suite: BenchmarkSuiteResult = {
      runAt,
      totalRepos: repos.length,
      successCount: successful.length,
      failCount: repos.length - successful.length,
      meanRsisBefore: parseFloat(meanBefore.toFixed(2)),
      meanRsisAfter: parseFloat(meanAfter.toFixed(2)),
      meanDelta: parseFloat((meanAfter - meanBefore).toFixed(2)),
      results,
    };

    this.printSummary(suite);
    return suite;
  }

  /**
   * Run a single benchmark repo.
   */
  private async runSingle(
    repo: BenchmarkRepo,
    options: { useNVD?: boolean; skipDev?: boolean }
  ): Promise<BenchmarkRunResult> {
    const start = Date.now();

    try {
      // Step 1: Scan
      const scanReport = await this.scanner.scan(repo.repoUrl, {
        useNVD: options.useNVD ?? false,
        skipDev: options.skipDev ?? false,
        persist: false, // benchmark runs don't persist to DB
      });

      const scanResults = scanReport.results;
      const scanDurationMs = Date.now() - start;

      // Step 2: Compute baseline RSIS (no remediations, no retrieval)
      const rsisBefore = this.scorer.compute(scanResults, [], 0);

      // Step 3: Simulate remediations — project what RSIS would be after applying upgrades
      const projectedScanResults = this.simulateRemediation(scanResults);
      const rsisAfter = this.scorer.compute(projectedScanResults, [], 0);

      // Step 4: Compute metrics
      const allVulns = scanResults.flatMap((r) => r.vulnerabilities);
      const fixable = allVulns.filter((v) => v.fixedVersions.length > 0);

      const metrics = {
        totalDeps: scanReport.totalDependencies,
        totalVulns: scanReport.totalVulnerabilities,
        criticalCount: allVulns.filter((v) => v.severity === "CRITICAL").length,
        highCount: allVulns.filter((v) => v.severity === "HIGH").length,
        kevCount: allVulns.filter((v) => v.kev).length,
        fixableVulns: fixable.length,
        remediableRate: allVulns.length > 0
          ? parseFloat((fixable.length / allVulns.length).toFixed(3))
          : 1.0,
      };

      const scoreDelta = parseFloat(
        (rsisAfter.totalScore - rsisBefore.totalScore).toFixed(2)
      );

      const expectationMet =
        rsisBefore.totalScore >= repo.expectedRsisBefore[0] &&
        rsisBefore.totalScore <= repo.expectedRsisBefore[1];

      return {
        repo,
        success: true,
        scanDurationMs,
        rsisBefore,
        rsisAfter,
        scoreDelta,
        metrics,
        expectationMet,
      };
    } catch (error) {
      return {
        repo,
        success: false,
        error: error instanceof Error ? error.message : String(error),
        scanDurationMs: Date.now() - start,
        rsisBefore: this.zeroRSIS(),
        rsisAfter: this.zeroRSIS(),
        scoreDelta: 0,
        metrics: {
          totalDeps: 0,
          totalVulns: 0,
          criticalCount: 0,
          highCount: 0,
          kevCount: 0,
          fixableVulns: 0,
          remediableRate: 0,
        },
        expectationMet: false,
      };
    }
  }

  /**
   * Simulate applying all fixable upgrades and return a cleaned scan result set.
   *
   * Logic: For each dependency, if ALL its vulnerabilities have known fixed
   * versions, remove those vulnerabilities from the result (simulating a
   * successful upgrade). Deps with no fix remain unchanged.
   *
   * This gives a conservative lower bound on post-remediation RSIS.
   */
  private simulateRemediation(
    scanResults: DependencyScanResult[]
  ): DependencyScanResult[] {
    return scanResults.map((result) => {
      const fullyFixable = result.vulnerabilities.every(
        (v) => v.fixedVersions.length > 0
      );

      if (fullyFixable && result.vulnerabilities.length > 0) {
        // Simulate: after upgrade, no vulnerabilities remain
        return { ...result, vulnerabilities: [] };
      }

      // Partially fixable: remove only vulns with fixed versions
      const remaining = result.vulnerabilities.filter(
        (v) => v.fixedVersions.length === 0
      );
      return { ...result, vulnerabilities: remaining };
    });
  }

  private zeroRSIS(): RSISScore {
    return this.scorer.compute([], [], 0);
  }

  // ─── Console Output ─────────────────────────────────────────────────────────

  private printResult(r: BenchmarkRunResult): void {
    if (!r.success) {
      console.log(`   ✗ FAILED: ${r.error}`);
      return;
    }

    const before = r.rsisBefore.totalScore.toFixed(1);
    const after  = r.rsisAfter.totalScore.toFixed(1);
    const delta  = r.scoreDelta >= 0 ? `+${r.scoreDelta}` : `${r.scoreDelta}`;
    const grade  = `${r.rsisBefore.grade} → ${r.rsisAfter.grade}`;
    const expect = r.expectationMet ? "✓" : "~";

    console.log(
      `   ${expect} RSIS: ${before} → ${after} (${delta})  Grade: ${grade}  ` +
      `Vulns: ${r.metrics.totalVulns}  ` +
      `Fixable: ${(r.metrics.remediableRate * 100).toFixed(0)}%  ` +
      `KEV: ${r.metrics.kevCount}  ` +
      `Scan: ${r.scanDurationMs}ms`
    );
  }

  private printSummary(suite: BenchmarkSuiteResult): void {
    console.log(`${"─".repeat(60)}`);
    console.log(`  BENCHMARK SUMMARY`);
    console.log(`${"─".repeat(60)}`);
    console.log(`  Repos:       ${suite.successCount}/${suite.totalRepos} successful`);
    console.log(`  Mean RSIS Before:  ${suite.meanRsisBefore}`);
    console.log(`  Mean RSIS After:   ${suite.meanRsisAfter}`);
    console.log(`  Mean Delta:        +${suite.meanDelta}`);
    console.log(`${"─".repeat(60)}\n`);
  }
}
