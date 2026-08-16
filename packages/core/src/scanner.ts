import { GitHubClient } from "./github/index.js";
import { parseManifest } from "./parsers/index.js";
import { OSVClient } from "./vulndb/osv-client.js";
import { NVDClient } from "./vulndb/nvd-client.js";
import { getDB, disconnectDB } from "./db.js";
import type {
  ParsedDependency,
  UnifiedVulnerability,
  ScanReport,
  Severity,
  DependencyScanResult,
} from "./types.js";

export interface ScanOptions {
  /** Use NVD as an additional data source (slower due to rate limits) */
  useNVD?: boolean;
  /** Skip dev dependencies */
  skipDev?: boolean;
  /** Save results to database */
  persist?: boolean;
}

const DEFAULT_OPTIONS: ScanOptions = {
  useNVD: false,
  skipDev: false,
  persist: true,
};

/**
 * The main vulnerability scanner.
 * Orchestrates the full pipeline: repo → parse → scan → report.
 */
export class VulnerabilityScanner {
  private github: GitHubClient;
  private osv: OSVClient;
  private nvd: NVDClient;

  constructor(githubToken?: string, nvdApiKey?: string) {
    this.github = new GitHubClient(githubToken);
    this.osv = new OSVClient();
    this.nvd = new NVDClient(nvdApiKey);
  }

  /**
   * Run a full scan on a GitHub repository.
   */
  async scan(
    repoUrl: string,
    options: ScanOptions = {}
  ): Promise<ScanReport> {
    const opts = { ...DEFAULT_OPTIONS, ...options };
    const { owner, repo } = this.github.parseRepoUrl(repoUrl);

    // ── Step 1: Fetch manifests ──────────────────────────────────────────
    const manifests = await this.github.fetchManifests(repoUrl);

    if (manifests.length === 0) {
      throw new Error(
        `No dependency manifest files found in ${owner}/${repo}. ` +
          `Looked for: package.json, pom.xml, requirements.txt`
      );
    }

    // ── Step 2: Parse all dependencies ───────────────────────────────────
    let allDeps: ParsedDependency[] = [];

    for (const manifest of manifests) {
      const parsed = parseManifest(manifest.content, manifest.path);
      allDeps.push(...parsed);
    }

    // Optionally skip dev dependencies
    if (opts.skipDev) {
      allDeps = allDeps.filter((d) => !d.isDev);
    }

    // Deduplicate by ecosystem + name + version
    const deduped = this.deduplicateDeps(allDeps);

    // ── Step 3: Query vulnerability databases ────────────────────────────
    const results: DependencyScanResult[] = [];

    // Use OSV batch API for efficiency
    const osvBatchResults = await this.osv.queryBatch(
      deduped.map((d) => ({
        ecosystem: d.ecosystem,
        name: d.name,
        version: d.version,
      }))
    );

    for (const dep of deduped) {
      const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
      let vulns: UnifiedVulnerability[] = osvBatchResults.get(key) || [];

      // Optionally enrich with NVD data
      if (opts.useNVD && vulns.length > 0) {
        for (const vuln of vulns) {
          if (vuln.cveId && vuln.cvssScore === null) {
            const nvdData = await this.nvd.getCVEById(vuln.cveId);
            if (nvdData) {
              vuln.cvssScore = nvdData.cvssScore;
              vuln.cvssVector = nvdData.cvssVector;
              vuln.severity = nvdData.severity;
              if (nvdData.references.length > 0) {
                vuln.references = [
                  ...new Set([...vuln.references, ...nvdData.references]),
                ];
              }
            }
          }
        }
      }

      results.push({ dependency: dep, vulnerabilities: vulns });
    }

    // ── Step 4: Build report ─────────────────────────────────────────────
    const allVulns = results.flatMap((r) => r.vulnerabilities);
    const severityCounts = this.countSeverities(allVulns);

    const report: ScanReport = {
      scanId: "", // Will be set by DB or generated
      repoUrl,
      repoOwner: owner,
      repoName: repo,
      scannedAt: new Date().toISOString(),
      totalDependencies: deduped.length,
      totalVulnerabilities: allVulns.length,
      severityCounts,
      results,
    };

    // ── Step 5: Persist to database ──────────────────────────────────────
    if (opts.persist) {
      report.scanId = await this.persistScan(report);
    }

    return report;
  }

  /**
   * Remove duplicate dependencies (same ecosystem + name + version).
   */
  private deduplicateDeps(deps: ParsedDependency[]): ParsedDependency[] {
    const seen = new Set<string>();
    return deps.filter((d) => {
      const key = `${d.ecosystem}:${d.name}@${d.version}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  /**
   * Count vulnerabilities by severity level.
   */
  private countSeverities(
    vulns: UnifiedVulnerability[]
  ): Record<Severity, number> {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      UNKNOWN: 0,
    };

    for (const v of vulns) {
      counts[v.severity]++;
    }

    return counts;
  }

  /**
   * Save scan results to the database.
   */
  private async persistScan(report: ScanReport): Promise<string> {
    const db = getDB();

    const scan = await db.scan.create({
      data: {
        repoUrl: report.repoUrl,
        repoOwner: report.repoOwner,
        repoName: report.repoName,
        status: "complete",
        totalDeps: report.totalDependencies,
        totalVulns: report.totalVulnerabilities,
        completedAt: new Date(),
        dependencies: {
          create: report.results.map((r) => ({
            ecosystem: r.dependency.ecosystem,
            name: r.dependency.name,
            version: r.dependency.version,
            manifestPath: r.dependency.manifestPath,
            isDev: r.dependency.isDev,
            vulnerabilities: {
              create: r.vulnerabilities.map((v) => ({
                cveId: v.cveId,
                osvId: v.osvId ?? null,
                severity: v.severity,
                cvssScore: v.cvssScore,
                cvssVector: v.cvssVector,
                summary: v.summary,
                details: v.details,
                publishedDate: v.publishedDate,
                modifiedDate: v.modifiedDate,
                fixedVersions: JSON.stringify(v.fixedVersions),
                references: JSON.stringify(v.references),
                source: v.source,
                affectedRange: v.affectedRange,
                kev: v.kev,
                githubAdvisoryId: v.githubAdvisoryId ?? null,
                mitigationGuidance: v.mitigationGuidance,
              })),
            },
          })),
        },
      },
    });

    return scan.id;
  }
}
