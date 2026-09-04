import { GitHubClient } from "./github/index.js";
import { parseManifest } from "./parsers/index.js";
import { OSVClient } from "./vulndb/osv-client.js";
import { NVDClient } from "./vulndb/nvd-client.js";
import { GitHubAdvisoryClient } from "./vulndb/github-advisory-client.js";
import { getDB, disconnectDB } from "./db.js";
import type {
  ParsedDependency,
  UnifiedVulnerability,
  ScanReport,
  Severity,
  DependencyScanResult,
  VulnerabilitySourceState,
} from "./types.js";

export interface ScanOptions {
  /** Use NVD as an additional data source (slower due to rate limits) */
  useNVD?: boolean;
  /** Query GitHub's package-scoped advisory database when a token is configured. */
  useGitHubAdvisories?: boolean;
  /** Skip dev dependencies */
  skipDev?: boolean;
  /** Save results to database */
  persist?: boolean;
}

const DEFAULT_OPTIONS: ScanOptions = {
  useNVD: false,
  useGitHubAdvisories: true,
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
  private githubAdvisories: GitHubAdvisoryClient;
  private readonly githubAdvisoriesEnabled: boolean;

  constructor(githubToken?: string, nvdApiKey?: string) {
    this.github = new GitHubClient(githubToken);
    this.osv = new OSVClient();
    this.nvd = new NVDClient(nvdApiKey);
    this.githubAdvisories = new GitHubAdvisoryClient(githubToken);
    this.githubAdvisoriesEnabled = Boolean(githubToken || process.env.GITHUB_TOKEN);
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
    const deduped = this.deduplicateDeps(this.resolveNpmLockfileVersions(allDeps));
    const unresolvedDependencies = deduped.filter((d) =>
      !d.version || d.version === "UNKNOWN" || d.version === "latest"
    ).length;

    // ── Step 3: Query vulnerability databases ────────────────────────────
    const results: DependencyScanResult[] = [];
    const sources: VulnerabilitySourceState[] = [
      { source: "OSV" as const, status: "available" as const },
      { source: "NVD" as const, status: opts.useNVD ? "available" as const : "disabled" as const },
      { source: "GITHUB" as const, status: opts.useGitHubAdvisories && this.githubAdvisoriesEnabled ? "available" as const : "disabled" as const },
    ];

    // Use OSV batch API for efficiency
    let osvBatchResults = new Map<string, UnifiedVulnerability[]>();
    try {
      osvBatchResults = await this.osv.queryBatch(deduped.map((d) => ({
        ecosystem: d.ecosystem, name: d.name, version: d.version,
      })));
    } catch (error) {
      sources[0] = { source: "OSV", status: "unavailable", error: this.errorMessage(error) };
    }

    for (const dep of deduped) {
      const key = `${dep.ecosystem}:${dep.name}@${dep.version}`;
      let vulns: UnifiedVulnerability[] = osvBatchResults.get(key) || [];

      if (opts.useGitHubAdvisories && this.githubAdvisoriesEnabled && dep.version !== "UNKNOWN") {
        try {
          const advisories = await this.githubAdvisories.query(dep.ecosystem, dep.name, dep.version);
          vulns = this.mergeVulnerabilities(vulns, advisories);
        } catch (error) {
          sources.find((s) => s.source === "GITHUB")!.status = "unavailable";
          sources.find((s) => s.source === "GITHUB")!.error = this.errorMessage(error);
        }
      }

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
      dataQuality: unresolvedDependencies > 0 || sources.some((s) => s.status === "unavailable") ? "partial" : "complete",
      unresolvedDependencies,
      warnings: [
        ...(unresolvedDependencies > 0 ? [`${unresolvedDependencies} dependencies have no resolved installed version; vulnerability matching was skipped for them.`] : []),
        ...sources.filter((s) => s.status === "unavailable").map((s) => `${s.source} was unavailable: ${s.error ?? "unknown error"}`),
      ],
      sources,
      results,
    };

    // ── Step 5: Persist to database ──────────────────────────────────────
    if (opts.persist) {
      report.scanId = await this.persistScan(report);
    }

    return report;
  }

  private mergeVulnerabilities(
    existing: UnifiedVulnerability[],
    incoming: UnifiedVulnerability[]
  ): UnifiedVulnerability[] {
    const merged = [...existing];
    for (const candidate of incoming) {
      const match = merged.find((v) =>
        (candidate.cveId && v.cveId === candidate.cveId) ||
        (candidate.githubAdvisoryId && v.githubAdvisoryId === candidate.githubAdvisoryId) ||
        (candidate.osvId && v.osvId === candidate.osvId)
      );
      if (!match) {
        merged.push(candidate);
        continue;
      }
      match.githubAdvisoryId ??= candidate.githubAdvisoryId;
      match.osvId ??= candidate.osvId;
      match.cveId ??= candidate.cveId;
      match.cvssScore ??= candidate.cvssScore;
      match.cvssVector ??= candidate.cvssVector;
      match.fixedVersions = [...new Set([...match.fixedVersions, ...candidate.fixedVersions])];
      match.references = [...new Set([...match.references, ...candidate.references])];
    }
    return merged;
  }

  private errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : "unknown source error";
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

  private resolveNpmLockfileVersions(deps: ParsedDependency[]): ParsedDependency[] {
    const lockVersions = new Map<string, string>();
    for (const dep of deps) {
      if (dep.ecosystem === "npm" && dep.manifestPath.endsWith("package-lock.json")) {
        const current = lockVersions.get(dep.name);
        if (!current || dep.name.split("/").length <= 2) lockVersions.set(dep.name, dep.version);
      }
    }

    return deps.map((dep) => {
      if (dep.ecosystem !== "npm" || dep.version !== "UNKNOWN") return dep;
      const resolved = lockVersions.get(dep.name);
      return resolved ? { ...dep, version: resolved } : dep;
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
        status: report.dataQuality,
        sourceStates: JSON.stringify(report.sources),
        totalDeps: report.totalDependencies,
        totalVulns: report.totalVulnerabilities,
        completedAt: new Date(),
        dependencies: {
          create: report.results.map((r) => ({
            ecosystem: r.dependency.ecosystem,
            name: r.dependency.name,
            version: r.dependency.version,
            versionSpec: r.dependency.versionSpec ?? null,
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
