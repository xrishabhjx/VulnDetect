import type {
  Ecosystem,
  Severity,
  UnifiedVulnerability,
  VulnDBClient,
} from "../types.js";

// ─── OSV API Types ──────────────────────────────────────────────────────────

interface OSVQueryRequest {
  package: {
    name: string;
    ecosystem: string;
  };
  version?: string;
}

interface OSVBatchRequest {
  queries: OSVQueryRequest[];
}

interface OSVAffected {
  package: {
    name: string;
    ecosystem: string;
    purl?: string;
  };
  ranges?: Array<{
    type: string;
    events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>;
  }>;
  versions?: string[];
}

interface OSVVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  severity?: Array<{
    type: string;
    score: string;
  }>;
  affected?: OSVAffected[];
  references?: Array<{
    type: string;
    url: string;
  }>;
}

interface OSVQueryResponse {
  vulns?: OSVVulnerability[];
}

interface OSVBatchResponse {
  results: OSVQueryResponse[];
}

// ─── Ecosystem Mapping ──────────────────────────────────────────────────────

const ECOSYSTEM_MAP: Record<Ecosystem, string> = {
  npm: "npm",
  maven: "Maven",
  pypi: "PyPI",
  cargo: "crates.io",
  go: "Go",
  nuget: "NuGet",
};

// ─── OSV Client ─────────────────────────────────────────────────────────────

/**
 * Client for the OSV.dev API (https://osv.dev).
 * Free, open-source vulnerability database aggregating 30+ sources.
 * No API key required.
 */
export class OSVClient implements VulnDBClient {
  source = "OSV" as const;
  private baseUrl = "https://api.osv.dev/v1";

  /**
   * Query vulnerabilities for a single package.
   */
  async query(
    ecosystem: Ecosystem,
    packageName: string,
    version: string
  ): Promise<UnifiedVulnerability[]> {
    // For Maven, OSV expects just the artifactId in some cases,
    // but the full groupId:artifactId format is also supported.
    const osvEcosystem = ECOSYSTEM_MAP[ecosystem];
    if (!osvEcosystem) return [];

    // Skip packages without a concrete version
    if (!version || version === "latest" || version === "UNKNOWN") return [];

    try {
      const response = await fetch(`${this.baseUrl}/query`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          package: {
            name: packageName,
            ecosystem: osvEcosystem,
          },
          version,
        }),
      });

      if (!response.ok) {
        console.error(
          `OSV query failed for ${packageName}@${version}: ${response.status}`
        );
        return [];
      }

      const data = (await response.json()) as OSVQueryResponse;
      return (data.vulns || []).map((v) =>
        this.normalizeVuln(v, ecosystem, packageName)
      );
    } catch (error) {
      console.error(
        `OSV query error for ${packageName}@${version}:`,
        error
      );
      return [];
    }
  }

  /**
   * Batch query — more efficient for scanning many dependencies at once.
   * OSV supports up to 1000 queries per batch.
   */
  async queryBatch(
    queries: Array<{
      ecosystem: Ecosystem;
      name: string;
      version: string;
    }>
  ): Promise<Map<string, UnifiedVulnerability[]>> {
    const results = new Map<string, UnifiedVulnerability[]>();

    // Filter out packages without concrete versions
    const validQueries = queries.filter(
      (q) => q.version && q.version !== "latest" && q.version !== "UNKNOWN"
    );

    if (validQueries.length === 0) return results;

    // Split into batches of 1000
    const batchSize = 1000;
    for (let i = 0; i < validQueries.length; i += batchSize) {
      const batch = validQueries.slice(i, i + batchSize);

      const request: OSVBatchRequest = {
        queries: batch.map((q) => ({
          package: {
            name: q.name,
            ecosystem: ECOSYSTEM_MAP[q.ecosystem],
          },
          version: q.version,
        })),
      };

      try {
        const response = await fetch(`${this.baseUrl}/querybatch`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(request),
        });

        if (!response.ok) {
          console.error(`OSV batch query failed: ${response.status}`);
          continue;
        }

        const data = (await response.json()) as OSVBatchResponse;

        for (let j = 0; j < data.results.length; j++) {
          const query = batch[j];
          const key = `${query.ecosystem}:${query.name}@${query.version}`;
          const vulns = (data.results[j].vulns || []).map((v) =>
            this.normalizeVuln(v, query.ecosystem, query.name)
          );
          results.set(key, vulns);
        }
      } catch (error) {
        console.error("OSV batch query error:", error);
      }
    }

    // Enrich any vulns missing severity with full detail fetch
    await this.enrichMissingSeverity(results);

    return results;
  }

  /**
   * For vulns where severity is UNKNOWN (batch API doesn't return it),
   * fetch the full record from /vulns/{id} to get the CVSS vector.
   */
  private async enrichMissingSeverity(
    results: Map<string, UnifiedVulnerability[]>
  ): Promise<void> {
    // Collect all vulns that need enrichment
    const toEnrich: Array<{ key: string; index: number; osvId: string }> = [];

    for (const [key, vulns] of results) {
      for (let i = 0; i < vulns.length; i++) {
        if (vulns[i].severity === "UNKNOWN" && vulns[i].osvId) {
          toEnrich.push({ key, index: i, osvId: vulns[i].osvId! });
        }
      }
    }

    if (toEnrich.length === 0) return;

    // Fetch in parallel batches of 10
    const concurrency = 10;
    for (let i = 0; i < toEnrich.length; i += concurrency) {
      const slice = toEnrich.slice(i, i + concurrency);
      await Promise.all(
        slice.map(async ({ key, index, osvId }) => {
          try {
            const res = await fetch(`${this.baseUrl}/vulns/${osvId}`);
            if (!res.ok) return;
            const full = (await res.json()) as OSVVulnerability;
            if (!full.severity?.length) return;

            const cvss = full.severity.find(
              (s) => s.type === "CVSS_V3" || s.type === "CVSS_V2"
            );
            if (!cvss) return;

            const score = this.extractCVSSScore(cvss.score);
            const severity = this.scoreSeverity(score);

            const vulnArr = results.get(key);
            if (vulnArr?.[index]) {
              vulnArr[index].cvssScore = score;
              vulnArr[index].cvssVector = cvss.score;
              vulnArr[index].severity = severity;
              // Also grab summary if it was missing
              if (
                (!vulnArr[index].summary ||
                  vulnArr[index].summary === "No description available") &&
                (full.summary || full.details)
              ) {
                vulnArr[index].summary =
                  full.summary ||
                  (full.details?.substring(0, 200) ?? "No description available");
              }
            }
          } catch {
            // Ignore errors per-vuln
          }
        })
      );
    }
  }


  /**
   * Normalize an OSV vulnerability record to our unified format.
   */
  private normalizeVuln(
    vuln: OSVVulnerability,
    ecosystem: Ecosystem,
    packageName: string
  ): UnifiedVulnerability {
    // Extract CVE ID from aliases
    const cveId =
      vuln.aliases?.find((a) => a.startsWith("CVE-")) || null;

    // Extract CVSS score
    let cvssScore: number | null = null;
    let cvssVector: string | null = null;
    const cvss = vuln.severity?.find(
      (s) => s.type === "CVSS_V3" || s.type === "CVSS_V2"
    );
    if (cvss) {
      cvssVector = cvss.score;
      cvssScore = this.extractCVSSScore(cvss.score);
    }

    // Determine severity from CVSS score
    const severity = this.scoreSeverity(cvssScore);

    // Extract fixed versions across all affected entries and ranges
    const fixedVersionsSet = new Set<string>();

    if (vuln.affected) {
      for (const affectedEntry of vuln.affected) {
        // Check if ecosystem & package match (case-insensitive)
        const matchEcosystem = affectedEntry.package.ecosystem?.toLowerCase() === ECOSYSTEM_MAP[ecosystem]?.toLowerCase();
        const matchPackage = affectedEntry.package.name?.toLowerCase() === packageName.toLowerCase();

        if (matchEcosystem || matchPackage || !affectedEntry.package.name) {
          if (affectedEntry.ranges) {
            for (const range of affectedEntry.ranges) {
              for (const event of range.events) {
                if (event.fixed) {
                  fixedVersionsSet.add(event.fixed);
                }
              }
            }
          }
        }
      }
    }

    const fixedVersions = Array.from(fixedVersionsSet);

    // Debug logging for advisory normalization audit
    if (process.env.DEBUG_VULN_NORMALIZATION === "true" || process.env.NODE_ENV === "development") {
      console.log(`[OSV Normalizer Debug] ID: ${vuln.id} | Pkg: ${packageName} (${ecosystem}) | Raw Affected Entries: ${vuln.affected?.length ?? 0} | Extracted Fixed: [${fixedVersions.join(", ")}]`);
    }

    // Build affected range string
    let affectedRange: string | null = null;
    const affectedEntry = vuln.affected?.find(
      (a) =>
        a.package.name?.toLowerCase() === packageName.toLowerCase() ||
        a.package.ecosystem?.toLowerCase() === ECOSYSTEM_MAP[ecosystem]?.toLowerCase()
    );

    if (affectedEntry?.ranges?.[0]) {
      const range = affectedEntry.ranges[0];
      const introduced = range.events.find((e) => e.introduced)?.introduced;
      const fixed = range.events.find((e) => e.fixed)?.fixed;
      if (introduced && fixed) {
        affectedRange = `>=${introduced}, <${fixed}`;
      } else if (introduced) {
        affectedRange = `>=${introduced}`;
      }
    }

    return {
      cveId,
      osvId: vuln.id,
      severity,
      cvssScore,
      cvssVector,
      summary: vuln.summary || vuln.details?.substring(0, 200) || "No description available",
      details: vuln.details || null,
      publishedDate: vuln.published || null,
      modifiedDate: vuln.modified || null,
      fixedVersions,
      references: vuln.references?.map((r) => r.url) || [],
      source: "OSV",
      affectedRange,
      kev: false,
      mitigationGuidance: null,
    };
  }

  /**
   * Extract numeric CVSS v3 base score from a CVSS vector string.
   * e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" → 9.8
   * Uses the official CVSS v3 base score formula.
   */
  private extractCVSSScore(vectorOrScore: string): number | null {
    // Already a plain number
    const num = parseFloat(vectorOrScore);
    if (!isNaN(num) && num >= 0 && num <= 10) return num;

    // Must be a CVSS v3 vector
    if (!vectorOrScore.includes("/")) return null;

    try {
      const parts = vectorOrScore.replace(/^CVSS:[0-9.]+\//, "").split("/");
      const metrics: Record<string, string> = {};
      for (const p of parts) {
        const [k, v] = p.split(":");
        if (k && v) metrics[k] = v;
      }

      // CVSS v3 base score weights
      const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
      const AC = { L: 0.77, H: 0.44 };
      const PR_noS = { N: 0.85, L: 0.62, H: 0.27 };
      const PR_S = { N: 0.85, L: 0.68, H: 0.5 };
      const UI = { N: 0.85, R: 0.62 };
      const CIA = { N: 0, L: 0.22, H: 0.56 };

      const scope = metrics["S"] ?? "U";
      const avW = AV[metrics["AV"] as keyof typeof AV] ?? 0;
      const acW = AC[metrics["AC"] as keyof typeof AC] ?? 0;
      const prW = scope === "C"
        ? (PR_S[metrics["PR"] as keyof typeof PR_S] ?? 0)
        : (PR_noS[metrics["PR"] as keyof typeof PR_noS] ?? 0);
      const uiW = UI[metrics["UI"] as keyof typeof UI] ?? 0;
      const cW = CIA[metrics["C"] as keyof typeof CIA] ?? 0;
      const iW = CIA[metrics["I"] as keyof typeof CIA] ?? 0;
      const aW = CIA[metrics["A"] as keyof typeof CIA] ?? 0;

      const iss = 1 - (1 - cW) * (1 - iW) * (1 - aW);
      const impact = scope === "C"
        ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
        : 6.42 * iss;

      const exploitability = 8.22 * avW * acW * prW * uiW;

      if (impact <= 0) return 0;

      let base: number;
      if (scope === "C") {
        base = Math.min(1.08 * (impact + exploitability), 10);
      } else {
        base = Math.min(impact + exploitability, 10);
      }

      return Math.ceil(base * 10) / 10;
    } catch {
      return null;
    }
  }

  /**
   * Map a CVSS score to a severity level.
   */
  private scoreSeverity(score: number | null): Severity {
    if (score === null) return "UNKNOWN";
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score > 0) return "LOW";
    return "UNKNOWN";
  }
}
