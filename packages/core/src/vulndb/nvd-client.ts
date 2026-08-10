import type {
  Ecosystem,
  Severity,
  UnifiedVulnerability,
  VulnDBClient,
} from "../types.js";

// ─── NVD API Types ──────────────────────────────────────────────────────────

interface NVDResponse {
  resultsPerPage: number;
  startIndex: number;
  totalResults: number;
  vulnerabilities: Array<{
    cve: NVDCve;
  }>;
}

interface NVDCve {
  id: string;
  published: string;
  lastModified: string;
  descriptions: Array<{
    lang: string;
    value: string;
  }>;
  metrics?: {
    cvssMetricV31?: Array<{
      cvssData: {
        version: string;
        vectorString: string;
        baseScore: number;
        baseSeverity: string;
      };
    }>;
    cvssMetricV2?: Array<{
      cvssData: {
        version: string;
        vectorString: string;
        baseScore: number;
      };
    }>;
  };
  references?: Array<{
    url: string;
    source: string;
  }>;
}

// ─── NVD Client ─────────────────────────────────────────────────────────────

/**
 * Client for the NIST NVD API (https://nvd.nist.gov/developers).
 * Free to use; API key recommended for higher rate limits.
 *
 * Rate limits:
 * - Without key: 5 requests per 30 seconds
 * - With key:    50 requests per 30 seconds
 *
 * The rate limiter uses a serialized promise queue so concurrent callers
 * (e.g. parallel `Promise.all` over vulnerabilities) still respect the
 * per-instance interval. A bare timestamp would race under concurrency.
 */
export class NVDClient implements VulnDBClient {
  source = "NVD" as const;
  private baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  private apiKey: string | undefined;
  private minRequestInterval: number; // ms between requests
  private queue: Promise<void> = Promise.resolve();
  private lastRequestTime = 0;
  private nextAllowedTime = 0;

  constructor(apiKey?: string) {
    this.apiKey = apiKey || process.env.NVD_API_KEY;
    // With key: 50 req/30s = 600ms apart. Without: 5 req/30s = 6000ms apart.
    // Add a small safety margin so we don't trip the limit on clock drift.
    this.minRequestInterval = this.apiKey ? 650 : 6500;
  }

  /**
   * Query NVD for vulnerabilities affecting a specific package.
   * Uses keyword search since NVD doesn't have a direct package→CVE API.
   */
  async query(
    ecosystem: Ecosystem,
    packageName: string,
    version: string
  ): Promise<UnifiedVulnerability[]> {
    if (!version || version === "latest" || version === "UNKNOWN") return [];

    // For Maven packages, use just the artifactId for search
    const searchName =
      ecosystem === "maven" && packageName.includes(":")
        ? packageName.split(":")[1]
        : packageName;

    try {
      await this.rateLimit();

      const params = new URLSearchParams({
        keywordSearch: searchName,
        resultsPerPage: "20",
      });

      const headers: Record<string, string> = {};
      if (this.apiKey) {
        headers["apiKey"] = this.apiKey;
      }

      const response = await fetch(`${this.baseUrl}?${params}`, { headers });

      if (response.status === 403 || response.status === 429) {
        console.error(
          `[NVD] Rate limit hit (HTTP ${response.status}) for ${searchName}. ` +
            `Backing off 30s before next call.`
        );
        // Push the next-allowed time forward so the queue pauses too.
        this.nextAllowedTime = Date.now() + 30_000;
        return [];
      }

      if (!response.ok) {
        console.error(`[NVD] Query failed for ${searchName}: HTTP ${response.status}`);
        return [];
      }

      const data = (await response.json()) as NVDResponse;

      return data.vulnerabilities.map((v) => this.normalizeVuln(v.cve));
    } catch (error) {
      console.error(`NVD query error for ${searchName}:`, error);
      return [];
    }
  }

  /**
   * Look up a specific CVE by its ID.
   * Useful for enriching OSV results with CVSS data from NVD.
   */
  async getCVEById(cveId: string): Promise<UnifiedVulnerability | null> {
    try {
      await this.rateLimit();

      const params = new URLSearchParams({ cveId });
      const headers: Record<string, string> = {};
      if (this.apiKey) {
        headers["apiKey"] = this.apiKey;
      }

      const response = await fetch(`${this.baseUrl}?${params}`, { headers });

      if (!response.ok) return null;

      const data = (await response.json()) as NVDResponse;
      if (data.vulnerabilities.length === 0) return null;

      return this.normalizeVuln(data.vulnerabilities[0].cve);
    } catch {
      return null;
    }
  }

  /**
   * Normalize an NVD CVE record to our unified format.
   */
  private normalizeVuln(cve: NVDCve): UnifiedVulnerability {
    // Get English description
    const summary =
      cve.descriptions.find((d) => d.lang === "en")?.value ||
      "No description available";

    // Extract CVSS v3.1 or fall back to v2
    let cvssScore: number | null = null;
    let cvssVector: string | null = null;
    let baseSeverity: string | null = null;

    if (cve.metrics?.cvssMetricV31?.[0]) {
      const cvss = cve.metrics.cvssMetricV31[0].cvssData;
      cvssScore = cvss.baseScore;
      cvssVector = cvss.vectorString;
      baseSeverity = cvss.baseSeverity;
    } else if (cve.metrics?.cvssMetricV2?.[0]) {
      const cvss = cve.metrics.cvssMetricV2[0].cvssData;
      cvssScore = cvss.baseScore;
      cvssVector = cvss.vectorString;
    }

    const severity: Severity = baseSeverity
      ? (baseSeverity.toUpperCase() as Severity)
      : this.scoreSeverity(cvssScore);

    const fixedVersions: string[] = [];

    if (process.env.DEBUG_VULN_NORMALIZATION === "true" || process.env.NODE_ENV === "development") {
      console.log(`[NVD Normalizer Debug] CVE: ${cve.id} | Extracted Fixed: [${fixedVersions.join(", ")}]`);
    }

    return {
      cveId: cve.id,
      severity,
      cvssScore,
      cvssVector,
      summary,
      details: null,
      publishedDate: cve.published,
      modifiedDate: cve.lastModified,
      fixedVersions,
      references: cve.references?.map((r) => r.url) || [],
      source: "NVD",
      affectedRange: null,
      kev: false,
      mitigationGuidance: null,
    };
  }

  private scoreSeverity(score: number | null): Severity {
    if (score === null) return "UNKNOWN";
    if (score >= 9.0) return "CRITICAL";
    if (score >= 7.0) return "HIGH";
    if (score >= 4.0) return "MEDIUM";
    if (score > 0) return "LOW";
    return "UNKNOWN";
  }

  /**
   * Concurrency-safe rate limiter. Each call returns a promise that
   * resolves only when the request is permitted by the per-instance
   * interval. By chaining onto `this.queue`, we serialize all NVD
   * requests even when callers invoke them in parallel.
   */
  private rateLimit(): Promise<void> {
    // Append a new task to the existing queue. The closure captures the
    // *current* `nextAllowedTime` at the moment this task runs (i.e.
    // after all previously-queued tasks have completed).
    const task = this.queue.then(async () => {
      const now = Date.now();
      const wait = Math.max(0, this.nextAllowedTime - now);
      if (wait > 0) {
        await this.sleep(wait);
      }
      this.lastRequestTime = Date.now();
      this.nextAllowedTime = this.lastRequestTime + this.minRequestInterval;
    });

    // Don't let an error in one queued request poison subsequent ones.
    this.queue = task.catch(() => undefined);
    return task;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
