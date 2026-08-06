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
 * - With key: 50 requests per 30 seconds
 */
export class NVDClient implements VulnDBClient {
  source = "NVD" as const;
  private baseUrl = "https://services.nvd.nist.gov/rest/json/cves/2.0";
  private apiKey: string | undefined;
  private lastRequestTime = 0;
  private minRequestInterval: number; // ms between requests

  constructor(apiKey?: string) {
    this.apiKey = apiKey || process.env.NVD_API_KEY;
    // With key: 50 req/30s = 600ms apart. Without: 5 req/30s = 6000ms apart
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

      if (response.status === 403) {
        console.error("NVD rate limit exceeded. Waiting...");
        await this.sleep(30000);
        return [];
      }

      if (!response.ok) {
        console.error(`NVD query failed for ${searchName}: ${response.status}`);
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
   * Simple rate limiter to respect NVD API limits.
   */
  private async rateLimit(): Promise<void> {
    const now = Date.now();
    const elapsed = now - this.lastRequestTime;

    if (elapsed < this.minRequestInterval) {
      await this.sleep(this.minRequestInterval - elapsed);
    }

    this.lastRequestTime = Date.now();
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
