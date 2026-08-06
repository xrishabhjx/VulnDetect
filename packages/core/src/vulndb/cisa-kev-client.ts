// ─── CISA Known Exploited Vulnerabilities (KEV) Client ──────────────────────

/**
 * Fetches and caches the CISA Known Exploited Vulnerabilities catalog.
 * https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 *
 * The catalog is a public JSON feed updated regularly. We fetch it once
 * per process lifetime and expose a simple lookup Set.
 *
 * Design: No API key required. Catalog is ~350KB compressed and fetched once.
 */

interface KEVCatalog {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KEVEntry[];
}

interface KEVEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  notes?: string;
}

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export class CISAKEVClient {
  readonly source = "CISA_KEV" as const;

  private kevSet: Set<string> | null = null;
  private lastFetched: number = 0;
  /** Refresh the catalog every 24 hours */
  private readonly cacheTtlMs = 24 * 60 * 60 * 1000;

  /**
   * Get the KEV catalog as a Set of CVE IDs.
   * Fetches from CISA if the cache is stale or empty.
   */
  async getKEVSet(): Promise<Set<string>> {
    const now = Date.now();

    if (this.kevSet && now - this.lastFetched < this.cacheTtlMs) {
      return this.kevSet;
    }

    try {
      const response = await fetch(KEV_URL, {
        headers: { "User-Agent": "vuln-shield/2.0" },
        signal: AbortSignal.timeout(10_000),
      });

      if (!response.ok) {
        console.warn(`[CISA KEV] HTTP ${response.status} — using stale cache`);
        return this.kevSet ?? new Set();
      }

      const catalog = (await response.json()) as KEVCatalog;
      this.kevSet = new Set(catalog.vulnerabilities.map((v) => v.cveID));
      this.lastFetched = now;
      console.log(`[CISA KEV] Loaded ${this.kevSet.size} known-exploited CVEs`);
    } catch (error) {
      console.warn("[CISA KEV] Failed to fetch catalog:", error);
      this.kevSet = this.kevSet ?? new Set();
    }

    return this.kevSet;
  }

  /**
   * Check if a given CVE ID is in the CISA KEV catalog.
   */
  async isKnownExploited(cveId: string | null): Promise<boolean> {
    if (!cveId) return false;
    const kevSet = await this.getKEVSet();
    return kevSet.has(cveId);
  }

  /**
   * Enrich a list of CVE IDs — returns a Set of KEV-confirmed CVEs from the list.
   */
  async filterKEV(cveIds: (string | null)[]): Promise<Set<string>> {
    const kevSet = await this.getKEVSet();
    const result = new Set<string>();
    for (const id of cveIds) {
      if (id && kevSet.has(id)) result.add(id);
    }
    return result;
  }
}

/** Singleton instance shared across the process */
export const cisaKEV = new CISAKEVClient();
