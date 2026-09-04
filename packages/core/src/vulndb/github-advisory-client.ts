import type { Ecosystem, UnifiedVulnerability } from "../types.js";
import semver from "semver";

// ─── GitHub Advisory GraphQL Types ──────────────────────────────────────────

interface GHAdvisoryNode {
  ghsaId: string;
  summary: string;
  description: string;
  severity: string;
  publishedAt: string;
  updatedAt: string;
  cvss?: {
    score: number;
    vectorString: string;
  };
  identifiers: Array<{ type: string; value: string }>;
  references: Array<{ url: string }>;
  vulnerabilities: {
    nodes: Array<{
      package: { name: string; ecosystem: string };
      firstPatchedVersion: { identifier: string } | null;
      vulnerableVersionRange: string;
    }>;
  };
}

interface GHAdvisoryResponse {
  data: {
    securityVulnerabilities: {
      nodes: GHAdvisoryNode[];
      pageInfo: { hasNextPage: boolean; endCursor: string | null };
    };
  };
}

// ─── GitHub Advisory Client ──────────────────────────────────────────────────

/**
 * Queries the GitHub Security Advisory Database via GraphQL.
 * Uses the existing GITHUB_TOKEN for authentication.
 *
 * Design note: We use the `securityVulnerabilities` GraphQL endpoint
 * rather than REST because it supports filtering by ecosystem + package
 * and returns structured GHSA data.
 */
export class GitHubAdvisoryClient {
  readonly source = "GITHUB" as const;
  private readonly token: string;
  private readonly endpoint = "https://api.github.com/graphql";

  constructor(token?: string) {
    this.token = token || process.env.GITHUB_TOKEN || "";
  }

  /**
   * Map GitHub Advisory ecosystem names to our internal Ecosystem type.
   */
  private mapEcosystem(ghEcosystem: string): Ecosystem | null {
    const map: Record<string, Ecosystem> = {
      NPM: "npm",
      MAVEN: "maven",
      PIP: "pypi",
      CRATES: "cargo",
      RUST: "cargo",
      GO: "go",
      ACTIONS: "npm",
      NUGET: "nuget",
    };
    return map[ghEcosystem.toUpperCase()] ?? null;
  }

  /**
   * Map GitHub severity string to our Severity type.
   */
  private mapSeverity(severity: string): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN" {
    const map: Record<string, "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN"> = {
      CRITICAL: "CRITICAL",
      HIGH: "HIGH",
      MODERATE: "MEDIUM",
      MEDIUM: "MEDIUM",
      LOW: "LOW",
    };
    return map[severity?.toUpperCase()] ?? "UNKNOWN";
  }

  /**
   * Query GitHub Advisories for a specific package.
   * Returns normalized UnifiedVulnerability records.
   */
  async query(
    ecosystem: Ecosystem,
    packageName: string,
    version: string
  ): Promise<UnifiedVulnerability[]> {
    if (!this.token) {
      // Cannot authenticate — skip silently
      return [];
    }

    // Map our ecosystem to GitHub's enum
    const ghEcosystem = ecosystem === "npm" ? "NPM"
      : ecosystem === "maven" ? "MAVEN"
      : ecosystem === "pypi" ? "PIP"
      : ecosystem === "cargo" ? "RUST"
      : ecosystem === "go" ? "GO"
      : ecosystem === "nuget" ? "NUGET"
      : null;

    if (!ghEcosystem) return [];

    const query = `
      query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
        securityVulnerabilities(
          ecosystem: $ecosystem
          package: $package
          first: 20
        ) {
          nodes {
            ghsaId
            summary
            description
            severity
            publishedAt
            updatedAt
            cvss { score vectorString }
            identifiers { type value }
            references { url }
            vulnerabilities(first: 5) {
              nodes {
                package { name ecosystem }
                firstPatchedVersion { identifier }
                vulnerableVersionRange
              }
            }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    `;

    try {
      const response = await fetch(this.endpoint, {
        method: "POST",
        headers: {
          Authorization: `bearer ${this.token}`,
          "Content-Type": "application/json",
          "User-Agent": "vuln-shield/2.0",
        },
        body: JSON.stringify({
          query,
          variables: { ecosystem: ghEcosystem, package: packageName },
        }),
      });

      if (!response.ok) {
        console.warn(`[GitHubAdvisory] HTTP ${response.status} for ${packageName}`);
        return [];
      }

      const data = (await response.json()) as GHAdvisoryResponse;
      const nodes = data?.data?.securityVulnerabilities?.nodes ?? [];

      return nodes.filter((node) => this.appliesToVersion(node, ecosystem, packageName, version)).map((node): UnifiedVulnerability => {
        // Extract CVE ID from identifiers
        const cveId = node.identifiers.find((i) => i.type === "CVE")?.value ?? null;

        const fixedVersions = node.vulnerabilities.nodes
          .map((v) => v.firstPatchedVersion?.identifier)
          .filter((v): v is string => !!v);

        if (process.env.DEBUG_VULN_NORMALIZATION === "true" || process.env.NODE_ENV === "development") {
          console.log(`[GitHubAdvisory Normalizer Debug] GHSA: ${node.ghsaId} | CVE: ${cveId} | Pkg: ${packageName} (${ecosystem}) | Extracted Fixed: [${fixedVersions.join(", ")}]`);
        }

        return {
          cveId,
          osvId: undefined,
          githubAdvisoryId: node.ghsaId,
          severity: this.mapSeverity(node.severity),
          cvssScore: node.cvss?.score ?? null,
          cvssVector: node.cvss?.vectorString ?? null,
          summary: node.summary,
          details: node.description || null,
          publishedDate: node.publishedAt,
          modifiedDate: node.updatedAt,
          fixedVersions,
          references: node.references.map((r) => r.url),
          source: "GITHUB",
          affectedRange:
            node.vulnerabilities.nodes[0]?.vulnerableVersionRange ?? null,
          kev: false, // will be enriched by CISA KEV client
          mitigationGuidance: null,
        };
      });
    } catch (error) {
      console.warn(`[GitHubAdvisory] Failed to query for ${packageName}:`, error);
      return [];
    }
  }

  private appliesToVersion(
    node: GHAdvisoryNode,
    ecosystem: Ecosystem,
    packageName: string,
    version: string
  ): boolean {
    const affected = node.vulnerabilities.nodes.find((entry) =>
      entry.package.name.toLowerCase() === packageName.toLowerCase() &&
      this.mapEcosystem(entry.package.ecosystem) === ecosystem
    );
    if (!affected) return false;
    if (ecosystem !== "npm") return true;
    try {
      return semver.satisfies(version.replace(/^v/, ""), affected.vulnerableVersionRange, { includePrerelease: true });
    } catch {
      // Preserve the advisory when GitHub's range is not npm-semver syntax;
      // the source has still identified the exact package.
      return true;
    }
  }
}
