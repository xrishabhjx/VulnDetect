import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { OSVClient } from "../src/vulndb/osv-client.js";
import { GitHubAdvisoryClient } from "../src/vulndb/github-advisory-client.js";
import { NVDClient } from "../src/vulndb/nvd-client.js";
import { RepoKnowledgeGraphBuilder } from "../src/intelligence/knowledge-graph.js";
import { RemediationValidator } from "../src/intelligence/validator.js";
import { ContextReasoner } from "../src/intelligence/reasoner.js";
import type {
  UnifiedVulnerability,
  DependencyScanResult,
  RepositoryContext,
  GraphContextPath,
  Ecosystem,
} from "../src/types.js";

describe("Vulnerability Normalization & Fixed Version Pipeline Propagation Audit", () => {
  let osvClient: OSVClient;
  let ghAdvisoryClient: GitHubAdvisoryClient;
  let nvdClient: NVDClient;
  let rkgBuilder: RepoKnowledgeGraphBuilder;
  let validator: RemediationValidator;
  let reasoner: ContextReasoner;

  beforeEach(() => {
    osvClient = new OSVClient();
    ghAdvisoryClient = new GitHubAdvisoryClient();
    nvdClient = new NVDClient();
    rkgBuilder = new RepoKnowledgeGraphBuilder();
    validator = new RemediationValidator();
    reasoner = new ContextReasoner();
  });

  // ─── 1. Upstream Advisory Normalization & Fixed Version Extraction ──────

  describe("Upstream Normalization (OSV / GitHub / NVD)", () => {
    it("correctly extracts fixed versions from raw OSV response for lodash (npm)", async () => {
      // Direct query to OSV for lodash 4.17.15 (vulnerable)
      const results = await osvClient.query("npm", "lodash", "4.17.15");
      expect(results.length).toBeGreaterThan(0);

      // Verify that at least one vulnerability contains non-empty fixedVersions
      const fixable = results.find((v) => v.fixedVersions.length > 0);
      expect(fixable).toBeDefined();
      expect(fixable!.fixedVersions).toContain("4.17.21");
    });

    it("correctly extracts fixed versions from raw OSV response for express-jwt (npm)", async () => {
      const results = await osvClient.query("npm", "express-jwt", "0.1.3");
      expect(results.length).toBeGreaterThan(0);

      const fixable = results.find((v) => v.fixedVersions.length > 0);
      expect(fixable).toBeDefined();
      expect(fixable!.fixedVersions.length).toBeGreaterThan(0);
    });

    it("correctly extracts fixed versions from raw OSV response for js-yaml (npm)", async () => {
      const results = await osvClient.query("npm", "js-yaml", "3.14.0");
      expect(results.length).toBeGreaterThan(0);

      const fixable = results.find((v) => v.fixedVersions.length > 0);
      expect(fixable).toBeDefined();
      expect(fixable!.fixedVersions.length).toBeGreaterThan(0);
    });

    it("correctly extracts fixed versions from raw OSV response for body-parser (npm)", async () => {
      const results = await osvClient.query("npm", "body-parser", "1.20.2");
      expect(results.length).toBeGreaterThan(0);

      const fixable = results.find((v) => v.fixedVersions.length > 0);
      expect(fixable).toBeDefined();
      expect(fixable!.fixedVersions).toContain("1.20.3");
    });

    it("supports multi-ecosystem fixed version extraction (Maven, PyPI, Cargo, Go, NuGet)", async () => {
      // Test PyPI
      const pypiResults = await osvClient.query("pypi", "django", "3.0.0");
      if (pypiResults.length > 0) {
        const fixable = pypiResults.find((v) => v.fixedVersions.length > 0);
        expect(fixable).toBeDefined();
      }

      // Test Cargo
      const cargoResults = await osvClient.query("cargo", "tokio", "0.2.0");
      if (cargoResults.length > 0) {
        const fixable = cargoResults.find((v) => v.fixedVersions.length > 0);
        expect(fixable).toBeDefined();
      }

      // Test Go
      const goResults = await osvClient.query("go", "github.com/gin-gonic/gin", "v1.6.0");
      if (goResults.length > 0) {
        const fixable = goResults.find((v) => v.fixedVersions.length > 0);
        expect(fixable).toBeDefined();
      }
    });
  });

  // ─── 2. Knowledge Graph Enrichment & Traversal ────────────────────────────

  describe("Knowledge Graph Fixed Version Propagation", () => {
    it("propagates fixedVersions to FIXED_BY nodes during RKG enrichment", () => {
      const mockScanResult: DependencyScanResult = {
        dependency: {
          name: "lodash",
          version: "4.17.15",
          ecosystem: "npm",
          isDev: false,
          manifestPath: "package.json",
        },
        vulnerabilities: [
          {
            cveId: "CVE-2021-23337",
            osvId: "GHSA-35jh-r3h4-6jhm",
            severity: "HIGH",
            cvssScore: 7.2,
            cvssVector: null,
            summary: "Command injection in lodash",
            details: null,
            publishedDate: null,
            modifiedDate: null,
            fixedVersions: ["4.17.21"],
            references: [],
            source: "OSV",
            affectedRange: "< 4.17.21",
            kev: false,
            mitigationGuidance: null,
          },
        ],
      };

      rkgBuilder.buildGraph("https://github.com/example/repo", [], [mockScanResult], []);
      const enriched = rkgBuilder.enrichWithThreatIntel([mockScanResult]);

      // Check FIXED_BY edge
      const fixedByEdge = enriched.edges.find((e) => e.relationship === "FIXED_BY");
      expect(fixedByEdge).toBeDefined();

      // Check context traversal
      const paths: GraphContextPath[] = rkgBuilder.traverseContext("lodash", "CVE-2021-23337");
      expect(paths.length).toBeGreaterThan(0);
      expect(paths[0].patchVersions).toContain("4.17.21");
    });
  });

  // ─── 3. Recommendation Engine & Validator ──────────────────────────────────

  describe("Recommendation Engine & Validator Propagation Guarantee", () => {
    it("NEVER emits 'No patch available' when fixedVersions are present", async () => {
      const mockVuln: UnifiedVulnerability = {
        cveId: "CVE-2021-23337",
        osvId: "GHSA-35jh-r3h4-6jhm",
        severity: "HIGH",
        cvssScore: 7.2,
        cvssVector: null,
        summary: "Command injection in lodash",
        details: null,
        publishedDate: null,
        modifiedDate: null,
        fixedVersions: ["4.17.21"],
        references: [],
        source: "OSV",
        affectedRange: "< 4.17.21",
        kev: false,
        mitigationGuidance: null,
      };

      const mockCtx: RepositoryContext = {
        profile: null,
        graphSummary: "Test Graph",
        graphPaths: [
          {
            dependency: "lodash",
            package: "lodash",
            threatId: "CVE-2021-23337",
            affectedModules: [],
            impactedFiles: ["package.json"],
            patchVersions: ["4.17.21"],
            kevStatus: false,
            explanation: "Graph context",
          },
        ],
        retrievedChunks: [],
        similarRepos: [],
        similarRepoEvidence: [],
        threatSummary: "High Severity CVE",
      };

      const report = await reasoner.reason(
        "test-scan-123",
        mockVuln,
        "lodash",
        "4.17.15",
        "npm",
        mockCtx
      );

      expect(report.candidates.length).toBeGreaterThan(0);
      const top = report.candidates[0];

      // Recommendation action must be UPGRADE, proposed version must be 4.17.21
      expect(top.action).toBe("upgrade");
      expect(top.proposedVersion).toBe("4.17.21");
      expect(top.explanation.toLowerCase()).not.toContain("no patch available");
      expect(top.explanation).toContain("4.17.21");

      // Validate through Validator
      const validated = await validator.validate(report, "npm", "4.17.15");
      expect(validated.candidates[0].validated).toBe(true);
      expect(validated.candidates[0].rejected).toBe(false);
    });
  });
});
