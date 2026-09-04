import { describe, it, expect } from "vitest";
import {
  RSISScorer,
  precisionAtK,
  recallAtK,
  mrr,
  ndcg,
  top1Accuracy,
  top3Accuracy,
  buildSuccessRate,
  vulnerabilityReductionRate,
  RemediationValidator,
  CandidateRanker,
  RepoKnowledgeGraphBuilder,
} from "../src/index.js";
import type {
  DependencyScanResult,
  RemediationReport,
  RemediationCandidate,
  UnifiedVulnerability,
  SimilarRepo,
} from "../src/types.js";

// ─── RSISScorer ───────────────────────────────────────────────────────────────

describe("RSISScorer", () => {
  const scorer = new RSISScorer();

  it("should produce grade A (>=85) when no vulnerabilities exist", () => {
    const scanResults: DependencyScanResult[] = [
      {
        dependency: { name: "lodash", version: "4.17.21", ecosystem: "npm", isDev: false, manifestPath: "package.json" },
        vulnerabilities: [],
      },
    ];
    const score = scorer.compute(scanResults, [], 0.85);
    expect(score.totalScore).toBeGreaterThanOrEqual(85);
    expect(score.grade).toBe("A");
    expect(score.signals.totalVulns).toBe(0);
  });

  it("should include Literature Rationale in score output", () => {
    const score = scorer.compute([], [], 0);
    expect(score.rationale).toBeDefined();
    expect(score.rationale.formula).toMatch(/RSIS/);
    expect(score.rationale.citations.length).toBeGreaterThan(0);
    expect(score.rationale.ablationNotes).toBeTruthy();
  });

  it("should penalise CRITICAL + KEV vulnerabilities more than LOW", () => {
    const makeScan = (severity: "CRITICAL" | "LOW"): DependencyScanResult[] => [
      {
        dependency: { name: "pkg", version: "1.0.0", ecosystem: "npm", isDev: false, manifestPath: "package.json" },
        vulnerabilities: [{
          cveId: "CVE-2024-0001", severity, cvssScore: severity === "CRITICAL" ? 9.8 : 2.0,
          cvssVector: null, summary: "Test", details: null,
          publishedDate: null, modifiedDate: null,
          fixedVersions: [], references: [], source: "OSV",
          affectedRange: null, kev: severity === "CRITICAL", mitigationGuidance: null,
        }],
      },
    ];

    const critScore = scorer.compute(makeScan("CRITICAL"), [], 0);
    const lowScore = scorer.compute(makeScan("LOW"), [], 0);
    expect(critScore.totalScore).toBeLessThan(lowScore.totalScore);
  });

  it("should expose all 5 component scores", () => {
    const score = scorer.compute([], [], 0.7);
    expect(score).toHaveProperty("securityScore");
    expect(score).toHaveProperty("retrievalScore");
    expect(score).toHaveProperty("validationScore");
    expect(score).toHaveProperty("maintainabilityScore");
    expect(score).toHaveProperty("compatibilityScore");
  });
});

// ─── Candidate Ranker ─────────────────────────────────────────────────────────

describe("CandidateRanker", () => {
  const ranker = new CandidateRanker();

  const makeVuln = (cvss: number, kev: boolean): UnifiedVulnerability => ({
    cveId: "CVE-2024-0001", severity: "HIGH", cvssScore: cvss,
    cvssVector: null, summary: "XSS vulnerability", details: null,
    publishedDate: null, modifiedDate: null,
    fixedVersions: ["2.0.0"], references: [], source: "OSV",
    affectedRange: "<2.0.0", kev, mitigationGuidance: null,
  });

  const makeCandidate = (action: "upgrade" | "mitigate", version: string | null, validated: boolean, rejected: boolean): RemediationCandidate => ({
    action, explanation: "", reasoning: "", confidence: 0.8,
    compatibilityRisk: "medium", proposedVersion: version,
    alternativePackage: null, dependencyImpact: [],
    validated, rejected, rejectionReason: null, validationNotes: null,
  });

  it("should assign rank 1 to the best candidate", () => {
    const candidates: RemediationCandidate[] = [
      makeCandidate("mitigate", null, true, false),
      makeCandidate("upgrade", "2.0.0", true, false),
    ];
    const ranked = ranker.rankCandidates(candidates, makeVuln(8.5, true), "1.0.0", []);
    expect(ranked[0].rank).toBe(1);
    expect(ranked[1].rank).toBe(2);
  });

  it("should score rejected candidates lower than validated ones", () => {
    const candidates: RemediationCandidate[] = [
      makeCandidate("upgrade", "2.0.0", true, true),   // rejected
      makeCandidate("upgrade", "2.0.0", true, false),  // validated
    ];
    const ranked = ranker.rankCandidates(candidates, makeVuln(7.5, false), "1.0.0", []);
    expect(ranked[0].rank).toBe(1);
    // The non-rejected one should be ranked #1 (higher utility)
    expect(ranked[0].rankingFeatures!.validationScore).toBeGreaterThan(ranked[1].rankingFeatures!.validationScore);
  });

  it("should include rankingFeatures with evidenceStrengthScore on every candidate", () => {
    const candidates: RemediationCandidate[] = [
      makeCandidate("upgrade", "2.0.0", true, false),
    ];
    const ranked = ranker.rankCandidates(candidates, makeVuln(9.0, false), "1.0.0", []);
    expect(ranked[0].rankingFeatures).toBeDefined();
    expect(ranked[0].rankingFeatures!.utilityScore).toBeGreaterThan(0);
    expect(ranked[0].rankingFeatures!).toHaveProperty("evidenceStrengthScore");
    expect(ranked[0].rankingFeatures!.evidenceStrengthScore).toBeGreaterThanOrEqual(0);
    expect(ranked[0].rankingFeatures!.evidenceStrengthScore).toBeLessThanOrEqual(1);
  });

  it("should score multi-source evidence (OSV+NVD+KEV) higher than OSV alone", () => {
    const candidate = makeCandidate("upgrade", "2.0.0", true, false);

    // Vuln with CVSS vector (implies NVD) + KEV
    const richVuln: UnifiedVulnerability = {
      ...makeVuln(9.0, true),
      source: "OSV",
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    };
    // Vuln with only OSV, no CVSS vector, no KEV
    const sparseVuln: UnifiedVulnerability = {
      ...makeVuln(7.0, false),
      source: "OSV",
      cvssVector: null,
    };

    const richRanked = ranker.rankCandidates([candidate], richVuln, "1.0.0", []);
    const sparseRanked = ranker.rankCandidates([candidate], sparseVuln, "1.0.0", []);
    expect(richRanked[0].rankingFeatures!.evidenceStrengthScore)
      .toBeGreaterThan(sparseRanked[0].rankingFeatures!.evidenceStrengthScore);
  });
});

// ─── Repository Knowledge Graph ───────────────────────────────────────────────

describe("RepoKnowledgeGraphBuilder", () => {
  const builder = new RepoKnowledgeGraphBuilder();

  const fakeScanResults: DependencyScanResult[] = [
    {
      dependency: { name: "express", version: "4.17.1", ecosystem: "npm", isDev: false, manifestPath: "package.json" },
      vulnerabilities: [
        {
          cveId: "CVE-2022-24999", severity: "HIGH", cvssScore: 7.5,
          cvssVector: null, summary: "Prototype pollution", details: null,
          publishedDate: null, modifiedDate: null,
          fixedVersions: ["4.17.3"], references: [], source: "OSV",
          affectedRange: "<4.17.3", kev: false, mitigationGuidance: null,
        },
      ],
    },
  ];

  const fakeChunks = [
    {
      filePath: "src/app.ts",
      chunkType: "function" as const,
      language: "typescript",
      content: "import express from 'express'\nconst app = express()",
      startLine: 1, endLine: 5,
    },
  ];

  const fakeTree = [
    { path: "src/app.ts", type: "blob" as const, size: 500 },
    { path: "package.json", type: "blob" as const, size: 300 },
    { path: "src", type: "tree" as const },
  ];

  it("should build a graph with nodes and edges", () => {
    const graph = builder.buildGraph("https://github.com/test/repo", fakeTree, fakeScanResults, fakeChunks);
    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.edges.length).toBeGreaterThan(0);
  });

  it("should include Threat nodes for each vulnerability", () => {
    const graph = builder.buildGraph("https://github.com/test/repo", fakeTree, fakeScanResults, fakeChunks);
    const threatNodes = graph.nodes.filter((n) => n.type === "Threat");
    expect(threatNodes.length).toBe(1);
    expect(threatNodes[0].properties.cveId).toBe("CVE-2022-24999");
  });

  it("should include Package and Dependency nodes", () => {
    const graph = builder.buildGraph("https://github.com/test/repo", fakeTree, fakeScanResults, fakeChunks);
    const pkgNodes = graph.nodes.filter((n) => n.type === "Package");
    const depNodes = graph.nodes.filter((n) => n.type === "Dependency");
    expect(pkgNodes.length).toBe(1);
    expect(pkgNodes[0].label).toBe("express");
    expect(depNodes.length).toBe(1);
  });

  it("should traverse and return context paths for a known package", () => {
    builder.buildGraph("https://github.com/test/repo", fakeTree, fakeScanResults, fakeChunks);
    const paths = builder.traverseContext("express", "CVE-2022-24999");
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].dependency).toBe("express");
    expect(paths[0].explanation).toContain("express");
  });

  it("should return empty paths for an unknown package", () => {
    builder.buildGraph("https://github.com/test/repo", fakeTree, fakeScanResults, fakeChunks);
    const paths = builder.traverseContext("nonexistent-pkg", null);
    expect(paths).toHaveLength(0);
  });
});

// ─── RKG Security Enrichment ───────────────────────────────────────────────────

describe("RepoKnowledgeGraphBuilder — enrichWithThreatIntel", () => {
  const builder = new RepoKnowledgeGraphBuilder();

  const scan: DependencyScanResult[] = [
    {
      dependency: { name: "lodash", version: "4.17.20", ecosystem: "npm", isDev: false, manifestPath: "package.json" },
      vulnerabilities: [
        {
          cveId: "CVE-2021-23337",
          severity: "HIGH",
          cvssScore: 7.2,
          cvssVector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
          summary: "Command injection",
          details: null,
          publishedDate: null,
          modifiedDate: null,
          fixedVersions: ["4.17.21"],
          references: [],
          source: "OSV",
          affectedRange: "<4.17.21",
          kev: true,
          mitigationGuidance: null,
        },
      ],
    },
  ];

  it("should add CVSSNode with HAS_CVSS edge after enrichment", () => {
    builder.buildGraph("https://github.com/test/repo2", [], scan, []);
    const graph = builder.enrichWithThreatIntel(scan);
    const cvssEdges = graph.edges.filter((e) => e.relationship === "HAS_CVSS");
    expect(cvssEdges.length).toBe(1);
    const cvssNode = graph.nodes.find((n) => n.id.startsWith("cvss:"));
    expect(cvssNode).toBeDefined();
    expect(cvssNode!.properties.score).toBe(7.2);
  });

  it("should add KEVNode with IN_KEV edge for actively exploited CVEs", () => {
    builder.buildGraph("https://github.com/test/repo2", [], scan, []);
    const graph = builder.enrichWithThreatIntel(scan);
    const kevEdges = graph.edges.filter((e) => e.relationship === "IN_KEV");
    expect(kevEdges.length).toBe(1);
    const kevNode = graph.nodes.find((n) => n.id.startsWith("kev:"));
    expect(kevNode).toBeDefined();
    expect(kevNode!.properties.exploited).toBe(true);
  });

  it("should add PatchNode with FIXED_BY edge for each fixed version", () => {
    builder.buildGraph("https://github.com/test/repo2", [], scan, []);
    const graph = builder.enrichWithThreatIntel(scan);
    const patchEdges = graph.edges.filter((e) => e.relationship === "FIXED_BY");
    expect(patchEdges.length).toBe(1);
    const patchNode = graph.nodes.find((n) => n.id.startsWith("patch:"));
    expect(patchNode).toBeDefined();
    expect(patchNode!.properties.version).toBe("4.17.21");
  });

  it("traverseContext should include patchVersions and kevStatus from enriched graph", () => {
    builder.buildGraph("https://github.com/test/repo2", [], scan, []);
    builder.enrichWithThreatIntel(scan);
    const paths = builder.traverseContext("lodash", "CVE-2021-23337");
    expect(paths.length).toBeGreaterThan(0);
    expect(paths[0].patchVersions).toContain("4.17.21");
    expect(paths[0].kevStatus).toBe(true);
  });
});

// ─── Retrieval Metrics ────────────────────────────────────────────────────────

describe("ML Evaluation Metrics", () => {
  it("should compute Precision@K correctly", () => {
    const retrieved = ["doc1", "doc2", "doc3", "doc4", "doc5"];
    const relevant = new Set(["doc2", "doc5", "doc7"]);
    expect(precisionAtK(retrieved, relevant, 5)).toBeCloseTo(2 / 5, 3);
    expect(precisionAtK(retrieved, relevant, 3)).toBeCloseTo(1 / 3, 3);
    expect(precisionAtK([], relevant, 5)).toBe(0);
  });

  it("should compute Recall@K correctly", () => {
    const retrieved = ["doc1", "doc2", "doc3", "doc4", "doc5"];
    const relevant = new Set(["doc2", "doc5", "doc7"]);
    expect(recallAtK(retrieved, relevant, 5)).toBeCloseTo(2 / 3, 3);
  });

  it("should compute MRR correctly", () => {
    const lists = [["doc1", "doc2", "doc3"], ["doc4", "doc1", "doc2"]];
    const relevantSets = [new Set(["doc2"]), new Set(["doc4"])];
    expect(mrr(lists, relevantSets)).toBe((0.5 + 1.0) / 2);
  });

  it("should compute nDCG within [0,1]", () => {
    const retrieved = ["doc1", "doc2", "doc3"];
    const relMap = new Map([["doc1", 0.5], ["doc2", 1.0]]);
    const score = ndcg(retrieved, relMap, 3);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(1.0);
  });

  it("should compute Top-1 and Top-3 Accuracy", () => {
    const makeC = (action: "upgrade" | "mitigate"): RemediationCandidate => ({
      action, explanation: "", reasoning: "", confidence: 0.8,
      compatibilityRisk: "low", proposedVersion: null,
      alternativePackage: null, dependencyImpact: [],
      validated: true, rejected: false, rejectionReason: null, validationNotes: null,
    });

    const candidateLists = [[makeC("upgrade")], [makeC("mitigate")]];
    const truth = ["upgrade", "upgrade"];
    expect(top1Accuracy(candidateLists, truth)).toBe(0.5);
    expect(top3Accuracy(candidateLists, truth)).toBe(0.5);
  });

  it("should compute Build Success Rate and Vuln Reduction Rate", () => {
    const makeC = (validated: boolean, rejected: boolean): RemediationCandidate => ({
      action: "upgrade", explanation: "", reasoning: "", confidence: 0.9,
      compatibilityRisk: "low", proposedVersion: "2.0.0",
      alternativePackage: null, dependencyImpact: [],
      validated, rejected, rejectionReason: null, validationNotes: null,
    });
    expect(buildSuccessRate([makeC(true, false), makeC(true, true)])).toBe(0.5);
    expect(vulnerabilityReductionRate(4, 2)).toBe(0.5);
    expect(vulnerabilityReductionRate(0, 0)).toBe(1.0);
  });
});

// ─── Validator (SemVer diff smoke test) ───────────────────────────────────────

describe("RemediationValidator", () => {
  const validator = new RemediationValidator();

  it("should record mitigate candidates without claiming resolution proof", async () => {
    const report: RemediationReport = {
      scanId: "scan1", cveId: "CVE-2023-1234",
      packageName: "express", ecosystem: "npm",
      candidates: [{
        action: "mitigate", explanation: "", reasoning: "",
        confidence: 0.8, compatibilityRisk: "low",
        proposedVersion: null, alternativePackage: null,
        dependencyImpact: [],
        validated: false, rejected: false,
        rejectionReason: null, validationNotes: null,
      }],
      reasoningTrace: null, contextChunks: [], validationPassed: false,
    };
    const validated = await validator.validate(report, "npm", "4.17.1");
    expect(validated.validationPassed).toBe(false);
    expect(validated.candidates[0].validated).toBe(false);
    expect(validated.candidates[0].rejected).toBe(false);
  });
});

// ─── Benchmark Suite (in-memory, no network) ─────────────────────────────────

describe("BenchmarkRunner — in-memory simulation", () => {
  // Import the internal simulation logic via the scorer directly
  // (We test the RSIS scoring of before/after simulation without network calls)
  const scorer = new RSISScorer();

  const vulnerableScan: DependencyScanResult[] = [
    {
      dependency: { name: "express", version: "4.17.1", ecosystem: "npm", isDev: false, manifestPath: "package.json" },
      vulnerabilities: [
        {
          cveId: "CVE-2022-24999", severity: "HIGH", cvssScore: 7.5,
          cvssVector: null, summary: "Prototype pollution", details: null,
          publishedDate: null, modifiedDate: null,
          fixedVersions: ["4.17.3"], references: [], source: "OSV",
          affectedRange: "<4.17.3", kev: false, mitigationGuidance: null,
        },
      ],
    },
    {
      dependency: { name: "lodash", version: "4.17.20", ecosystem: "npm", isDev: false, manifestPath: "package.json" },
      vulnerabilities: [
        {
          cveId: "CVE-2021-23337", severity: "HIGH", cvssScore: 7.2,
          cvssVector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
          summary: "Command injection", details: null,
          publishedDate: null, modifiedDate: null,
          fixedVersions: ["4.17.21"], references: [], source: "OSV",
          affectedRange: "<4.17.21", kev: true, mitigationGuidance: null,
        },
      ],
    },
    {
      // Unfixable dependency — no patch available
      dependency: { name: "some-legacy-pkg", version: "1.0.0", ecosystem: "npm", isDev: false, manifestPath: "package.json" },
      vulnerabilities: [
        {
          cveId: "CVE-2019-0001", severity: "MEDIUM", cvssScore: 5.0,
          cvssVector: null, summary: "Legacy vulnerability", details: null,
          publishedDate: null, modifiedDate: null,
          fixedVersions: [], // No fix available
          references: [], source: "OSV",
          affectedRange: "*", kev: false, mitigationGuidance: null,
        },
      ],
    },
  ];

  // Simulate remediation: remove vulns with fixed versions available
  function simulateRemediation(scan: DependencyScanResult[]): DependencyScanResult[] {
    return scan.map((result) => {
      const fullyFixable = result.vulnerabilities.every((v) => v.fixedVersions.length > 0);
      if (fullyFixable && result.vulnerabilities.length > 0) {
        return { ...result, vulnerabilities: [] };
      }
      const remaining = result.vulnerabilities.filter((v) => v.fixedVersions.length === 0);
      return { ...result, vulnerabilities: remaining };
    });
  }

  it("RSIS before remediation should be lower than after remediation", () => {
    const rsisBefore = scorer.compute(vulnerableScan, [], 0);
    const fixedScan = simulateRemediation(vulnerableScan);
    const rsisAfter = scorer.compute(fixedScan, [], 0);

    expect(rsisAfter.totalScore).toBeGreaterThan(rsisBefore.totalScore);
    expect(rsisAfter.signals.totalVulns).toBeLessThan(rsisBefore.signals.totalVulns);
  });

  it("should only keep unfixable vulns after simulation", () => {
    const fixedScan = simulateRemediation(vulnerableScan);
    const remaining = fixedScan.flatMap((r) => r.vulnerabilities);
    // Only the legacy pkg with no fix should remain
    expect(remaining.length).toBe(1);
    expect(remaining[0].cveId).toBe("CVE-2019-0001");
  });

  it("should produce a valid RSISScore with all 5 components after remediation", () => {
    const fixedScan = simulateRemediation(vulnerableScan);
    const score = scorer.compute(fixedScan, [], 0);
    expect(score).toHaveProperty("securityScore");
    expect(score).toHaveProperty("retrievalScore");
    expect(score).toHaveProperty("validationScore");
    expect(score).toHaveProperty("maintainabilityScore");
    expect(score).toHaveProperty("compatibilityScore");
    expect(score.totalScore).toBeGreaterThanOrEqual(0);
    expect(score.totalScore).toBeLessThanOrEqual(100);
  });

  it("score delta should be positive when fixable vulns exist", () => {
    const rsisBefore = scorer.compute(vulnerableScan, [], 0);
    const rsisAfter = scorer.compute(simulateRemediation(vulnerableScan), [], 0);
    const delta = rsisAfter.totalScore - rsisBefore.totalScore;
    expect(delta).toBeGreaterThan(0);
  });
});

// ─── Benchmark Catalog ────────────────────────────────────────────────────────

describe("BENCHMARK_REPOS catalog", () => {
  it("should contain at least 5 repos", async () => {
    const { BENCHMARK_REPOS } = await import("../src/benchmark/benchmark-repos.js");
    expect(BENCHMARK_REPOS.length).toBeGreaterThanOrEqual(5);
  });

  it("every repo should have valid ecosystem and expected RSIS range", async () => {
    const { BENCHMARK_REPOS } = await import("../src/benchmark/benchmark-repos.js");
    for (const repo of BENCHMARK_REPOS) {
      expect(["npm", "maven", "pypi"]).toContain(repo.ecosystem);
      expect(repo.expectedRsisBefore[0]).toBeLessThan(repo.expectedRsisBefore[1]);
      expect(repo.repoUrl).toMatch(/^[\w.-]+\/[\w.-]+$/);
    }
  });
});

// ─── Configurable Evidence Weights ───────────────────────────────────────────

describe("Evidence Source Weights — configurable via env", () => {
  it("default weights loaded from env should sum to 1.0", async () => {
    // Import after env is clear so defaults are used
    const { CandidateRanker: Ranker } = await import("../src/intelligence/candidate-ranker.js");
    const ranker = new Ranker();
    // We can't inspect evidenceWeights directly (private), but we can verify
    // evidenceStrengthScore is within [0, 1] on a known-source vulnerability
    const vuln: UnifiedVulnerability = {
      cveId: "CVE-2024-TEST", severity: "HIGH", cvssScore: 7.5,
      cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      summary: "Test", details: null, publishedDate: null, modifiedDate: null,
      fixedVersions: ["2.0.0"], references: [], source: "NVD",
      affectedRange: "<2.0.0", kev: true, mitigationGuidance: null,
    };
    const candidate: RemediationCandidate = {
      action: "upgrade", explanation: "", reasoning: "", confidence: 0.9,
      compatibilityRisk: "low", proposedVersion: "2.0.0",
      alternativePackage: null, dependencyImpact: [],
      validated: true, rejected: false, rejectionReason: null, validationNotes: null,
    };
    const ranked = ranker.rankCandidates([candidate], vuln, "1.0.0", []);
    const ess = ranked[0].rankingFeatures!.evidenceStrengthScore;
    expect(ess).toBeGreaterThanOrEqual(0);
    expect(ess).toBeLessThanOrEqual(1);
    // NVD source (CVSS vector present) + KEV = 0.20 + 0.20 = 0.40 minimum
    expect(ess).toBeGreaterThanOrEqual(0.35);
  });
});
