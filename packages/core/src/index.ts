// ─── VulnShield Core ────────────────────────────────────────────────────────
// AI-Powered Vulnerability Detection and Mitigation System
// Repository Security Intelligence & Context-Aware Remediation Platform
// ─────────────────────────────────────────────────────────────────────────────

// ─── Phase 1 Exports (unchanged) ─────────────────────────────────────────────

export { VulnerabilityScanner } from "./scanner.js";
export type { ScanOptions } from "./scanner.js";

export { GitHubClient } from "./github/index.js";

export { NpmParser, MavenParser, PythonParser } from "./parsers/index.js";
export { parseManifest, getParserForFile, MANIFEST_FILENAMES } from "./parsers/index.js";

export { OSVClient } from "./vulndb/osv-client.js";
export { NVDClient } from "./vulndb/nvd-client.js";

export { getDB, disconnectDB } from "./db.js";

export type {
  Ecosystem,
  ParsedDependency,
  ManifestFile,
  Severity,
  UnifiedVulnerability,
  DependencyScanResult,
  ScanReport,
  ManifestParser,
  VulnDBClient,
} from "./types.js";

// ─── Phase 2 & Research Upgrade Exports ─────────────────────────────────────

// Main intelligence pipeline entry point
export { IntelligenceAnalyzer } from "./analyzer.js";
export type { AnalysisOptions } from "./analyzer.js";

// Intelligence & Knowledge Graph modules
export { RepoKnowledgeGraphBuilder } from "./intelligence/knowledge-graph.js";
export { RepoUnderstander } from "./intelligence/repo-understander.js";
export { RepoChunker } from "./intelligence/chunker.js";
export { Embedder } from "./intelligence/embedder.js";
export { ContextRetriever } from "./intelligence/retriever.js";
export { SimilarRepoFinder } from "./intelligence/similar-repos.js";
export { ContextReasoner, ReasoningEngine } from "./intelligence/reasoner.js";
export { RemediationValidator } from "./intelligence/validator.js";
export { CandidateRanker } from "./intelligence/candidate-ranker.js";
export type { EvidenceSourceWeights } from "./intelligence/candidate-ranker.js";

// Benchmark suite
export { BenchmarkRunner } from "./benchmark/benchmark-runner.js";
export { formatBenchmarkReport } from "./benchmark/benchmark-report.js";
export { BENCHMARK_REPOS } from "./benchmark/benchmark-repos.js";
export type { BenchmarkRepo } from "./benchmark/benchmark-repos.js";
export type { BenchmarkRunResult, BenchmarkSuiteResult } from "./benchmark/benchmark-runner.js";
export { RSISScorer } from "./intelligence/rsis-scorer.js";

// Threat intelligence clients
export { GitHubAdvisoryClient } from "./vulndb/github-advisory-client.js";
export { CISAKEVClient, cisaKEV } from "./vulndb/cisa-kev-client.js";

// Evaluation
export { Evaluator } from "./evaluation/evaluator.js";
export {
  precisionAtK,
  recallAtK,
  mrr,
  ndcg,
  top1Accuracy,
  top3Accuracy,
  buildSuccessRate,
  vulnerabilityReductionRate,
  computeEvalMetrics,
} from "./evaluation/metrics.js";

// Research Upgrade Types
export type {
  RepositoryMetadata,
  RepositoryProfile,
  FolderNode,
  ChunkType,
  RepoChunk,
  RetrievedChunk,
  RetrievalFilter,
  RKGNode,
  RKGEdge,
  RKGNodeType,
  RKGEdgeType,
  RepositoryKnowledgeGraph,
  GraphContextPath,
  SimilarRepo,
  MaintenanceActivity,
  RemediationAction,
  CompatibilityRisk,
  ChainStep,
  EvidenceReference,
  CandidateRankingFeatures,
  RemediationCandidate,
  RemediationReport,
  RSISWeights,
  RSISSignals,
  RSISLiteratureRationale,
  RSISScore,
  RetrievalMetrics,
  RecommendationMetrics,
  ValidationMetrics,
  EvalMetrics,
  AnalysisResult,
} from "./types.js";
