// Re-export all types from the backend for frontend use
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type Ecosystem = "npm" | "maven" | "pypi" | "cargo" | "go" | "nuget";
export type RemediationAction = "upgrade" | "replace" | "mitigate" | "accept";
export type CompatibilityRisk = "low" | "medium" | "high";
export type ChunkType = "function" | "class" | "module" | "documentation" | "config";
export type MaintenanceActivity = "active" | "moderate" | "stale";

export interface ParsedDependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  isDev: boolean;
  manifestPath: string;
}

export interface UnifiedVulnerability {
  cveId: string | null;
  osvId?: string;
  githubAdvisoryId?: string;
  severity: Severity;
  cvssScore: number | null;
  cvssVector: string | null;
  summary: string;
  details: string | null;
  publishedDate: string | null;
  modifiedDate: string | null;
  fixedVersions: string[];
  references: string[];
  source: "OSV" | "NVD" | "GITHUB" | "CISA_KEV";
  affectedRange: string | null;
  kev: boolean;
  mitigationGuidance: string | null;
}

export interface DependencyScanResult {
  dependency: ParsedDependency;
  vulnerabilities: UnifiedVulnerability[];
}

export interface ScanReport {
  scanId: string;
  repoUrl: string;
  repoOwner: string;
  repoName: string;
  scannedAt: string;
  totalDependencies: number;
  totalVulnerabilities: number;
  severityCounts: Record<Severity, number>;
  results: DependencyScanResult[];
}

export interface FolderNode {
  path: string;
  type: "blob" | "tree";
  size?: number;
}

export interface RepositoryMetadata {
  language: string | null;
  languages: Record<string, number>;
  framework: string | null;
  purpose: string | null;
  topics: string[];
  description: string | null;
  folderHierarchy: FolderNode[];
  totalFiles: number;
  hasDockerfile: boolean;
  hasCiCd: boolean;
  hasTests: boolean;
  stars: number;
  forks: number;
  openIssues: number;
  lastPushed: string | null;
}

export interface RepositoryProfile extends RepositoryMetadata {
  architecture: string | null;
  repositoryType: "web-app" | "api" | "library" | "cli" | "monorepo" | "data" | "unknown";
  database: string | null;
  orm: string | null;
  authentication: string | null;
  deployment: string | null;
  ciCdPlatform: string | null;
  testingFramework: string | null;
  packageManagers: string[];
  primaryDependencies: string[];
}

export type RKGNodeType = "Repository" | "File" | "Module" | "Dependency" | "Package" | "Threat";
export type RKGEdgeType = "CONTAINS" | "IMPORTS" | "DEPENDS_ON" | "AFFECTS" | "REMEDIATES" | "HAS_CVSS" | "IN_KEV" | "FIXED_BY" | "REPLACED_BY";

export interface RKGNode {
  id: string;
  label: string;
  type: RKGNodeType;
  properties: Record<string, unknown>;
}

export interface RKGEdge {
  source: string;
  target: string;
  relationship: RKGEdgeType;
  weight?: number;
}

export interface RepositoryKnowledgeGraph {
  nodes: RKGNode[];
  edges: RKGEdge[];
}

export interface GraphContextPath {
  dependency: string;
  package: string;
  threatId: string | null;
  affectedModules: string[];
  impactedFiles: string[];
  patchVersions: string[];
  kevStatus: boolean;
  explanation: string;
}

export interface RepoChunk {
  filePath: string;
  chunkType: ChunkType;
  language: string | null;
  content: string;
  startLine: number | null;
  endLine: number | null;
  embedding?: number[];
}

export interface RetrievedChunk extends RepoChunk {
  id: string;
  similarityScore: number;
  denseScore?: number;
  bm25Score?: number;
  rrfScore?: number;
}

export interface SimilarRepo {
  owner: string;
  repo: string;
  fullName: string;
  description: string | null;
  language: string | null;
  stars: number;
  forks: number;
  openIssues: number;
  pushAgeDays: number;
  maintenanceActivity: MaintenanceActivity;
  healthScore: number;
  topics: string[];
  similarityScore: number;
  githubUrl: string;
}

export interface SimilarRepoEvidence {
  repoFullName: string;
  repoUrl: string;
  similarityScore: number;
  healthScore: number;
  maintenanceActivity: MaintenanceActivity;
  sharedDependencies: string[];
  knownSafeVersion: string | null;
  upgradePattern: string | null;
}

export interface RepositoryContext {
  profile: RepositoryProfile | null;
  graphSummary: string;
  graphPaths: GraphContextPath[];
  retrievedChunks: RetrievedChunk[];
  similarRepoEvidence: SimilarRepoEvidence[];
  similarRepos: SimilarRepo[];
}

export interface ChainStep {
  stepNumber: number;
  observation: string;
  deduction: string;
}

export interface EvidenceReference {
  filePath: string;
  startLine?: number | null;
  endLine?: number | null;
  codeSnippet?: string;
  relevance: string;
}

export interface CandidateRankingFeatures {
  compatibilityScore: number;
  securityGainScore: number;
  dependencyImpactScore: number;
  validationScore: number;
  patternAlignmentScore: number;
  evidenceStrengthScore: number;
  utilityScore: number;
}

export interface RemediationCandidate {
  action: RemediationAction;
  explanation: string;
  reasoning: string;
  chainOfReasoning?: ChainStep[];
  evidence?: EvidenceReference[];
  confidence: number;
  compatibilityRisk: CompatibilityRisk;
  proposedVersion: string | null;
  alternativePackage: string | null;
  dependencyImpact: string[];
  validated: boolean;
  rejected: boolean;
  rejectionReason: string | null;
  validationNotes: string | null;
  rankingFeatures?: CandidateRankingFeatures;
  rank?: number;
}

export interface RemediationReport {
  scanId: string;
  cveId: string | null;
  packageName: string;
  ecosystem: Ecosystem;
  candidates: RemediationCandidate[];
  reasoningTrace: string | null;
  contextChunks: RetrievedChunk[];
  graphContext?: GraphContextPath[];
  validationPassed: boolean;
}

export interface RSISWeights {
  security: number;
  retrieval: number;
  validation: number;
  maintainability: number;
  compatibility: number;
}

export interface RSISSignals {
  criticalVulns: number;
  highVulns: number;
  mediumVulns: number;
  lowVulns: number;
  totalVulns: number;
  totalDeps: number;
  highConfidenceCandidates: number;
  totalCandidates: number;
  meanRetrievalSimilarity: number;
  hybridMRR: number;
  validatedCandidates: number;
  totalValidated: number;
  recentDeps: number;
  kevCount: number;
  semverCompatRate: number;
}

export interface RSISLiteratureRationale {
  formula: string;
  citations: string[];
  ablationNotes: string;
}

export interface RSISScore {
  totalScore: number;
  securityScore: number;
  retrievalScore: number;
  validationScore: number;
  maintainabilityScore: number;
  compatibilityScore: number;
  weights: RSISWeights;
  signals: RSISSignals;
  rationale: RSISLiteratureRationale;
  grade: "A" | "B" | "C" | "D" | "F";
}

export interface RetrievalMetrics {
  precisionAtK: number;
  recallAtK: number;
  mrr: number;
  ndcg: number;
  k: number;
}

export interface RecommendationMetrics {
  top1Accuracy: number;
  top3Accuracy: number;
}

export interface ValidationMetrics {
  buildSuccessRate: number;
  vulnReductionRate: number;
}

export interface EvalMetrics {
  retrieval: RetrievalMetrics;
  recommendation: RecommendationMetrics;
  validation: ValidationMetrics;
}

export interface IntelligenceSummary {
  repositoryUnderstanding: string;
  stackDescription: string;
  graphStats: {
    totalNodes: number;
    totalEdges: number;
    fileCount: number;
    moduleCount: number;
    packageCount: number;
    threatCount: number;
    kevCount: number;
  };
  similarRepoInfluence: string;
  threatIntelSummary: string;
  projectedRsisAfterRemediation: number;
}

export interface AnalysisResult {
  scanId: string;
  scan: ScanReport;
  metadata: RepositoryMetadata | null;
  repositoryProfile: RepositoryProfile | null;
  knowledgeGraph: RepositoryKnowledgeGraph;
  chunksIndexed: number;
  similarRepos: SimilarRepo[];
  remediations: RemediationReport[];
  rsis: RSISScore;
  intelligenceSummary: IntelligenceSummary | null;
  aiEnabled: boolean;
}

// UI-specific types
export interface ScanListItem {
  id: string;
  repoUrl: string;
  repoOwner: string;
  repoName: string;
  type: "quick" | "full";
  totalDependencies: number;
  totalVulnerabilities: number;
  rsis?: RSISScore;
  status: "pending" | "scanning" | "complete" | "failed";
  createdAt: string;
  completedAt?: string;
  errorMessage?: string;
}
