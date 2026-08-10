// UI-facing subset of the shapes returned by the VulnShield API (packages/api).
// The GET endpoints return persisted Prisma rows; JSON-string columns
// (candidates, weights, signals, references, fixedVersions) are parsed client-side.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export interface Vulnerability {
  id: string;
  cveId: string | null;
  severity: Severity;
  cvssScore: number | null;
  summary: string;
  source: string;
  kev: boolean;
  fixedVersions: string | null; // JSON string
  references: string | null; // JSON string
}

export interface Dependency {
  id: string;
  ecosystem: string;
  name: string;
  version: string;
  manifestPath: string;
  isDev: boolean;
  vulnerabilities: Vulnerability[];
}

export interface RepositoryMetadata {
  language: string | null;
  framework: string | null;
  description: string | null;
  stars: number;
  forks: number;
  openIssues: number;
  totalFiles: number;
}

export interface SimilarRepository {
  id: string;
  fullName: string;
  description: string | null;
  language: string | null;
  stars: number;
  similarityScore: number;
  githubUrl: string;
}

// One candidate inside RemediationReport.candidates (JSON-decoded)
export interface RemediationCandidate {
  action: "upgrade" | "replace" | "mitigate" | "accept";
  explanation: string;
  proposedVersion: string | null;
  alternativePackage: string | null;
  compatibilityRisk: "low" | "medium" | "high";
  confidence: number;
  validated: boolean;
  rank?: number;
}

export interface RemediationReport {
  id: string;
  cveId: string | null;
  packageName: string;
  ecosystem: string;
  candidates: string; // JSON string of RemediationCandidate[]
  validationPassed: boolean;
}

export interface RSISScoreRow {
  totalScore: number;
  severityScore: number;
  remediationScore: number;
  retrievalScore: number;
  validationScore: number;
  maintainabilityScore: number;
  compatibilityScore: number;
  weights: string; // JSON string
  signals: string; // JSON string
}

// Shape of GET /api/analyze/:id
export interface AnalysisRow {
  id: string;
  repoUrl: string;
  repoOwner: string;
  repoName: string;
  status: string;
  totalDeps: number;
  totalVulns: number;
  createdAt: string;
  completedAt: string | null;
  dependencies: Dependency[];
  metadata: RepositoryMetadata | null;
  similarRepos: SimilarRepository[];
  remediations: RemediationReport[];
  rsisScore: RSISScoreRow | null;
}

// Shape of a row in GET /api/scans
export interface ScanListItem {
  id: string;
  repoUrl: string;
  repoOwner: string;
  repoName: string;
  status: string;
  totalDeps: number;
  totalVulns: number;
  createdAt: string;
}

// Shape returned by POST /api/analyze (only the field we use to navigate)
export interface AnalyzeResponse {
  scanId: string;
}
