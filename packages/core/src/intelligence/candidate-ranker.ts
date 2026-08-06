import semver from "semver";
import type {
  RemediationCandidate,
  CandidateRankingFeatures,
  SimilarRepo,
  UnifiedVulnerability,
} from "../types.js";

export interface CandidateRankerWeights {
  compatibility: number;      // Default: 0.20
  securityGain: number;       // Default: 0.30
  dependencyImpact: number;   // Default: 0.12
  validation: number;         // Default: 0.18
  patternAlignment: number;   // Default: 0.10
  evidenceStrength: number;   // Default: 0.10
}

const DEFAULT_RANKER_WEIGHTS: CandidateRankerWeights = {
  compatibility: 0.20,
  securityGain: 0.30,
  dependencyImpact: 0.12,
  validation: 0.18,
  patternAlignment: 0.10,
  evidenceStrength: 0.10,
};

// ─── Evidence Source Weights (env-configurable) ──────────────────────────────

export interface EvidenceSourceWeights {
  osv: number;            // EVIDENCE_WEIGHT_OSV (default 0.20)
  nvd: number;            // EVIDENCE_WEIGHT_NVD (default 0.20)
  githubAdvisory: number; // EVIDENCE_WEIGHT_GITHUB (default 0.25)
  cisaKev: number;        // EVIDENCE_WEIGHT_KEV (default 0.20)
  similarRepo: number;    // EVIDENCE_WEIGHT_SIMILAR_REPO (default 0.15)
}

/**
 * Load evidence source weights from environment variables.
 *
 * These are default configuration values, not absolute truths.
 * The framework supports different weighting schemes tuned via:
 *   - ablation experiments (holding one source out and measuring score drift)
 *   - expert elicitation (security researcher preference surveys)
 *   - empirical calibration against a held-out benchmark set
 *
 * Override any weight via .env:
 *   EVIDENCE_WEIGHT_GITHUB=0.35  (if your org places higher trust in GHSA)
 *   EVIDENCE_WEIGHT_OSV=0.15     (adjust accordingly)
 */
function loadEvidenceWeights(): EvidenceSourceWeights {
  const parse = (key: string, def: number) => {
    const val = parseFloat(process.env[key] ?? "");
    return isNaN(val) ? def : val;
  };

  const w = {
    osv:            parse("EVIDENCE_WEIGHT_OSV",          0.20),
    nvd:            parse("EVIDENCE_WEIGHT_NVD",          0.20),
    githubAdvisory: parse("EVIDENCE_WEIGHT_GITHUB",       0.25),
    cisaKev:        parse("EVIDENCE_WEIGHT_KEV",          0.20),
    similarRepo:    parse("EVIDENCE_WEIGHT_SIMILAR_REPO", 0.15),
  };

  // Normalise so weights always sum to 1.0 regardless of config
  const total = Object.values(w).reduce((s, v) => s + v, 0);
  if (Math.abs(total - 1.0) > 0.01) {
    for (const k of Object.keys(w) as Array<keyof EvidenceSourceWeights>) {
      w[k] /= total;
    }
  }

  return w;
}

// ─── Candidate Ranker ──────────────────────────────────────────────────────────

/**
 * Patch Candidate Ranker — Feature-based ML Decision Pipeline.
 *
 * Converts raw LLM-generated candidates into ranked output via a 6-feature
 * multi-criteria utility scoring function:
 *
 *   1. Compatibility      (SemVer patch/minor/major delta)
 *   2. Security Gain      (CVSS score reduction + KEV resolution bonus)
 *   3. Dependency Impact  (inverse of transitive dependency chain risk)
 *   4. Validation         (registry existence + OSV re-scan outcome)
 *   5. Pattern Alignment  (healthy similar-repo adoption signals)
 *   6. Evidence Strength  (independent corroborating source count — measurable confidence)
 */
export class CandidateRanker {
  private weights: CandidateRankerWeights;
  private evidenceWeights: EvidenceSourceWeights;

  constructor(weights: Partial<CandidateRankerWeights> = {}) {
    this.weights = { ...DEFAULT_RANKER_WEIGHTS, ...weights };
    this.evidenceWeights = loadEvidenceWeights();

    // Normalize candidate ranker weights if they don't sum to 1.0
    const total = Object.values(this.weights).reduce((s, v) => s + v, 0);
    if (Math.abs(total - 1.0) > 0.01) {
      for (const k of Object.keys(this.weights) as Array<keyof CandidateRankerWeights>) {
        this.weights[k] /= total;
      }
    }
  }

  /**
   * Rank candidate patches for a vulnerability.
   * Returns candidates sorted by utility score (rank 1 = best).
   */
  rankCandidates(
    candidates: RemediationCandidate[],
    vulnerability: UnifiedVulnerability,
    currentVersion: string,
    similarRepos: SimilarRepo[] = []
  ): RemediationCandidate[] {
    if (candidates.length === 0) return [];

    const scored = candidates.map((candidate) => {
      const features = this.extractFeatures(candidate, vulnerability, currentVersion, similarRepos);
      return {
        ...candidate,
        rankingFeatures: features,
        confidence: parseFloat(features.utilityScore.toFixed(3)),
      };
    });

    scored.sort((a, b) => b.rankingFeatures!.utilityScore - a.rankingFeatures!.utilityScore);

    return scored.map((c, index) => ({ ...c, rank: index + 1 }));
  }

  // ─── Feature Extraction ────────────────────────────────────────────────────

  private extractFeatures(
    candidate: RemediationCandidate,
    vulnerability: UnifiedVulnerability,
    currentVersion: string,
    similarRepos: SimilarRepo[]
  ): CandidateRankingFeatures {

    // 1. Compatibility Score — SemVer diff determines breakage risk
    let compatibilityScore = 0.5;
    if (candidate.action === "accept" || candidate.action === "mitigate") {
      compatibilityScore = 0.9; // No version change → no breakage
    } else if (
      candidate.proposedVersion &&
      semver.valid(currentVersion) &&
      semver.valid(candidate.proposedVersion)
    ) {
      const diff = semver.diff(currentVersion, candidate.proposedVersion);
      if (diff === "patch") compatibilityScore = 1.0;        // SemVer safe
      else if (diff === "minor") compatibilityScore = 0.85;  // Backward compatible
      else if (diff === "major") compatibilityScore = 0.40;  // Potential breaking changes
    }

    // 2. Security Gain Score — CVSS reduction + active exploitation bonus
    let securityGainScore = 0.5;
    if (candidate.action === "upgrade" && candidate.proposedVersion) {
      const cvss = vulnerability.cvssScore ?? 7.5;
      const baseGain = cvss / 10.0;
      const kevBonus = vulnerability.kev ? 0.2 : 0; // KEV resolution is high value
      securityGainScore = Math.min(1.0, baseGain + kevBonus);
    } else if (candidate.action === "mitigate") {
      securityGainScore = 0.6; // Partial risk reduction
    } else if (candidate.action === "accept") {
      securityGainScore = 0.1; // Accepted risk — no gain
    }

    // 3. Dependency Impact Score — transitive dependency chain risk penalty
    const transitiveCount = candidate.dependencyImpact?.length ?? 0;
    // Inverse decay: 0 transitive = 1.0, each extra dep reduces score
    const dependencyImpactScore = 1.0 / (1.0 + 0.2 * transitiveCount);

    // 4. Validation Score — registry + OSV re-scan outcome
    let validationScore = 0.5; // Default: unknown state
    if (candidate.rejected) {
      validationScore = 0.0; // Hard fail
    } else if (candidate.validated) {
      // Penalise if new CVEs were found in proposed version
      validationScore = candidate.validationNotes?.includes("⚠️") ? 0.3 : 1.0;
    }

    // 5. Pattern Alignment — healthy similar repo signal
    const healthyRepos = similarRepos.filter((r) => r.healthScore >= 70);
    const patternAlignmentScore = healthyRepos.length >= 3 ? 1.0
      : healthyRepos.length >= 1 ? 0.85
      : 0.6; // No healthy comparators found

    // 6. Evidence Strength Score — multi-source corroboration
    const evidenceStrengthScore = this.computeEvidenceStrength(candidate, vulnerability, similarRepos);

    // Weighted composite utility
    const utilityScore =
      compatibilityScore      * this.weights.compatibility +
      securityGainScore       * this.weights.securityGain +
      dependencyImpactScore   * this.weights.dependencyImpact +
      validationScore         * this.weights.validation +
      patternAlignmentScore   * this.weights.patternAlignment +
      evidenceStrengthScore   * this.weights.evidenceStrength;

    return {
      compatibilityScore:    parseFloat(compatibilityScore.toFixed(3)),
      securityGainScore:     parseFloat(securityGainScore.toFixed(3)),
      dependencyImpactScore: parseFloat(dependencyImpactScore.toFixed(3)),
      validationScore:       parseFloat(validationScore.toFixed(3)),
      patternAlignmentScore: parseFloat(patternAlignmentScore.toFixed(3)),
      evidenceStrengthScore: parseFloat(evidenceStrengthScore.toFixed(3)),
      utilityScore:          parseFloat(utilityScore.toFixed(3)),
    };
  }

  /**
   * Compute Evidence Strength Score from independent corroborating sources.
   *
   * Each source is binary (present/absent) and contributes its fixed weight.
   * The score is the sum of weights of all confirmed sources.
   *
   * Example:
   *   Candidate A: OSV + NVD + GitHub Advisory + CISA KEV + Similar Repo → 1.00
   *   Candidate B: OSV + NVD only                                         → 0.40
   *   Candidate C: Pure-LLM, no external sources                          → 0.00
   */
  private computeEvidenceStrength(
    candidate: RemediationCandidate,
    vulnerability: UnifiedVulnerability,
    similarRepos: SimilarRepo[]
  ): number {
    let score = 0;

    // OSV: present if vulnerability was sourced from OSV or has an osvId
    const hasOSV = vulnerability.source === "OSV" ||
      candidate.evidence?.some((e) => e.relevance.toLowerCase().includes("osv"));
    if (hasOSV) score += this.evidenceWeights.osv;

    // NVD: present if vulnerability has NVD source or CVSS vector (NVD-specific)
    const hasNVD = vulnerability.source === "NVD" || vulnerability.cvssVector !== null;
    if (hasNVD) score += this.evidenceWeights.nvd;

    // GitHub Advisory: present if source is GITHUB or githubAdvisoryId set
    const hasGHSA = vulnerability.source === "GITHUB" ||
      vulnerability.githubAdvisoryId !== undefined;
    if (hasGHSA) score += this.evidenceWeights.githubAdvisory;

    // CISA KEV: present if this CVE is actively exploited
    if (vulnerability.kev) score += this.evidenceWeights.cisaKev;

    // Similar Repo: present if at least one healthy similar repo was discovered
    const hasSimilarRepo = similarRepos.some((r) => r.healthScore >= 60);
    if (hasSimilarRepo) score += this.evidenceWeights.similarRepo;

    return Math.min(1.0, score);
  }
}
