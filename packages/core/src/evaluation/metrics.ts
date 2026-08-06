import type {
  RetrievalMetrics,
  RecommendationMetrics,
  ValidationMetrics,
  EvalMetrics,
  RemediationCandidate,
} from "../types.js";

// ─── Retrieval Metrics ────────────────────────────────────────────────────────

/**
 * Precision@K: fraction of top-K retrieved items that are relevant.
 *
 * @param retrieved - Ordered list of retrieved item IDs
 * @param relevant  - Set of ground-truth relevant item IDs
 * @param k         - Cutoff rank
 */
export function precisionAtK(
  retrieved: string[],
  relevant: Set<string>,
  k: number
): number {
  if (k === 0 || retrieved.length === 0) return 0;
  const topK = retrieved.slice(0, k);
  const hits = topK.filter((id) => relevant.has(id)).length;
  return hits / k;
}

/**
 * Recall@K: fraction of relevant items retrieved in top-K.
 *
 * @param retrieved - Ordered list of retrieved item IDs
 * @param relevant  - Set of ground-truth relevant item IDs
 * @param k         - Cutoff rank
 */
export function recallAtK(
  retrieved: string[],
  relevant: Set<string>,
  k: number
): number {
  if (relevant.size === 0) return 0;
  const topK = retrieved.slice(0, k);
  const hits = topK.filter((id) => relevant.has(id)).length;
  return hits / relevant.size;
}

/**
 * Mean Reciprocal Rank (MRR): average of 1/rank for the first relevant hit.
 *
 * @param retrievedLists - List of retrieved lists (one per query)
 * @param relevantSets   - Corresponding list of relevant item sets
 */
export function mrr(
  retrievedLists: string[][],
  relevantSets: Array<Set<string>>
): number {
  if (retrievedLists.length === 0) return 0;

  let sum = 0;
  for (let i = 0; i < retrievedLists.length; i++) {
    const retrieved = retrievedLists[i];
    const relevant = relevantSets[i];
    for (let rank = 0; rank < retrieved.length; rank++) {
      if (relevant.has(retrieved[rank])) {
        sum += 1 / (rank + 1);
        break;
      }
    }
  }

  return sum / retrievedLists.length;
}

/**
 * Normalized Discounted Cumulative Gain (nDCG@K).
 *
 * @param retrieved   - Ordered list of retrieved item IDs
 * @param relevanceMap - Map from item ID to relevance score (1.0 = fully relevant)
 * @param k           - Cutoff rank
 */
export function ndcg(
  retrieved: string[],
  relevanceMap: Map<string, number>,
  k: number
): number {
  const topK = retrieved.slice(0, k);

  // DCG: actual gain from retrieved order
  const dcg = topK.reduce((sum, id, i) => {
    const gain = relevanceMap.get(id) ?? 0;
    return sum + gain / Math.log2(i + 2); // log2(rank+1), rank is 1-indexed
  }, 0);

  // IDCG: ideal gain (sort all relevant items descending)
  const idealOrder = [...relevanceMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, k);

  const idcg = idealOrder.reduce((sum, [, gain], i) => {
    return sum + gain / Math.log2(i + 2);
  }, 0);

  return idcg === 0 ? 0 : dcg / idcg;
}

// ─── Recommendation Metrics ───────────────────────────────────────────────────

/**
 * Top-1 Accuracy: fraction of cases where the top candidate matches ground truth.
 *
 * @param candidateLists  - List of candidate arrays (one per vulnerability)
 * @param groundTruth     - Correct action strings per vulnerability
 */
export function top1Accuracy(
  candidateLists: RemediationCandidate[][],
  groundTruth: string[]
): number {
  if (candidateLists.length === 0) return 0;
  let hits = 0;

  for (let i = 0; i < candidateLists.length; i++) {
    const top = candidateLists[i][0];
    if (top && top.action === groundTruth[i]) hits++;
  }

  return hits / candidateLists.length;
}

/**
 * Top-3 Accuracy: fraction of cases where ground truth appears in top-3 candidates.
 */
export function top3Accuracy(
  candidateLists: RemediationCandidate[][],
  groundTruth: string[]
): number {
  if (candidateLists.length === 0) return 0;
  let hits = 0;

  for (let i = 0; i < candidateLists.length; i++) {
    const top3 = candidateLists[i].slice(0, 3);
    if (top3.some((c) => c.action === groundTruth[i])) hits++;
  }

  return hits / candidateLists.length;
}

// ─── Validation Metrics ───────────────────────────────────────────────────────

/**
 * Build Success Rate: fraction of validated candidates that were not rejected.
 *
 * @param candidates - All remediation candidates across all reports
 */
export function buildSuccessRate(candidates: RemediationCandidate[]): number {
  if (candidates.length === 0) return 0;
  const validated = candidates.filter((c) => c.validated);
  const passed = validated.filter((c) => !c.rejected);
  return validated.length > 0 ? passed.length / validated.length : 0;
}

/**
 * Vulnerability Reduction Rate: fraction of high/critical vulns that have a
 * validated, high-confidence fix candidate.
 *
 * @param totalHighCritical     - Count of HIGH + CRITICAL vulns in the scan
 * @param addressedByRemediation - Count with validated, non-rejected candidates
 */
export function vulnerabilityReductionRate(
  totalHighCritical: number,
  addressedByRemediation: number
): number {
  if (totalHighCritical === 0) return 1.0; // no high/critical = 100% "reduced"
  return Math.min(1.0, addressedByRemediation / totalHighCritical);
}

// ─── Aggregate Metrics Builder ────────────────────────────────────────────────

/**
 * Build a complete EvalMetrics object from raw evaluation data.
 *
 * @param retrievedLists  - List of retrieved chunk ID lists (one per vulnerability query)
 * @param relevantSets    - Ground-truth relevant chunk IDs
 * @param relevanceMaps   - Graded relevance maps for nDCG
 * @param candidateLists  - Remediation candidate lists
 * @param groundTruth     - Correct actions for each vulnerability
 * @param allCandidates   - All candidates (for build success rate)
 * @param totalHighCritical - Count of HIGH + CRITICAL vulns
 * @param addressedCount  - Count addressed by validated fixes
 * @param k               - Retrieval cutoff
 */
export function computeEvalMetrics(
  retrievedLists: string[][],
  relevantSets: Array<Set<string>>,
  relevanceMaps: Array<Map<string, number>>,
  candidateLists: RemediationCandidate[][],
  groundTruth: string[],
  allCandidates: RemediationCandidate[],
  totalHighCritical: number,
  addressedCount: number,
  k = 5
): EvalMetrics {
  // Aggregate retrieval metrics across all queries
  const pAtK = retrievedLists.length > 0
    ? retrievedLists.reduce((s, r, i) => s + precisionAtK(r, relevantSets[i], k), 0) / retrievedLists.length
    : 0;

  const rAtK = retrievedLists.length > 0
    ? retrievedLists.reduce((s, r, i) => s + recallAtK(r, relevantSets[i], k), 0) / retrievedLists.length
    : 0;

  const mrrScore = mrr(retrievedLists, relevantSets);

  const ndcgScore = retrievedLists.length > 0
    ? retrievedLists.reduce((s, r, i) => s + ndcg(r, relevanceMaps[i], k), 0) / retrievedLists.length
    : 0;

  const retrieval: RetrievalMetrics = {
    precisionAtK: parseFloat(pAtK.toFixed(4)),
    recallAtK: parseFloat(rAtK.toFixed(4)),
    mrr: parseFloat(mrrScore.toFixed(4)),
    ndcg: parseFloat(ndcgScore.toFixed(4)),
    k,
  };

  const recommendation: RecommendationMetrics = {
    top1Accuracy: parseFloat(top1Accuracy(candidateLists, groundTruth).toFixed(4)),
    top3Accuracy: parseFloat(top3Accuracy(candidateLists, groundTruth).toFixed(4)),
  };

  const validation: ValidationMetrics = {
    buildSuccessRate: parseFloat(buildSuccessRate(allCandidates).toFixed(4)),
    vulnReductionRate: parseFloat(
      vulnerabilityReductionRate(totalHighCritical, addressedCount).toFixed(4)
    ),
  };

  return { retrieval, recommendation, validation };
}
