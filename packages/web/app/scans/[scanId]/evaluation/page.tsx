"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { apiClient } from "@/lib/api-client";
import { LoadingSpinner, ErrorMessage } from "@/components/common/Loading";
import type { EvalMetrics } from "@/lib/types";
import Link from "next/link";

export default function EvaluationPage() {
  const params = useParams();
  const scanId = params.scanId as string;

  const [metrics, setMetrics] = useState<EvalMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [evaluating, setEvaluating] = useState(false);

  const runEvaluation = useCallback(async () => {
    setEvaluating(true);
    setError(null);
    try {
      const res = await apiClient.runEvaluation(scanId);
      setMetrics(res.metrics);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to run evaluation";
      setError(msg);
    } finally {
      setEvaluating(false);
    }
  }, [scanId]);

  const fetchEvaluation = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.getEvaluationResults(scanId);
      setMetrics(data.metrics);
    } catch {
      // If not yet evaluated, auto-trigger evaluation
      runEvaluation();
    } finally {
      setLoading(false);
    }
  }, [runEvaluation, scanId]);

  useEffect(() => {
    fetchEvaluation();
  }, [fetchEvaluation]);

  if (loading || evaluating) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <LoadingSpinner
          size="lg"
          text="Computing Precision@K, Recall@K, MRR & nDCG benchmark metrics..."
        />
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto px-6 py-12 space-y-10 bg-background min-h-screen text-primary">
      {/* Top Header */}
      <div className="space-y-2 border-b border-border pb-6">
        <Link
          href={`/scans/${scanId}/analysis`}
          className="text-xs font-mono text-secondary hover:text-accent transition-colors"
        >
          ← Back to Analysis Dashboard
        </Link>
        <h1 className="text-3xl font-display font-bold text-primary">
          Machine Learning Benchmark Evaluation
        </h1>
        <p className="text-sm font-mono text-secondary">
          Quantitative retrieval & ranking performance metrics for Scan ID:{" "}
          <span className="text-primary font-semibold">{scanId}</span>
        </p>
      </div>

      {error && <ErrorMessage message={error} />}

      {metrics && (
        <div className="space-y-8">
          {/* Section 1: Retrieval Metrics (Hybrid BM25 + Dense RRF) */}
          <div className="card p-6 sm:p-8 space-y-6 border-border">
            <div className="border-b border-border pb-4">
              <span className="text-xs font-mono uppercase tracking-wider text-accent">
                Hybrid Retrieval Performance
              </span>
              <h2 className="text-2xl font-display font-semibold text-primary">
                Retrieval Metrics (k = {metrics.retrieval.k})
              </h2>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-4 rounded-lg bg-surface/50 border border-border space-y-1">
                <span className="text-[11px] font-mono text-secondary uppercase">Precision@{metrics.retrieval.k}</span>
                <div className="text-2xl font-mono font-bold text-accent">
                  {(metrics.retrieval.precisionAtK * 100).toFixed(1)}%
                </div>
              </div>
              <div className="p-4 rounded-lg bg-surface/50 border border-border space-y-1">
                <span className="text-[11px] font-mono text-secondary uppercase">Recall@{metrics.retrieval.k}</span>
                <div className="text-2xl font-mono font-bold text-accent">
                  {(metrics.retrieval.recallAtK * 100).toFixed(1)}%
                </div>
              </div>
              <div className="p-4 rounded-lg bg-surface/50 border border-border space-y-1">
                <span className="text-[11px] font-mono text-secondary uppercase">MRR (Mean Reciprocal Rank)</span>
                <div className="text-2xl font-mono font-bold text-low">
                  {metrics.retrieval.mrr.toFixed(3)}
                </div>
              </div>
              <div className="p-4 rounded-lg bg-surface/50 border border-border space-y-1">
                <span className="text-[11px] font-mono text-secondary uppercase">nDCG Score</span>
                <div className="text-2xl font-mono font-bold text-low">
                  {metrics.retrieval.ndcg.toFixed(3)}
                </div>
              </div>
            </div>
          </div>

          {/* Section 2: Recommendation & Ranking Accuracy */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
            <div className="card p-6 space-y-4 border-border">
              <span className="text-xs font-mono uppercase tracking-wider text-secondary">
                Patch Recommendation Accuracy
              </span>
              <div className="grid grid-cols-2 gap-4 pt-2">
                <div className="p-4 rounded-lg bg-surface border border-border space-y-1">
                  <span className="text-xs font-mono text-secondary">Top-1 Accuracy</span>
                  <div className="text-2xl font-mono font-bold text-primary">
                    {(metrics.recommendation.top1Accuracy * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="p-4 rounded-lg bg-surface border border-border space-y-1">
                  <span className="text-xs font-mono text-secondary">Top-3 Accuracy</span>
                  <div className="text-2xl font-mono font-bold text-accent">
                    {(metrics.recommendation.top3Accuracy * 100).toFixed(1)}%
                  </div>
                </div>
              </div>
            </div>

            <div className="card p-6 space-y-4 border-border">
              <span className="text-xs font-mono uppercase tracking-wider text-secondary">
                Validation Pipeline Metrics
              </span>
              <div className="grid grid-cols-2 gap-4 pt-2">
                <div className="p-4 rounded-lg bg-surface border border-border space-y-1">
                  <span className="text-xs font-mono text-secondary">Build Success Rate</span>
                  <div className="text-2xl font-mono font-bold text-low">
                    {(metrics.validation.buildSuccessRate * 100).toFixed(1)}%
                  </div>
                </div>
                <div className="p-4 rounded-lg bg-surface border border-border space-y-1">
                  <span className="text-xs font-mono text-secondary">Vuln Reduction Rate</span>
                  <div className="text-2xl font-mono font-bold text-low">
                    {(metrics.validation.vulnReductionRate * 100).toFixed(1)}%
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
