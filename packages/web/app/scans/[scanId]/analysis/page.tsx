"use client";

import { useEffect } from "react";
import { useParams } from "next/navigation";
import { useAnalysis } from "@/hooks/useScan";
import { LoadingSpinner, ErrorMessage } from "@/components/common/Loading";
import { RSISScoreCard } from "@/components/analysis-dashboard/RSISScoreCard";
import { RepositoryProfileCard } from "@/components/analysis-dashboard/RepositoryProfileCard";
import { KnowledgeGraphViewer } from "@/components/analysis-dashboard/KnowledgeGraphViewer";
import { RemediationList } from "@/components/analysis-dashboard/RemediationList";
import { ProjectedRSISComparison } from "@/components/analysis-dashboard/ProjectedRSISComparison";
import { SimilarRepoGrid } from "@/components/similar-repos/SimilarRepoGrid";
import Link from "next/link";

export default function AnalysisDashboardPage() {
  const params = useParams();
  const scanId = params.scanId as string;

  const { analysis, stage, error, getAnalysis } = useAnalysis();

  useEffect(() => {
    getAnalysis(scanId);
  }, [scanId, getAnalysis]);

  if (!analysis || stage !== "complete") {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <LoadingSpinner
          size="lg"
          text={error ? "Error loading analysis" : "Loading full intelligence analysis..."}
        />
      </div>
    );
  }

  const repoOwner = analysis.scan?.repoOwner ?? (analysis as any)?.repoOwner ?? "";
  const repoName = analysis.scan?.repoName ?? (analysis as any)?.repoName ?? "";

  if (error) {
    return (
      <div className="max-w-6xl mx-auto px-6 py-12">
        <ErrorMessage message={error} />
      </div>
    );
  }

  return (
    <div className="bg-background min-h-screen text-primary py-12">
      <div className="max-w-6xl mx-auto px-6 space-y-10">
        {/* Header Breadcrumb */}
        <div className="space-y-2 border-b border-border pb-6">
          <div className="flex items-center justify-between">
            <Link
              href="/scans"
              className="text-xs font-mono text-secondary hover:text-accent transition-colors"
            >
              ← Back to Scan History
            </Link>

            <Link
              href={`/scans/${scanId}/evaluation`}
              className="btn btn-secondary text-xs font-mono"
            >
              View ML Benchmark Metrics →
            </Link>
          </div>

          <h1 className="text-3xl sm:text-4xl font-display font-bold text-primary">
            Vulnerability Intelligence Dashboard
          </h1>
          <p className="text-sm font-mono text-secondary">
            Target Repository:{" "}
            <span className="text-primary font-semibold">
              {repoOwner}/{repoName}
            </span>
          </p>
        </div>

        {/* 1. RSIS Score Gauge & Breakdown */}
        <section>
          <RSISScoreCard rsis={analysis.rsis} />
        </section>

        {/* Hairline Divider */}
        <div className="divider" />

        {/* 2. Repository Profile Card */}
        <section>
          <RepositoryProfileCard profile={analysis.repositoryProfile} />
        </section>

        {/* Hairline Divider */}
        <div className="divider" />

        {/* 3. Knowledge Graph Visualization */}
        <section>
          <KnowledgeGraphViewer graph={analysis.knowledgeGraph} />
        </section>

        {/* Hairline Divider */}
        <div className="divider" />

        {/* 4. Ranked Remediation List (Using ReasoningChain) */}
        <section>
          <RemediationList remediations={analysis.remediations} />
        </section>

        {/* Hairline Divider */}
        <div className="divider" />

        {/* 5. Projected RSIS Score Comparison */}
        <section>
          <ProjectedRSISComparison
            currentScore={analysis.rsis.totalScore}
            projectedScore={
              analysis.intelligenceSummary?.projectedRsisAfterRemediation ||
              analysis.rsis.totalScore
            }
            intelligenceSummary={analysis.intelligenceSummary}
          />
        </section>

        {/* Hairline Divider */}
        <div className="divider" />

        {/* 6. Similar Repositories */}
        {analysis.similarRepos && analysis.similarRepos.length > 0 && (
          <section>
            <SimilarRepoGrid repos={analysis.similarRepos} />
          </section>
        )}
      </div>
    </div>
  );
}
