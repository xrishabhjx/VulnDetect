"use client";

import type { IntelligenceSummary } from "@/lib/types";

interface ProjectedRSISComparisonProps {
  currentScore: number;
  projectedScore: number;
  intelligenceSummary: IntelligenceSummary | null;
}

export function ProjectedRSISComparison({
  currentScore,
  projectedScore,
  intelligenceSummary,
}: ProjectedRSISComparisonProps) {
  const delta = projectedScore - currentScore;
  const deltaFormatted = (delta >= 0 ? "+" : "") + delta.toFixed(1);
  const scoreFormatted = (score: number) => score.toFixed(1);

  const getGrade = (score: number) => {
    if (score >= 85) return "A";
    if (score >= 70) return "B";
    if (score >= 55) return "C";
    if (score >= 40) return "D";
    return "F";
  };

  const getGradeColor = (score: number) => {
    if (score >= 85) return "text-low";
    if (score >= 70) return "text-accent";
    if (score >= 55) return "text-medium";
    if (score >= 40) return "text-high";
    return "text-critical";
  };

  return (
    <div className="card p-6 sm:p-8 space-y-6 border-border">
      <div className="border-b border-border pb-4">
        <span className="text-xs font-mono uppercase tracking-wider text-accent">
          Impact Projection
        </span>
        <h2 className="text-2xl font-display font-semibold text-primary">
          Projected RSIS Score After Remediation
        </h2>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-center">
        {/* Current Score */}
        <div className="p-6 rounded-lg bg-surface/50 border border-border text-center space-y-2">
          <span className="text-xs font-mono text-secondary uppercase">Current Score</span>
          <div className="text-4xl font-mono font-bold text-primary">
            {scoreFormatted(currentScore)}
          </div>
          <div className={`text-sm font-display font-semibold ${getGradeColor(currentScore)}`}>
            Grade {getGrade(currentScore)}
          </div>
        </div>

        {/* Delta Indicator */}
        <div className="flex flex-col items-center justify-center space-y-2 text-center">
          <span className="text-2xl font-mono text-accent">➔</span>
          <div className="text-2xl font-mono font-bold text-low">
            {deltaFormatted} pts
          </div>
          <span className="text-xs font-mono text-secondary">
            Post-Remediation Security Gain
          </span>
        </div>

        {/* Projected Score */}
        <div className="p-6 rounded-lg bg-surface border border-accent/40 text-center space-y-2">
          <span className="text-xs font-mono text-accent uppercase font-semibold">Projected Score</span>
          <div className="text-4xl font-mono font-bold text-accent">
            {scoreFormatted(projectedScore)}
          </div>
          <div className={`text-sm font-display font-semibold ${getGradeColor(projectedScore)}`}>
            Grade {getGrade(projectedScore)}
          </div>
        </div>
      </div>

      {/* Intelligence summary note */}
      {intelligenceSummary && (
        <div className="p-4 rounded-lg bg-background border border-border space-y-2 text-xs font-body text-secondary leading-relaxed">
          <div className="font-mono text-primary uppercase font-semibold">Pipeline Intelligence Summary</div>
          {intelligenceSummary.repositoryUnderstanding && (
            <p>{intelligenceSummary.repositoryUnderstanding}</p>
          )}
          {intelligenceSummary.similarRepoInfluence && (
            <p className="font-mono text-accent text-[11px]">{intelligenceSummary.similarRepoInfluence}</p>
          )}
        </div>
      )}
    </div>
  );
}
