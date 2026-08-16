"use client";

import { useState } from "react";
import type { RemediationReport, RemediationCandidate } from "@/lib/types";
import { ConfidenceScore, RiskBadge, StatusBadge } from "@/components/common/Badges";
import { ReasoningChain } from "@/components/evidence/ReasoningChain";

interface RemediationListProps {
  remediations: RemediationReport[];
}

function RemediationCardComponent({
  report,
  candidate,
  index,
}: {
  report: RemediationReport;
  candidate: RemediationCandidate;
  index: number;
}) {
  const [expanded, setExpanded] = useState(index === 0);

  const actionBorder = {
    upgrade: "border-l-accent",
    replace: "border-l-high",
    mitigate: "border-l-medium",
    accept: "border-l-low",
  }[candidate.action] || "border-l-accent";

  return (
    <div className={`card overflow-hidden border-l-4 ${actionBorder} p-0 transition-colors`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-6 hover:bg-surface/60 transition text-left space-y-3"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 font-mono text-sm">
            <span className="badge badge-accent uppercase">{candidate.action}</span>
            <span className="font-semibold text-primary">{report.packageName}</span>
            {candidate.proposedVersion && (
              <span className="text-accent text-xs font-semibold">
                → {candidate.proposedVersion}
              </span>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <ConfidenceScore confidence={candidate.confidence} size="sm" />
            <RiskBadge risk={candidate.compatibilityRisk} size="sm" />
            {candidate.validated && <StatusBadge status="validated" size="sm" />}
            <span className="text-secondary select-none">{expanded ? "▲" : "▼"}</span>
          </div>
        </div>

        <p className="text-sm font-body text-secondary leading-relaxed">
          {candidate.explanation}
        </p>
      </button>

      {expanded && (
        <div className="border-t border-border p-6 space-y-6 bg-background/50">
          {/* Reasoning narrative */}
          {candidate.reasoning && (
            <div className="space-y-1">
              <span className="text-xs font-mono uppercase tracking-wider text-secondary">
                Technical Context Rationale
              </span>
              <p className="text-sm font-body text-primary leading-relaxed">
                {candidate.reasoning}
              </p>
            </div>
          )}

          {/* Signature Reasoning Chain Component */}
          {candidate.chainOfReasoning && candidate.chainOfReasoning.length > 0 && (
            <div className="space-y-3 pt-2 border-t border-border/60">
              <span className="text-xs font-mono uppercase tracking-wider text-accent">
                Explicit Chain of Reasoning
              </span>
              <div className="p-4 rounded-lg bg-surface border border-border">
                <ReasoningChain
                  steps={candidate.chainOfReasoning}
                  evidenceReferences={candidate.evidence}
                />
              </div>
            </div>
          )}

          {/* Transitive impact */}
          {candidate.dependencyImpact && candidate.dependencyImpact.length > 0 && (
            <div className="space-y-2 pt-2 border-t border-border/60">
              <span className="text-xs font-mono uppercase tracking-wider text-secondary">
                Transitive Dependency Impact
              </span>
              <div className="flex flex-wrap gap-2">
                {candidate.dependencyImpact.map((dep) => (
                  <span
                    key={dep}
                    className="text-xs font-mono px-2.5 py-1 rounded bg-surface border border-border text-secondary"
                  >
                    {dep}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Validation notes */}
          {candidate.validationNotes && (
            <div className="p-3 rounded-lg bg-low/10 border border-low/30 text-xs font-mono text-low">
              ✓ Validation: {candidate.validationNotes}
            </div>
          )}

          {/* Rejection notes */}
          {candidate.rejectionReason && (
            <div className="p-3 rounded-lg bg-critical/10 border border-critical/30 text-xs font-mono text-critical">
              ✕ Rejected: {candidate.rejectionReason}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function RemediationList({ remediations }: RemediationListProps) {
  const allCandidates = remediations.flatMap((report) =>
    report.candidates.map((candidate, idx) => ({ report, candidate, index: idx }))
  );

  const sortedCandidates = allCandidates.sort((a, b) => {
    const aRank = a.candidate.rank ?? Infinity;
    const bRank = b.candidate.rank ?? Infinity;
    if (aRank !== bRank) return aRank - bRank;
    return b.candidate.confidence - a.candidate.confidence;
  });

  if (sortedCandidates.length === 0) {
    return (
      <div className="card p-8 text-center font-mono text-xs text-secondary border-border">
        No remediation recommendations generated.
      </div>
    );
  }

  return (
    <div className="card p-6 sm:p-8 space-y-6 border-border">
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div>
          <span className="text-xs font-mono uppercase tracking-wider text-accent">
            LLM Reasoning Output
          </span>
          <h2 className="text-2xl font-display font-semibold text-primary">
            Ranked Remediation Recommendations ({sortedCandidates.length})
          </h2>
        </div>
      </div>

      <div className="space-y-4">
        {sortedCandidates.map((item, idx) => (
          <RemediationCardComponent
            key={`${item.report.cveId}-${idx}`}
            report={item.report}
            candidate={item.candidate}
            index={idx}
          />
        ))}
      </div>
    </div>
  );
}
