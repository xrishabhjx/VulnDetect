"use client";

import React from "react";
import type { ChainStep, EvidenceReference } from "@/lib/types";

export interface ReasoningStepItem {
  observed: string;
  evidence?: string | EvidenceReference[];
  deduced: string;
  stepNumber?: number;
}

interface ReasoningChainProps {
  steps?: ReasoningStepItem[] | ChainStep[];
  evidenceReferences?: EvidenceReference[];
  isPreview?: boolean;
  className?: string;
}

export function ReasoningChain({
  steps = [],
  evidenceReferences,
  isPreview = false,
  className = "",
}: ReasoningChainProps) {
  if (!steps || steps.length === 0) {
    return (
      <div className="py-4 text-secondary text-sm font-body">
        No reasoning steps recorded for this analysis.
      </div>
    );
  }

  return (
    <div className={`relative pl-6 space-y-8 ${className}`}>
      {/* Continuous vertical connecting line */}
      <div className="absolute left-[7px] top-3 bottom-3 w-[1px] bg-border" />

      {steps.map((step, idx) => {
        const stepNum = "stepNumber" in step && step.stepNumber ? step.stepNumber : idx + 1;
        const observed = "observed" in step ? step.observed : (step as ChainStep).observation;
        const deduced = "deduced" in step ? step.deduced : (step as ChainStep).deduction;

        // Extract evidence text or references
        let evidenceText: string | null = null;
        let evidenceRefs: EvidenceReference[] = [];

        if ("evidence" in step && step.evidence) {
          if (typeof step.evidence === "string") {
            evidenceText = step.evidence;
          } else if (Array.isArray(step.evidence)) {
            evidenceRefs = step.evidence;
          }
        }

        // Fallback to top-level evidenceReferences if provided for this index
        if (!evidenceText && evidenceRefs.length === 0 && evidenceReferences && evidenceReferences[idx]) {
          evidenceRefs = [evidenceReferences[idx]];
        }

        return (
          <div
            key={idx}
            className="relative group reasoning-step"
            style={{
              animationDelay: isPreview ? `${idx * 120}ms` : "0ms",
            }}
          >
            {/* Small filled circle node */}
            <div className="absolute -left-[24px] top-[6px] w-[15px] h-[15px] rounded-full bg-background border-2 border-accent flex items-center justify-center">
              <div className="w-[5px] h-[5px] rounded-full bg-accent" />
            </div>

            <div className="space-y-2">
              {/* Step Header / Observed */}
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[11px] font-mono text-secondary uppercase tracking-wider">
                    Step {stepNum} — Observed
                  </span>
                </div>
                <p className="text-body-sm text-secondary leading-relaxed font-body">
                  {observed}
                </p>
              </div>

              {/* Evidence Reference (Monospace & Accent color for data emphasis) */}
              {(evidenceText || evidenceRefs.length > 0) && (
                <div className="py-1 px-2.5 rounded bg-surface border border-border/60 inline-block max-w-full">
                  <div className="flex items-center gap-2 text-xs font-mono text-accent truncate">
                    <span className="text-secondary select-none">EVIDENCE:</span>
                    {evidenceText && <span className="truncate">{evidenceText}</span>}
                    {evidenceRefs.map((ref, rIdx) => (
                      <span key={rIdx} className="truncate">
                        {ref.filePath}
                        {ref.startLine && `:${ref.startLine}`}
                        {ref.relevance && ` (${ref.relevance})`}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Deduced */}
              <div>
                <div className="text-[11px] font-mono text-secondary uppercase tracking-wider mb-1">
                  Deduced
                </div>
                <p className="text-body text-primary font-medium leading-relaxed font-body">
                  {deduced}
                </p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
