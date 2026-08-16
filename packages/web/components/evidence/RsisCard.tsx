"use client";

import React from "react";

interface RsisCardProps {
  repoName: string;
  vulnerability: string;
  rsiScore: number;
  grade?: "A" | "B" | "C" | "D" | "F";
  severity: "critical" | "high" | "medium" | "low";
  remediation: string;
  impact: string;
}

export function RsisCard({
  repoName = "expressjs/express",
  vulnerability = "CVE-2024-21538",
  rsiScore = 72,
  grade = "C",
  severity = "high",
  remediation = "Upgrade to express@4.19.2+",
  impact = "Mitigates ReDoS vulnerability in path-to-regexp router",
}: RsisCardProps) {
  const subDimensions = [
    { name: "Security", score: 68, weight: "30%" },
    { name: "Retrieval", score: 85, weight: "20%" },
    { name: "Validation", score: 70, weight: "20%" },
    { name: "Maintainability", score: 74, weight: "15%" },
    { name: "Compatibility", score: 88, weight: "15%" },
  ];

  return (
    <div className="card max-w-md w-full space-y-6 shadow-2xl border-border/80">
      {/* Card Header */}
      <div className="flex items-start justify-between">
        <div>
          <span className="text-[11px] font-mono uppercase tracking-wider text-secondary">
            Repository Risk Audit
          </span>
          <h3 className="text-xl font-display font-semibold text-primary mt-0.5">
            {repoName}
          </h3>
        </div>
        <div className="flex items-center gap-2">
          <span className="badge badge-high font-mono text-xs uppercase">
            {severity}
          </span>
          <span className="w-8 h-8 rounded-lg bg-surface border border-border flex items-center justify-center font-display font-bold text-medium text-sm">
            {grade}
          </span>
        </div>
      </div>

      {/* Main RSIS Gauge / Score Summary */}
      <div className="p-4 rounded-lg bg-background/60 border border-border space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono text-secondary">
            RSIS Score (0-100)
          </span>
          <span className="text-2xl font-mono font-bold text-accent">
            {rsiScore}
            <span className="text-xs font-normal text-secondary">/100</span>
          </span>
        </div>

        {/* Progress bar */}
        <div className="w-full h-1.5 bg-surface rounded-full overflow-hidden">
          <div
            className="h-full bg-accent transition-all duration-500"
            style={{ width: `${rsiScore}%` }}
          />
        </div>

        <div className="flex items-center justify-between text-xs font-mono text-secondary pt-1">
          <span>Target: 85+ (Grade A)</span>
          <span className="text-accent">{vulnerability}</span>
        </div>
      </div>

      {/* 5-Dimension Mini Bar Chart */}
      <div className="space-y-2">
        <div className="text-[11px] font-mono uppercase tracking-wider text-secondary">
          5-Dimension RSIS Breakdown
        </div>
        <div className="space-y-1.5">
          {subDimensions.map((dim) => (
            <div key={dim.name} className="flex items-center gap-3 text-xs">
              <span className="w-24 text-secondary font-body truncate">
                {dim.name}
              </span>
              <div className="flex-1 h-1 bg-surface rounded-full overflow-hidden">
                <div
                  className="h-full bg-secondary/60 rounded-full"
                  style={{ width: `${dim.score}%` }}
                />
              </div>
              <span className="w-8 font-mono text-right text-primary">
                {dim.score}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Key Finding Preview */}
      <div className="pt-2 border-t border-border space-y-2">
        <div className="flex items-center justify-between text-xs">
          <span className="font-mono text-secondary">REMEDIATION</span>
          <span className="font-mono text-accent">{remediation}</span>
        </div>
        <p className="text-xs text-secondary font-body leading-relaxed">
          {impact}
        </p>
      </div>
    </div>
  );
}
