"use client";

import { PieChart, Pie, Cell, ResponsiveContainer } from "recharts";
import type { RSISScore } from "@/lib/types";
import { GradeBadge } from "@/components/common/Badges";

interface RSISScoreCardProps {
  rsis: RSISScore;
}

export function RSISScoreCard({ rsis }: RSISScoreCardProps) {
  const dimensions = [
    {
      name: "Security",
      value: rsis.securityScore,
      weight: rsis.weights.security,
      description: "Severity density & KEV status",
    },
    {
      name: "Retrieval",
      value: rsis.retrievalScore,
      weight: rsis.weights.retrieval,
      description: "BM25+Dense similarity relevance",
    },
    {
      name: "Validation",
      value: rsis.validationScore,
      weight: rsis.weights.validation,
      description: "Registry & build validation rate",
    },
    {
      name: "Maintainability",
      value: rsis.maintainabilityScore,
      weight: rsis.weights.maintainability,
      description: "Dependency freshness & ecosystem activity",
    },
    {
      name: "Compatibility",
      value: rsis.compatibilityScore,
      weight: rsis.weights.compatibility,
      description: "SemVer major/minor safety delta",
    },
  ];

  const getScoreColor = (score: number) => {
    if (score >= 85) return "#4CC38A";
    if (score >= 70) return "#5B8DEF";
    if (score >= 55) return "#F5D90A";
    if (score >= 40) return "#F5A524";
    return "#E5484D";
  };

  const pieData = [
    { name: "Score", value: rsis.totalScore },
    { name: "Gap", value: Math.max(0, 100 - rsis.totalScore) },
  ];

  return (
    <div className="card p-6 sm:p-8 space-y-6 border-border">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-4">
        <div>
          <span className="text-xs font-mono uppercase tracking-wider text-secondary">
            Primary Metric
          </span>
          <h2 className="text-2xl font-display font-semibold text-primary">
            Repository Security Intelligence Score (RSIS)
          </h2>
        </div>
        <GradeBadge grade={rsis.grade} size="lg" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        {/* Radial Gauge (4 cols) */}
        <div className="lg:col-span-5 flex flex-col items-center justify-center p-6 rounded-lg bg-surface/50 border border-border">
          <div className="relative w-48 h-48">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  innerRadius={68}
                  outerRadius={84}
                  startAngle={180}
                  endAngle={0}
                  dataKey="value"
                >
                  <Cell fill={getScoreColor(rsis.totalScore)} />
                  <Cell fill="#262B31" />
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex flex-col items-center justify-center pt-6">
              <span className="text-4xl font-mono font-bold text-primary">
                {Math.round(rsis.totalScore)}
              </span>
              <span className="text-xs font-mono text-secondary">/ 100</span>
            </div>
          </div>

          <div className="text-center space-y-1 mt-2">
            <span className="text-sm font-display font-semibold text-primary">
              Letter Grade: {rsis.grade}
            </span>
            <p className="text-xs text-secondary font-body">
              Weighted composite security posture
            </p>
          </div>
        </div>

        {/* Sub-dimension bars (7 cols) */}
        <div className="lg:col-span-7 space-y-4">
          <span className="text-xs font-mono uppercase tracking-wider text-secondary">
            5 Sub-Dimension Breakdown
          </span>

          <div className="space-y-3">
            {dimensions.map((dim) => (
              <div key={dim.name} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-body font-medium text-primary">
                    {dim.name}
                  </span>
                  <div className="font-mono space-x-2">
                    <span className="text-primary font-semibold">
                      {Math.round(dim.value)}
                    </span>
                    <span className="text-secondary">
                      ({Math.round(dim.weight * 100)}%)
                    </span>
                  </div>
                </div>

                <div className="w-full h-2 bg-surface rounded-full overflow-hidden border border-border/50">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${dim.value}%`,
                      backgroundColor: getScoreColor(dim.value),
                    }}
                  />
                </div>

                <p className="text-[11px] text-secondary font-body">
                  {dim.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Rationale & Formula note */}
      {rsis.rationale && (
        <div className="p-4 rounded-lg bg-surface/40 border border-border/60 text-xs font-mono text-secondary space-y-1">
          <div><span className="text-primary">FORMULA:</span> {rsis.rationale.formula}</div>
          {rsis.rationale.citations && rsis.rationale.citations.length > 0 && (
            <div><span className="text-primary">CITATIONS:</span> {rsis.rationale.citations.join(" • ")}</div>
          )}
        </div>
      )}
    </div>
  );
}
