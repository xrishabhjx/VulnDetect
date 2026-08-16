"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { ScanReport } from "@/lib/types";

interface ScanSummaryProps {
  scan: ScanReport;
}

export function ScanSummary({ scan }: ScanSummaryProps) {
  const severityCounts = scan.severityCounts ?? {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  };

  const severityData = [
    { name: "Critical", value: severityCounts.CRITICAL ?? 0, color: "#E5484D" },
    { name: "High", value: severityCounts.HIGH ?? 0, color: "#F5A524" },
    { name: "Medium", value: severityCounts.MEDIUM ?? 0, color: "#F5D90A" },
    { name: "Low", value: severityCounts.LOW ?? 0, color: "#4CC38A" },
  ].filter((d) => d.value > 0);

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
      <div className="card p-6 space-y-1">
        <span className="text-xs font-mono text-secondary uppercase tracking-wider">
          Dependencies Analyzed
        </span>
        <div className="text-3xl font-mono font-semibold text-primary">
          {scan.totalDependencies}
        </div>
        <p className="text-xs text-secondary font-body">Across detected manifests</p>
      </div>

      <div className="card p-6 space-y-1">
        <span className="text-xs font-mono text-secondary uppercase tracking-wider">
          Total Vulnerabilities
        </span>
        <div className={`text-3xl font-mono font-semibold ${scan.totalVulnerabilities > 0 ? "text-critical" : "text-low"}`}>
          {scan.totalVulnerabilities}
        </div>
        <p className="text-xs text-secondary font-body">Matched against vulnerability DBs</p>
      </div>

      <div className="card p-6 flex flex-col justify-between">
        <span className="text-xs font-mono text-secondary uppercase tracking-wider mb-2">
          Severity Distribution
        </span>
        {severityData.length > 0 ? (
          <div className="h-16 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={18}
                  outerRadius={30}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#14171B",
                    borderColor: "#262B31",
                    borderRadius: "8px",
                    color: "#E8EAED",
                    fontSize: "12px",
                    fontFamily: "var(--font-jetbrains-mono)",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="text-xs font-mono text-low py-2">
            ✓ Zero vulnerabilities detected
          </div>
        )}
      </div>
    </div>
  );
}
