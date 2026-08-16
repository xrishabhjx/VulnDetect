"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { useScan } from "@/hooks/useScan";
import { LoadingSpinner, ErrorMessage } from "@/components/common/Loading";
import { ScanSummary } from "@/components/scan-results/ScanSummary";
import { SeverityBadge } from "@/components/common/Badges";
import Link from "next/link";

export default function QuickScanPage() {
  const params = useParams();
  const scanId = params.scanId as string;
  const [sortBy, setSortBy] = useState<"severity" | "name">("severity");
  const [filterSeverity, setFilterSeverity] = useState<string | null>(null);

  const { scan, status, error, getScan } = useScan();

  useEffect(() => {
    getScan(scanId);
  }, [scanId, getScan]);

  if (status === "loading") {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <LoadingSpinner size="lg" text="Loading scan report..." />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="max-w-6xl mx-auto px-6 py-12">
        <ErrorMessage message={error || "Scan not found"} />
      </div>
    );
  }

  // Filter and sort results
  const baseResults = scan.results ?? [];
  let filteredResults = baseResults;
  if (filterSeverity) {
    filteredResults = filteredResults.filter((r) =>
      r.vulnerabilities.some((v) => v.severity === filterSeverity)
    );
  }

  const sortedResults = [...filteredResults].sort((a, b) => {
    if (sortBy === "name") {
      return a.dependency.name.localeCompare(b.dependency.name);
    }
    const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    const maxSevA = Math.min(...a.vulnerabilities.map((v) => order.indexOf(v.severity)));
    const maxSevB = Math.min(...b.vulnerabilities.map((v) => order.indexOf(v.severity)));
    return maxSevA - maxSevB;
  });

  return (
    <div className="max-w-6xl mx-auto px-6 py-12 space-y-8 bg-background min-h-screen">
      {/* Top Breadcrumb & Header */}
      <div className="space-y-2">
        <Link
          href="/scans"
          className="text-xs font-mono text-secondary hover:text-accent transition-colors"
        >
          ← Back to Scan History
        </Link>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-3xl font-display font-bold text-primary">
              Dependency Scan Results
            </h1>
            <p className="text-sm font-mono text-secondary mt-1">
              Repository: <span className="text-primary">{scan.repoOwner}/{scan.repoName}</span>
            </p>
          </div>
          <Link
            href={`/scans/new?url=${encodeURIComponent(scan.repoUrl)}&type=full`}
            className="btn btn-primary"
          >
            Run Full AI Analysis →
          </Link>
        </div>
      </div>

      {/* Summary Cards */}
      <ScanSummary scan={scan} />

      {/* Controls: Filter & Sort */}
      <div className="card p-4 flex flex-wrap items-center justify-between gap-4 border-border">
        <div className="flex flex-wrap items-center gap-4 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-secondary">Filter Severity:</span>
            <select
              value={filterSeverity || ""}
              onChange={(e) => setFilterSeverity(e.target.value || null)}
              className="bg-surface border border-border rounded px-3 py-1.5 text-primary focus:outline-none focus:border-accent"
            >
              <option value="">ALL</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-secondary">Sort by:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as "severity" | "name")}
              className="bg-surface border border-border rounded px-3 py-1.5 text-primary focus:outline-none focus:border-accent"
            >
              <option value="severity">Highest Severity</option>
              <option value="name">Package Name</option>
            </select>
          </div>
        </div>

        <span className="text-xs font-mono text-secondary">
          Showing {sortedResults.length} of {filteredResults.length} dependencies
        </span>
      </div>

      {/* Dependency List Table */}
      <div className="card overflow-hidden border-border p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm font-body">
            <thead>
              <tr className="border-b border-border bg-surface/60 font-mono text-xs text-secondary uppercase tracking-wider">
                <th className="px-6 py-4">Package</th>
                <th className="px-6 py-4">Version</th>
                <th className="px-6 py-4">Ecosystem</th>
                <th className="px-6 py-4">Vulnerabilities</th>
                <th className="px-6 py-4">Type</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {sortedResults.map((result) => (
                <tr
                  key={`${result.dependency.ecosystem}:${result.dependency.name}`}
                  className="hover:bg-surface/40 transition-colors"
                >
                  <td className="px-6 py-4 font-mono font-medium text-primary">
                    {result.dependency.name}
                  </td>
                  <td className="px-6 py-4 font-mono text-secondary text-xs">
                    {result.dependency.version}
                  </td>
                  <td className="px-6 py-4">
                    <span className="badge badge-accent uppercase">
                      {result.dependency.ecosystem}
                    </span>
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex flex-wrap gap-1.5">
                      {result.vulnerabilities.length > 0 ? (
                        result.vulnerabilities.map((vuln, vIdx) => (
                          <SeverityBadge key={vIdx} severity={vuln.severity} size="sm" />
                        ))
                      ) : (
                        <span className="text-xs font-mono text-low">Clear</span>
                      )}
                    </div>
                  </td>
                  <td className="px-6 py-4 font-mono text-xs text-secondary">
                    {result.dependency.isDev ? "Dev" : "Production"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {sortedResults.length === 0 && (
          <div className="p-12 text-center text-secondary font-mono text-xs">
            No dependencies match the selected filters.
          </div>
        )}
      </div>
    </div>
  );
}
