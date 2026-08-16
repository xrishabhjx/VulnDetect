"use client";

import { useEffect, useState } from "react";
import { apiClient } from "@/lib/api-client";
import { LoadingSpinner, ErrorMessage } from "@/components/common/Loading";
import { StatusBadge } from "@/components/common/Badges";
import Link from "next/link";
import type { ScanListItem } from "@/lib/types";

export default function ScansPage() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.listScans();
      const transformed = data.map((scan: any) => ({
        id: scan.id,
        repoUrl: scan.repoUrl,
        repoOwner: scan.repoOwner,
        repoName: scan.repoName,
        type: "full" as const,
        totalDependencies: scan.totalDeps || 0,
        totalVulnerabilities: scan.totalVulns || 0,
        status: (scan.status || "complete") as "pending" | "scanning" | "complete" | "failed",
        createdAt: scan.createdAt,
        completedAt: scan.completedAt,
        errorMessage: scan.errorMessage,
      }));
      setScans(transformed);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load scan history";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "numeric",
        minute: "2-digit",
      });
    } catch {
      return dateString;
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-6 py-12 space-y-8 bg-background min-h-screen text-primary">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <span className="text-xs font-mono uppercase tracking-wider text-secondary">
            Repository Audits
          </span>
          <h1 className="text-3xl font-display font-bold text-primary">
            Scan History
          </h1>
        </div>

        <Link href="/" className="btn btn-primary">
          + New Scan
        </Link>
      </div>

      {error && <ErrorMessage message={error} onDismiss={() => setError(null)} />}

      {loading ? (
        <div className="py-16 flex justify-center">
          <LoadingSpinner size="lg" text="Fetching scan history..." />
        </div>
      ) : scans.length === 0 ? (
        <div className="card p-12 text-center space-y-4 border-border">
          <p className="text-secondary font-mono text-sm">
            No vulnerability scans recorded yet.
          </p>
          <Link href="/" className="btn btn-primary inline-block">
            Start Your First Scan
          </Link>
        </div>
      ) : (
        <div className="card overflow-hidden border-border p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm font-body">
              <thead>
                <tr className="border-b border-border bg-surface/60 font-mono text-xs text-secondary uppercase tracking-wider">
                  <th className="px-6 py-4">Repository</th>
                  <th className="px-6 py-4">Date</th>
                  <th className="px-6 py-4">Dependencies</th>
                  <th className="px-6 py-4">Vulnerabilities</th>
                  <th className="px-6 py-4">Status</th>
                  <th className="px-6 py-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-surface/40 transition-colors">
                    <td className="px-6 py-4">
                      <div className="space-y-0.5">
                        <p className="font-mono font-medium text-primary text-sm">
                          {scan.repoOwner}/{scan.repoName}
                        </p>
                        <p className="font-mono text-xs text-secondary truncate max-w-[240px]">
                          {scan.repoUrl}
                        </p>
                      </div>
                    </td>
                    <td className="px-6 py-4 font-mono text-xs text-secondary">
                      {formatDate(scan.createdAt)}
                    </td>
                    <td className="px-6 py-4 font-mono text-sm text-primary">
                      {scan.totalDependencies}
                    </td>
                    <td className="px-6 py-4 font-mono text-sm">
                      <span
                        className={
                          scan.totalVulnerabilities > 0 ? "text-critical font-semibold" : "text-low"
                        }
                      >
                        {scan.totalVulnerabilities}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <StatusBadge status={scan.status} size="sm" />
                    </td>
                    <td className="px-6 py-4 text-right">
                      <div className="flex items-center justify-end gap-3 font-mono text-xs">
                        <Link
                          href={`/scans/${scan.id}`}
                          className="text-secondary hover:text-primary transition-colors"
                        >
                          Quick Scan
                        </Link>
                        <Link
                          href={`/scans/${scan.id}/analysis`}
                          className="text-accent hover:text-accent-hover font-semibold transition-colors"
                        >
                          Full Analysis →
                        </Link>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
