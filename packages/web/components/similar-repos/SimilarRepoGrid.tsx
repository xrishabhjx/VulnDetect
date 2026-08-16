"use client";

import type { SimilarRepo } from "@/lib/types";

interface SimilarRepoGridProps {
  repos: SimilarRepo[];
}

export function SimilarRepoGrid({ repos }: SimilarRepoGridProps) {
  if (!repos || repos.length === 0) {
    return (
      <div className="card p-6 border-border text-xs font-mono text-secondary">
        No similar repositories discovered.
      </div>
    );
  }

  const sortedRepos = [...repos].sort((a, b) => b.similarityScore - a.similarityScore);

  const getMaintenanceBadge = (activity: string) => {
    switch (activity) {
      case "active":
        return <span className="badge badge-low text-[10px]">ACTIVE</span>;
      case "moderate":
        return <span className="badge badge-medium text-[10px]">MODERATE</span>;
      case "stale":
        return <span className="badge badge-high text-[10px]">STALE</span>;
      default:
        return <span className="badge badge-unknown text-[10px]">UNKNOWN</span>;
    }
  };

  return (
    <div className="card p-6 sm:p-8 space-y-6 border-border">
      <div className="border-b border-border pb-4 flex items-center justify-between">
        <div>
          <span className="text-xs font-mono uppercase tracking-wider text-secondary">
            Vector Similarity Retrieval
          </span>
          <h2 className="text-2xl font-display font-semibold text-primary">
            Similar Public Repositories ({repos.length})
          </h2>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {sortedRepos.map((repo) => (
          <a
            key={repo.fullName || `${repo.owner}/${repo.repo}`}
            href={repo.githubUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="card card-hover p-5 flex flex-col justify-between space-y-4 border-border"
          >
            <div className="space-y-2">
              <div className="flex items-start justify-between gap-2">
                <h3 className="font-mono text-sm font-semibold text-primary truncate hover:text-accent transition-colors">
                  {repo.fullName || `${repo.owner}/${repo.repo}`}
                </h3>
                {getMaintenanceBadge(repo.maintenanceActivity)}
              </div>
              <p className="text-xs font-body text-secondary line-clamp-2 leading-relaxed">
                {repo.description || "No description provided."}
              </p>
            </div>

            {/* Stats & Scores */}
            <div className="space-y-3 pt-3 border-t border-border/60">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-secondary">Similarity:</span>
                <span className="text-accent font-bold">
                  {(repo.similarityScore * 100).toFixed(0)}%
                </span>
              </div>

              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-secondary">Health Score:</span>
                <span className="text-primary font-bold">{repo.healthScore}/100</span>
              </div>

              <div className="flex items-center justify-between text-[11px] font-mono text-secondary pt-1">
                <span>⭐ {repo.stars}</span>
                <span>🍴 {repo.forks}</span>
                <span>📋 {repo.openIssues}</span>
              </div>
            </div>
          </a>
        ))}
      </div>
    </div>
  );
}
