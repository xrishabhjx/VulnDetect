"use client";

import type { RepositoryProfile } from "@/lib/types";

interface RepositoryProfileCardProps {
  profile: RepositoryProfile | null;
}

export function RepositoryProfileCard({ profile }: RepositoryProfileCardProps) {
  if (!profile) {
    return (
      <div className="card p-6 border-border text-xs font-mono text-secondary">
        Repository profile details not available.
      </div>
    );
  }

  const stackItems = [
    { label: "Language", val: profile.language },
    { label: "Framework", val: profile.framework },
    { label: "Database", val: profile.database },
    { label: "ORM", val: profile.orm },
    { label: "Deployment", val: profile.deployment },
    { label: "CI/CD", val: profile.ciCdPlatform },
    { label: "Testing", val: profile.testingFramework },
    { label: "Architecture", val: profile.architecture },
  ].filter((item) => item.val);

  return (
    <div className="card p-6 sm:p-8 space-y-6 border-border">
      <div className="border-b border-border pb-4 flex items-center justify-between">
        <div>
          <span className="text-xs font-mono uppercase tracking-wider text-secondary">
            Global Repo Context
          </span>
          <h2 className="text-2xl font-display font-semibold text-primary">
            Repository Architecture Profile
          </h2>
        </div>
        {profile.repositoryType && profile.repositoryType !== "unknown" && (
          <span className="badge badge-accent uppercase font-mono">
            {profile.repositoryType}
          </span>
        )}
      </div>

      {/* GitHub Repo Signals */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg bg-surface/50 border border-border space-y-1">
          <span className="text-[11px] font-mono text-secondary uppercase">Stars</span>
          <div className="text-xl font-mono font-semibold text-primary">{profile.stars || 0}</div>
        </div>
        <div className="p-4 rounded-lg bg-surface/50 border border-border space-y-1">
          <span className="text-[11px] font-mono text-secondary uppercase">Forks</span>
          <div className="text-xl font-mono font-semibold text-primary">{profile.forks || 0}</div>
        </div>
        <div className="p-4 rounded-lg bg-surface/50 border border-border space-y-1">
          <span className="text-[11px] font-mono text-secondary uppercase">Open Issues</span>
          <div className="text-xl font-mono font-semibold text-primary">{profile.openIssues || 0}</div>
        </div>
        <div className="p-4 rounded-lg bg-surface/50 border border-border space-y-1">
          <span className="text-[11px] font-mono text-secondary uppercase">Total Files</span>
          <div className="text-xl font-mono font-semibold text-primary">{profile.totalFiles || 0}</div>
        </div>
      </div>

      {/* Stack & Signals */}
      <div className="space-y-3">
        <span className="text-xs font-mono uppercase tracking-wider text-secondary">
          Detected Stack Signals
        </span>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {stackItems.map((item) => (
            <div
              key={item.label}
              className="p-3 rounded-lg bg-surface border border-border/80 space-y-1"
            >
              <span className="text-[10px] font-mono text-secondary uppercase tracking-wider block">
                {item.label}
              </span>
              <span className="text-xs font-mono font-medium text-primary block truncate">
                {item.val}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Purpose / Summary */}
      {profile.purpose && (
        <div className="p-4 rounded-lg bg-background border border-border text-xs font-body text-secondary leading-relaxed">
          <span className="font-mono text-primary uppercase font-semibold">Purpose: </span>
          {profile.purpose}
        </div>
      )}
    </div>
  );
}
