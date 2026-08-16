"use client";

import { useState } from "react";
import { parseGitHubUrl } from "@/lib/utils";

interface RepositoryFormProps {
  onSubmit: (url: string, scanType: "quick" | "full") => void;
  loading?: boolean;
}

export function RepositoryForm({ onSubmit, loading }: RepositoryFormProps) {
  const [url, setUrl] = useState("");
  const [scanType, setScanType] = useState<"quick" | "full">("full");
  const [error, setError] = useState("");

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (!url.trim()) {
      setError("Please enter a repository URL");
      return;
    }

    const parsed = parseGitHubUrl(url);
    if (!parsed) {
      setError("Please enter a valid GitHub repository URL (e.g. https://github.com/owner/repo)");
      return;
    }

    onSubmit(url, scanType);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* URL Input */}
      <div className="space-y-2">
        <label htmlFor="repo-url" className="block text-xs font-mono text-secondary uppercase tracking-wider">
          GitHub Repository URL
        </label>
        <input
          id="repo-url"
          type="url"
          placeholder="https://github.com/owner/repository"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            setError("");
          }}
          disabled={loading}
          className="w-full px-4 py-3 bg-surface border border-border rounded-lg text-primary placeholder:text-secondary/60 focus:outline-none focus:border-accent disabled:opacity-50 transition font-mono text-sm"
        />
        {error && (
          <p className="text-xs font-mono text-critical mt-1">{error}</p>
        )}
      </div>

      {/* Analysis Type Selection */}
      <div className="space-y-2">
        <label className="block text-xs font-mono text-secondary uppercase tracking-wider">
          Analysis Depth
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <button
            type="button"
            onClick={() => setScanType("quick")}
            disabled={loading}
            className={`p-4 rounded-lg border text-left transition font-body space-y-1 ${
              scanType === "quick"
                ? "bg-surface border-accent text-primary"
                : "bg-surface/50 border-border text-secondary hover:border-border/80"
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-primary">Quick Scan</span>
              <span className="text-xs font-mono text-accent">Phase 1</span>
            </div>
            <p className="text-xs text-secondary leading-relaxed">
              Dependency parsing & cross-reference across OSV/NVD/Advisory DBs.
            </p>
          </button>

          <button
            type="button"
            onClick={() => setScanType("full")}
            disabled={loading}
            className={`p-4 rounded-lg border text-left transition font-body space-y-1 ${
              scanType === "full"
                ? "bg-surface border-accent text-primary"
                : "bg-surface/50 border-border text-secondary hover:border-border/80"
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="font-semibold text-sm text-primary">Full AI Analysis</span>
              <span className="text-xs font-mono text-accent">Phase 2</span>
            </div>
            <p className="text-xs text-secondary leading-relaxed">
              Knowledge Graph, hybrid retrieval, LLM reasoning, RSIS score & remediations.
            </p>
          </button>
        </div>
      </div>

      {/* Action Buttons (side by side with gap-3) */}
      <div className="flex flex-row items-center gap-3 pt-2">
        <button
          type="submit"
          disabled={loading}
          className="btn btn-primary"
        >
          {loading ? "Initializing..." : `Start ${scanType === "quick" ? "Quick Scan" : "Full Analysis"}`}
        </button>
      </div>
    </form>
  );
}
