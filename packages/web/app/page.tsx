"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { api } from "@/lib/api";
import type { ScanListItem } from "@/lib/types";
import { Card } from "@/components/ui";

export default function Home() {
  const router = useRouter();
  const [repoUrl, setRepoUrl] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [scans, setScans] = useState<ScanListItem[] | null>(null);

  useEffect(() => {
    api.listScans().then(setScans).catch(() => setScans([]));
  }, []);

  async function runAnalysis(e: React.FormEvent) {
    e.preventDefault();
    const value = repoUrl.trim();
    if (!value) return;
    setRunning(true);
    setError(null);
    try {
      const { scanId } = await api.analyze(value);
      router.push(`/scan/${scanId}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Analysis failed");
      setRunning(false);
    }
  }

  return (
    <div className="space-y-10">
      <section className="space-y-4">
        <h1 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Evidence-grounded repository security
        </h1>
        <p className="max-w-2xl text-slate-400">
          Scan a public GitHub repository. VulnShield builds a knowledge graph, retrieves the
          exact vulnerable code, and returns ranked, validated remediations with a Repository
          Security Intelligence Score.
        </p>

        <Card className="max-w-2xl">
          <form onSubmit={runAnalysis} className="space-y-3">
            <label htmlFor="repo" className="block text-sm font-medium text-slate-300">
              GitHub repository
            </label>
            <div className="flex flex-col gap-3 sm:flex-row">
              <input
                id="repo"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="OWASP/NodeGoat"
                disabled={running}
                className="flex-1 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-white outline-none placeholder:text-slate-600 focus:border-slate-500 disabled:opacity-60"
              />
              <button
                type="submit"
                disabled={running || !repoUrl.trim()}
                className="rounded-lg bg-emerald-600 px-5 py-2 font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {running ? "Analyzing…" : "Run analysis"}
              </button>
            </div>
            <p className="text-xs text-slate-500">
              Accepts <code className="text-slate-400">owner/repo</code> or a full GitHub URL. Full
              analysis runs the LLM pipeline and can take a minute or two.
            </p>
            {error && (
              <p className="rounded-lg bg-crit/10 px-3 py-2 text-sm text-crit ring-1 ring-crit/30">
                {error}
              </p>
            )}
          </form>
        </Card>
      </section>

      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">
          Recent scans
        </h2>
        {scans === null ? (
          <p className="text-sm text-slate-500">Loading…</p>
        ) : scans.length === 0 ? (
          <p className="text-sm text-slate-500">No scans yet. Run one above to get started.</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {scans.map((s) => (
              <Link key={s.id} href={`/scan/${s.id}`}>
                <Card className="transition hover:border-slate-600">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-white">
                      {s.repoOwner}/{s.repoName}
                    </span>
                    <StatusPill status={s.status} />
                  </div>
                  <div className="mt-2 flex gap-4 text-xs text-slate-500">
                    <span>{s.totalDeps} deps</span>
                    <span>{s.totalVulns} vulns</span>
                    <span>{new Date(s.createdAt).toLocaleDateString()}</span>
                  </div>
                </Card>
              </Link>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const style =
    status === "complete"
      ? "bg-ok/15 text-ok"
      : status === "failed"
        ? "bg-crit/15 text-crit"
        : "bg-slate-500/15 text-slate-400";
  return (
    <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${style}`}>{status}</span>
  );
}
