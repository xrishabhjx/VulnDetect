"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, grade, safeParse, severityCounts, SEVERITY_ORDER } from "@/lib/api";
import type {
  AnalysisRow,
  RemediationCandidate,
  RemediationReport,
  Severity,
} from "@/lib/types";
import { Card, ScoreRing, SeverityBadge, Stat } from "@/components/ui";

const SEVERITY_BAR: Record<Severity, string> = {
  CRITICAL: "bg-crit",
  HIGH: "bg-high",
  MEDIUM: "bg-med",
  LOW: "bg-low",
  UNKNOWN: "bg-slate-600",
};

export default function ScanPage({ params }: { params: { id: string } }) {
  const [data, setData] = useState<AnalysisRow | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getAnalysis(params.id)
      .then(setData)
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load"));
  }, [params.id]);

  if (error)
    return (
      <div className="space-y-4">
        <BackLink />
        <Card>
          <p className="text-crit">{error}</p>
        </Card>
      </div>
    );

  if (!data)
    return (
      <div className="space-y-4">
        <BackLink />
        <p className="text-slate-500">Loading analysis…</p>
      </div>
    );

  const counts = severityCounts(data.dependencies);
  const vulnDeps = data.dependencies.filter((d) => d.vulnerabilities.length > 0);
  const rsis = data.rsisScore;

  return (
    <div className="space-y-8">
      <BackLink />

      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white">
            {data.repoOwner}/{data.repoName}
          </h1>
          <a
            href={`https://github.com/${data.repoOwner}/${data.repoName}`}
            target="_blank"
            rel="noreferrer"
            className="text-sm text-slate-500 hover:text-slate-300"
          >
            {data.repoUrl}
          </a>
        </div>
        <div className="text-right text-xs text-slate-500">
          <div>Status: {data.status}</div>
          <div>{new Date(data.createdAt).toLocaleString()}</div>
        </div>
      </header>

      {/* RSIS + top-line stats */}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="flex items-center gap-5">
          {rsis ? (
            <>
              <ScoreRing score={rsis.totalScore} gradeLetter={grade(rsis.totalScore)} />
              <div>
                <div className="text-xs uppercase tracking-wide text-slate-500">
                  RSIS Score
                </div>
                <p className="mt-1 max-w-[16rem] text-sm text-slate-400">
                  Repository Security Intelligence — lower means more risk.
                </p>
              </div>
            </>
          ) : (
            <p className="text-sm text-slate-500">No RSIS score computed for this scan.</p>
          )}
        </Card>

        <Card className="col-span-2 grid grid-cols-2 gap-4 sm:grid-cols-4">
          <Stat label="Dependencies" value={data.totalDeps} />
          <Stat label="Vulnerabilities" value={data.totalVulns} />
          <Stat label="Remediations" value={data.remediations.length} />
          <Stat label="Similar repos" value={data.similarRepos.length} />
        </Card>
      </div>

      {/* Severity breakdown */}
      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
          Severity breakdown
        </h2>
        <SeverityBar counts={counts} total={data.totalVulns} />
        <div className="mt-4 flex flex-wrap gap-4">
          {SEVERITY_ORDER.map((sev) => (
            <div key={sev} className="flex items-center gap-2">
              <SeverityBadge severity={sev} />
              <span className="text-sm text-slate-300">{counts[sev]}</span>
            </div>
          ))}
        </div>
      </Card>

      {/* RSIS component breakdown */}
      {rsis && <RsisBreakdown rsis={rsis} />}

      {/* Repository metadata */}
      {data.metadata && (
        <Card>
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">
            Repository profile
          </h2>
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <Stat label="Language" value={data.metadata.language ?? "—"} />
            <Stat label="Framework" value={data.metadata.framework ?? "—"} />
            <Stat label="Stars" value={data.metadata.stars} />
            <Stat label="Open issues" value={data.metadata.openIssues} />
          </div>
          {data.metadata.description && (
            <p className="mt-4 text-sm text-slate-400">{data.metadata.description}</p>
          )}
        </Card>
      )}

      {/* Remediations */}
      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">
          Ranked remediations ({data.remediations.length})
        </h2>
        {data.remediations.length === 0 ? (
          <Card>
            <p className="text-sm text-slate-500">No remediations generated.</p>
          </Card>
        ) : (
          <div className="space-y-3">
            {data.remediations.map((r) => (
              <RemediationRow key={r.id} report={r} />
            ))}
          </div>
        )}
      </section>

      {/* Vulnerable dependencies */}
      <section className="space-y-3">
        <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">
          Vulnerable dependencies ({vulnDeps.length})
        </h2>
        {vulnDeps.length === 0 ? (
          <Card>
            <p className="text-sm text-slate-500">No vulnerable dependencies found. 🎉</p>
          </Card>
        ) : (
          <div className="space-y-3">
            {vulnDeps.map((d) => (
              <DependencyRow key={d.id} dep={d} />
            ))}
          </div>
        )}
      </section>

      {/* Similar repos */}
      {data.similarRepos.length > 0 && (
        <section className="space-y-3">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">
            Similar repositories
          </h2>
          <div className="grid gap-3 sm:grid-cols-2">
            {data.similarRepos.map((s) => (
              <a key={s.id} href={s.githubUrl} target="_blank" rel="noreferrer">
                <Card className="transition hover:border-slate-600">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-white">{s.fullName}</span>
                    <span className="text-xs text-slate-500">
                      {Math.round(s.similarityScore * 100)}% match
                    </span>
                  </div>
                  {s.description && (
                    <p className="mt-1 line-clamp-2 text-sm text-slate-400">{s.description}</p>
                  )}
                  <div className="mt-2 text-xs text-slate-500">
                    ★ {s.stars} · {s.language ?? "—"}
                  </div>
                </Card>
              </a>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function BackLink() {
  return (
    <Link href="/" className="text-sm text-slate-500 hover:text-slate-300">
      ← Back to scans
    </Link>
  );
}

function SeverityBar({ counts, total }: { counts: Record<Severity, number>; total: number }) {
  if (total === 0)
    return <div className="h-2 w-full rounded-full bg-slate-800" />;
  return (
    <div className="flex h-2 w-full overflow-hidden rounded-full bg-slate-800">
      {SEVERITY_ORDER.map((sev) =>
        counts[sev] > 0 ? (
          <div
            key={sev}
            className={SEVERITY_BAR[sev]}
            style={{ width: `${(counts[sev] / total) * 100}%` }}
            title={`${sev}: ${counts[sev]}`}
          />
        ) : null
      )}
    </div>
  );
}

function RsisBreakdown({ rsis }: { rsis: NonNullable<AnalysisRow["rsisScore"]> }) {
  const dims = [
    { label: "Security",         value: rsis.severityScore },
    { label: "Retrieval",        value: rsis.retrievalScore },
    { label: "Validation",       value: rsis.validationScore },
    { label: "Maintainability",  value: rsis.maintainabilityScore },
    { label: "Remediation",      value: rsis.remediationScore },
    { label: "Compatibility",    value: rsis.compatibilityScore },
  ];
  return (
    <Card>
      <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-500">
        RSIS dimensions
      </h2>
      <div className="space-y-3">
        {dims.map((d) => (
          <div key={d.label}>
            <div className="mb-1 flex justify-between text-sm">
              <span className="text-slate-300">{d.label}</span>
              <span className="text-slate-400">{Math.round(d.value)}</span>
            </div>
            <div className="h-2 w-full rounded-full bg-slate-800">
              <div
                className="h-2 rounded-full bg-emerald-500"
                style={{ width: `${Math.max(0, Math.min(100, d.value))}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function RemediationRow({ report }: { report: RemediationReport }) {
  const candidates = safeParse<RemediationCandidate[]>(report.candidates, []);
  const top = candidates[0];
  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="font-mono text-white">{report.packageName}</span>
          {report.cveId && <span className="text-xs text-slate-500">{report.cveId}</span>}
        </div>
        <span
          className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
            report.validationPassed ? "bg-ok/15 text-ok" : "bg-slate-500/15 text-slate-400"
          }`}
        >
          {report.validationPassed ? "validated" : "unvalidated"}
        </span>
      </div>
      {top ? (
        <div className="mt-3 space-y-1">
          <div className="flex items-center gap-2 text-sm">
            <ActionTag action={top.action} />
            {top.proposedVersion && (
              <span className="font-mono text-emerald-400">→ {top.proposedVersion}</span>
            )}
            {top.alternativePackage && (
              <span className="font-mono text-emerald-400">→ {top.alternativePackage}</span>
            )}
            <span className="text-xs text-slate-500">
              {Math.round(top.confidence * 100)}% confidence · {top.compatibilityRisk} risk
            </span>
          </div>
          <p className="text-sm text-slate-400">{top.explanation}</p>
          {candidates.length > 1 && (
            <p className="text-xs text-slate-600">
              +{candidates.length - 1} alternative candidate
              {candidates.length > 2 ? "s" : ""}
            </p>
          )}
        </div>
      ) : (
        <p className="mt-2 text-sm text-slate-500">No candidate proposed.</p>
      )}
    </Card>
  );
}

function ActionTag({ action }: { action: RemediationCandidate["action"] }) {
  const style: Record<string, string> = {
    upgrade: "bg-ok/15 text-ok",
    replace: "bg-low/15 text-low",
    mitigate: "bg-med/15 text-med",
    accept: "bg-slate-500/15 text-slate-400",
  };
  return (
    <span
      className={`rounded px-1.5 py-0.5 text-[11px] font-semibold uppercase ${style[action] ?? style.accept}`}
    >
      {action}
    </span>
  );
}

function DependencyRow({
  dep,
}: {
  dep: AnalysisRow["dependencies"][number];
}) {
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-white">
          {dep.name}
          <span className="text-slate-500">@{dep.version}</span>
        </span>
        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[11px] text-slate-400">
          {dep.ecosystem}
        </span>
        {dep.isDev && <span className="text-[11px] text-slate-600">dev</span>}
      </div>
      <ul className="mt-3 space-y-2">
        {dep.vulnerabilities.map((v) => (
          <li key={v.id} className="rounded-lg bg-slate-950/50 p-3">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={v.severity} />
              {v.cveId && <span className="font-mono text-xs text-slate-300">{v.cveId}</span>}
              {v.cvssScore != null && (
                <span className="text-xs text-slate-500">CVSS {v.cvssScore}</span>
              )}
              {v.kev && (
                <span className="rounded bg-crit/15 px-1.5 py-0.5 text-[11px] font-semibold text-crit">
                  KEV
                </span>
              )}
              <span className="text-xs text-slate-600">{v.source}</span>
            </div>
            <p className="mt-1 text-sm text-slate-400">{v.summary}</p>
          </li>
        ))}
      </ul>
    </Card>
  );
}
