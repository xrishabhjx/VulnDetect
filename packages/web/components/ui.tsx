import type { Severity } from "@/lib/types";

// Tailwind can't build class names from runtime strings, so severity → classes
// is an explicit lookup (not `bg-${sev}`).
const SEVERITY_STYLE: Record<Severity, string> = {
  CRITICAL: "bg-crit/15 text-crit ring-crit/30",
  HIGH: "bg-high/15 text-high ring-high/30",
  MEDIUM: "bg-med/15 text-med ring-med/30",
  LOW: "bg-low/15 text-low ring-low/30",
  UNKNOWN: "bg-slate-500/15 text-slate-400 ring-slate-500/30",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ring-1 ${SEVERITY_STYLE[severity]}`}
    >
      {severity}
    </span>
  );
}

export function Card({
  children,
  className = "",
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={`rounded-xl border border-slate-800 bg-slate-900/50 p-5 ${className}`}
    >
      {children}
    </div>
  );
}

export function Stat({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-2xl font-semibold text-white">{value}</div>
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
    </div>
  );
}

const GRADE_COLOR: Record<string, string> = {
  A: "text-ok",
  B: "text-low",
  C: "text-med",
  D: "text-high",
  F: "text-crit",
};

/** Radial 0–100 score ring for the RSIS total score. */
export function ScoreRing({ score, gradeLetter }: { score: number; gradeLetter: string }) {
  const pct = Math.max(0, Math.min(100, score));
  const color =
    pct >= 80 ? "#22c55e" : pct >= 60 ? "#eab308" : pct >= 40 ? "#f97316" : "#ef4444";
  return (
    <div
      className="relative grid h-32 w-32 place-items-center rounded-full"
      style={{
        background: `conic-gradient(${color} ${pct * 3.6}deg, #1e293b 0deg)`,
      }}
    >
      <div className="grid h-24 w-24 place-items-center rounded-full bg-slate-950">
        <span className="text-3xl font-bold text-white">{Math.round(score)}</span>
        <span className={`text-sm font-semibold ${GRADE_COLOR[gradeLetter] ?? "text-slate-400"}`}>
          Grade {gradeLetter}
        </span>
      </div>
    </div>
  );
}
