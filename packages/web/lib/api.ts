import type {
  AnalysisRow,
  AnalyzeResponse,
  ScanListItem,
  Severity,
} from "./types";

const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3011";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
    cache: "no-store",
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.error) msg = body.error;
    } catch {
      /* non-JSON error body */
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

export const api = {
  listScans: () => req<ScanListItem[]>("/api/scans"),
  getAnalysis: (id: string) => req<AnalysisRow>(`/api/analyze/${id}`),
  analyze: (repoUrl: string) =>
    req<AnalyzeResponse>("/api/analyze", {
      method: "POST",
      body: JSON.stringify({ repoUrl }),
    }),
};

// ─── Small shared helpers used across components ────────────────────────────

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/** Count vulnerabilities by severity across a dependency list. */
export function severityCounts(
  deps: { vulnerabilities: { severity: Severity }[] }[]
): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    UNKNOWN: 0,
  };
  for (const d of deps)
    for (const v of d.vulnerabilities) counts[v.severity] = (counts[v.severity] ?? 0) + 1;
  return counts;
}

export { SEVERITY_ORDER };

/** Letter grade from an RSIS 0–100 score (mirrors core rsis-scorer thresholds). */
export function grade(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function safeParse<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}
