import type { Severity } from "./types";

// Severity colors matching design tokens
export const SEVERITY_COLORS: Record<Severity, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "bg-critical/15", text: "text-critical", border: "border-critical/30" },
  HIGH: { bg: "bg-high/15", text: "text-high", border: "border-high/30" },
  MEDIUM: { bg: "bg-medium/15", text: "text-medium", border: "border-medium/30" },
  LOW: { bg: "bg-low/15", text: "text-low", border: "border-low/30" },
  UNKNOWN: { bg: "bg-secondary/15", text: "text-secondary", border: "border-secondary/30" },
};

export const SEVERITY_LABELS: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  UNKNOWN: "Unknown",
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  UNKNOWN: 4,
};

// Grade colors
export const GRADE_COLORS: Record<"A" | "B" | "C" | "D" | "F", { bg: string; text: string }> = {
  A: { bg: "bg-low/15", text: "text-low" },
  B: { bg: "bg-accent/15", text: "text-accent" },
  C: { bg: "bg-medium/15", text: "text-medium" },
  D: { bg: "bg-high/15", text: "text-high" },
  F: { bg: "bg-critical/15", text: "text-critical" },
};

// Remediation action labels
export const ACTION_ICONS: Record<string, string> = {
  upgrade: "Upgrade",
  replace: "Replace",
  mitigate: "Mitigate",
  accept: "Accept",
};

// Risk level colors
export const RISK_COLORS: Record<string, string> = {
  low: "text-low",
  medium: "text-medium",
  high: "text-critical",
};

// Maintenance activity colors
export const MAINTENANCE_COLORS: Record<string, string> = {
  active: "text-low",
  moderate: "text-medium",
  stale: "text-critical",
};

// Format utilities
export function formatSeverity(severity: Severity): string {
  return SEVERITY_LABELS[severity] || severity;
}

export function formatCVSSScore(score: number | null): string {
  if (score === null || score === undefined) return "N/A";
  return score.toFixed(1);
}

export function formatDate(dateString: string | null): string {
  if (!dateString) return "Unknown";
  try {
    return new Date(dateString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return "Invalid date";
  }
}

export function formatConfidence(confidence: number): string {
  const percent = Math.round(confidence * 100);
  return `${percent}%`;
}

export function getGradeColor(score: number): "A" | "B" | "C" | "D" | "F" {
  if (score >= 85) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  if (score >= 40) return "D";
  return "F";
}

export function formatScore(score: number): string {
  return score.toFixed(0);
}

export function getScoreColor(score: number): string {
  const grade = getGradeColor(score);
  return GRADE_COLORS[grade].text;
}
