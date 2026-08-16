"use client";

import type { Severity } from "@/lib/types";
import { cn, getSeverityClasses } from "@/lib/utils";

interface SeverityBadgeProps {
  severity: Severity;
  size?: "sm" | "md" | "lg";
  icon?: boolean;
}

export function SeverityBadge({ severity, size = "md" }: SeverityBadgeProps) {
  const { bg, text, border } = getSeverityClasses(severity);

  const sizeClasses = {
    sm: "px-2 py-0.5 text-[11px]",
    md: "px-2.5 py-1 text-xs",
    lg: "px-3 py-1.5 text-sm",
  };

  const labels: Record<Severity, string> = {
    CRITICAL: "CRITICAL",
    HIGH: "HIGH",
    MEDIUM: "MEDIUM",
    LOW: "LOW",
    UNKNOWN: "UNKNOWN",
  };

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full font-mono font-medium border uppercase tracking-wider",
        bg,
        text,
        border,
        sizeClasses[size]
      )}
    >
      {labels[severity]}
    </span>
  );
}

interface GradeBadgeProps {
  grade: "A" | "B" | "C" | "D" | "F";
  size?: "sm" | "md" | "lg";
}

export function GradeBadge({ grade, size = "md" }: GradeBadgeProps) {
  const gradeColors: Record<"A" | "B" | "C" | "D" | "F", { bg: string; text: string; border: string }> = {
    A: { bg: "bg-low/15", text: "text-low", border: "border-low/30" },
    B: { bg: "bg-accent/15", text: "text-accent", border: "border-accent/30" },
    C: { bg: "bg-medium/15", text: "text-medium", border: "border-medium/30" },
    D: { bg: "bg-high/15", text: "text-high", border: "border-high/30" },
    F: { bg: "bg-critical/15", text: "text-critical", border: "border-critical/30" },
  };

  const sizeClasses = {
    sm: "w-6 h-6 text-xs",
    md: "w-8 h-8 text-sm",
    lg: "w-10 h-10 text-base",
  };

  const { bg, text, border } = gradeColors[grade];

  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-lg font-display font-bold border",
        bg,
        text,
        border,
        sizeClasses[size]
      )}
    >
      {grade}
    </span>
  );
}

interface ConfidenceScoreProps {
  confidence: number;
  size?: "sm" | "md" | "lg";
}

export function ConfidenceScore({ confidence, size = "md" }: ConfidenceScoreProps) {
  const percent = Math.round(confidence * 100);
  let color = "text-critical";
  if (percent >= 80) color = "text-low";
  else if (percent >= 60) color = "text-medium";
  else if (percent >= 40) color = "text-high";

  const sizeClasses = {
    sm: "text-xs font-mono",
    md: "text-sm font-mono",
    lg: "text-base font-mono",
  };

  return (
    <span className={cn("font-medium", color, sizeClasses[size])}>
      {percent}% confidence
    </span>
  );
}

interface RiskBadgeProps {
  risk: "low" | "medium" | "high";
  size?: "sm" | "md";
}

export function RiskBadge({ risk, size = "md" }: RiskBadgeProps) {
  const colors = {
    low: { bg: "bg-low/15", text: "text-low", border: "border-low/30" },
    medium: { bg: "bg-medium/15", text: "text-medium", border: "border-medium/30" },
    high: { bg: "bg-critical/15", text: "text-critical", border: "border-critical/30" },
  };

  const sizeClasses = {
    sm: "px-2 py-0.5 text-[11px]",
    md: "px-2.5 py-1 text-xs",
  };

  const { bg, text, border } = colors[risk];

  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full font-mono font-medium border uppercase tracking-wider",
        bg,
        text,
        border,
        sizeClasses[size]
      )}
    >
      {risk} risk
    </span>
  );
}

interface StatusBadgeProps {
  status: "pending" | "scanning" | "complete" | "failed" | "validated" | "rejected";
  size?: "sm" | "md";
}

export function StatusBadge({ status, size = "md" }: StatusBadgeProps) {
  const statusConfig = {
    pending: { color: "text-secondary", bg: "bg-secondary/15", border: "border-secondary/30" },
    scanning: { color: "text-accent", bg: "bg-accent/15", border: "border-accent/30" },
    complete: { color: "text-low", bg: "bg-low/15", border: "border-low/30" },
    failed: { color: "text-critical", bg: "bg-critical/15", border: "border-critical/30" },
    validated: { color: "text-low", bg: "bg-low/15", border: "border-low/30" },
    rejected: { color: "text-critical", bg: "bg-critical/15", border: "border-critical/30" },
  };

  const sizeClasses = {
    sm: "px-2 py-0.5 text-[11px]",
    md: "px-2.5 py-1 text-xs",
  };

  const config = statusConfig[status];

  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full font-mono font-medium border uppercase tracking-wider",
        config.bg,
        config.color,
        config.border,
        sizeClasses[size]
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-current" />
      {status}
    </span>
  );
}
