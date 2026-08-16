import { clsx, type ClassValue } from "clsx";
import type { Severity } from "./types";
import { SEVERITY_COLORS } from "./constants";

export function cn(...inputs: ClassValue[]) {
  return clsx(inputs);
}

export function getSeverityClasses(severity: Severity) {
  return SEVERITY_COLORS[severity];
}

export function truncate(str: string, length: number): string {
  return str.length > length ? str.slice(0, length) + "..." : str;
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + " " + sizes[i];
}

export function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  try {
    // Handle various GitHub URL formats
    const patterns = [
      /github\.com\/([^\/]+)\/([^\/]+?)(?:\.git)?$/,
      /github\.com\/([^\/]+)\/([^\/]+)\/?$/,
    ];

    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) {
        return {
          owner: match[1],
          repo: match[2],
        };
      }
    }
  } catch {
    // Ignore errors
  }
  return null;
}

export function formatRepositoryName(owner: string, repo: string): string {
  return `${owner}/${repo}`;
}

export function getInitials(text: string): string {
  return text
    .split(" ")
    .map((word) => word[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);
}

export function calculateHealthScore(repo: {
  stars?: number;
  forks?: number;
  openIssues?: number;
  pushAgeDays?: number;
}): number {
  let score = 50; // Base score

  // Stars contribution (0-20)
  const starsContribution = Math.min((repo.stars || 0) / 500, 20);
  score += starsContribution;

  // Push age contribution (0-15)
  const pushAgeDays = repo.pushAgeDays || 999;
  if (pushAgeDays < 7) score += 15;
  else if (pushAgeDays < 30) score += 10;
  else if (pushAgeDays < 90) score += 5;

  // Forks contribution (0-10)
  const forksContribution = Math.min((repo.forks || 0) / 100, 10);
  score += forksContribution;

  // Issues contribution (0-5)
  const openIssuesRatio = (repo.openIssues || 0) / (repo.stars || 1);
  if (openIssuesRatio < 0.1) score += 5;
  else if (openIssuesRatio < 0.3) score += 3;

  return Math.min(100, Math.round(score));
}
