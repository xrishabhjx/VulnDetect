import type { Metadata } from "next";
import { HomeClient } from "@/components/home";
import type { ScanListItem } from "@/lib/types";

export const metadata: Metadata = {
  title: "VulnShield — Run a repository security analysis",
  description:
    "Scan any public GitHub repository and get an evidence-grounded Repository Security " +
    "Intelligence Score (RSIS), ranked remediations, and code-level vulnerability context.",
  openGraph: {
    title: "VulnShield — Repository Security Intelligence",
    description:
      "Evidence-grounded vulnerability reasoning: scan a GitHub repo, get a Repository " +
      "Security Intelligence Score and ranked remediations.",
    type: "website",
  },
};

// Server-side initial fetch — the page can render scans without waiting
// for a client-side useEffect. Falls back to [] on any error so the form
// is always usable.
async function fetchInitialScans(): Promise<ScanListItem[]> {
  const base = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3011";
  try {
    const res = await fetch(`${base}/api/scans`, {
      cache: "no-store",
      signal: AbortSignal.timeout(5_000),
    });
    if (!res.ok) return [];
    return (await res.json()) as ScanListItem[];
  } catch {
    return [];
  }
}

export default async function HomePage() {
  const initialScans = await fetchInitialScans();
  return <HomeClient initialScans={initialScans} />;
}
