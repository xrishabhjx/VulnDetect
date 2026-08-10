"use client";

import Link from "next/link";
import { useEffect } from "react";
import { Card } from "@/components/ui";

// Segment-level error boundary for /scan/[id]. Triggered when the
// client-side fetch in the page throws (e.g. 404 for an unknown scan,
// 500 from the API, or a network failure).
export default function ScanError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[VulnShield] Scan page error boundary caught:", error);
  }, [error]);

  return (
    <div className="space-y-4">
      <Link href="/" className="text-sm text-slate-500 hover:text-slate-300">
        ← Back to scans
      </Link>
      <Card>
        <h1 className="text-xl font-semibold text-white">Couldn’t load this analysis</h1>
        <p className="mt-2 text-sm text-slate-400">
          {error.message || "The scan ID may be invalid, or the API may be unreachable."}
        </p>
        {error.digest && (
          <p className="mt-1 font-mono text-xs text-slate-600">Error ID: {error.digest}</p>
        )}
        <div className="mt-4 flex gap-3">
          <button
            type="button"
            onClick={reset}
            className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-emerald-500"
          >
            Try again
          </button>
          <Link
            href="/"
            className="rounded-lg border border-slate-700 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-slate-500"
          >
            Back to home
          </Link>
        </div>
      </Card>
    </div>
  );
}
