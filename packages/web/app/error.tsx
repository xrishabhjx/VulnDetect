"use client";

import { useEffect } from "react";
import Link from "next/link";
import { Card } from "@/components/ui";

// Next.js client error boundary. Triggered when a server component throws
// OR when a client component throws during render. The reset button asks
// Next to re-render the segment.
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log to the browser console so it's visible in DevTools.
    console.error("[VulnShield] Page error boundary caught:", error);
  }, [error]);

  return (
    <div className="space-y-4">
      <Card>
        <h1 className="text-xl font-semibold text-white">Something went wrong</h1>
        <p className="mt-2 text-sm text-slate-400">
          {error.message || "An unexpected error occurred while loading this page."}
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
