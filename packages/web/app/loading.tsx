import { Card } from "@/components/ui";

// Suspense fallback shown while a server-component page is loading.
// Scoped to the segment, so the header from app/layout.tsx remains visible.
export default function Loading() {
  return (
    <div className="space-y-6" aria-busy="true" aria-live="polite">
      <div className="space-y-2">
        <div className="h-8 w-2/3 animate-pulse rounded bg-slate-800" />
        <div className="h-4 w-1/2 animate-pulse rounded bg-slate-800" />
      </div>
      <Card>
        <div className="space-y-3">
          <div className="h-4 w-1/4 animate-pulse rounded bg-slate-800" />
          <div className="h-10 w-full animate-pulse rounded bg-slate-800" />
        </div>
      </Card>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="h-24 animate-pulse rounded-xl bg-slate-900/50" />
        <div className="h-24 animate-pulse rounded-xl bg-slate-900/50" />
      </div>
      <p className="text-xs text-slate-500">Loading…</p>
    </div>
  );
}
