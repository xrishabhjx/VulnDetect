import { Card } from "@/components/ui";

// Segment-level Suspense fallback for /scan/[id] — keeps the header
// visible while the page hydrates and the client-side fetch begins.
export default function ScanLoading() {
  return (
    <div className="space-y-8" aria-busy="true" aria-live="polite">
      <div className="h-4 w-32 animate-pulse rounded bg-slate-800" />
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="space-y-2">
          <div className="h-9 w-72 animate-pulse rounded bg-slate-800" />
          <div className="h-4 w-48 animate-pulse rounded bg-slate-800" />
        </div>
      </div>
      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="flex items-center gap-5">
          <div className="h-32 w-32 animate-pulse rounded-full bg-slate-800" />
          <div className="space-y-2">
            <div className="h-3 w-24 animate-pulse rounded bg-slate-800" />
            <div className="h-3 w-56 animate-pulse rounded bg-slate-800" />
          </div>
        </Card>
        <Card className="col-span-2 grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[0, 1, 2, 3].map((i) => (
            <div key={i} className="space-y-2">
              <div className="h-6 w-16 animate-pulse rounded bg-slate-800" />
              <div className="h-3 w-20 animate-pulse rounded bg-slate-800" />
            </div>
          ))}
        </Card>
      </div>
      <Card>
        <div className="h-2 w-full animate-pulse rounded-full bg-slate-800" />
      </Card>
      <p className="text-xs text-slate-500">Loading analysis…</p>
    </div>
  );
}
