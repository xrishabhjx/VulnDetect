"use client";

import { useEffect, useRef, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useScan, useAnalysis } from "@/hooks/useScan";
import { LoadingSpinner, PipelineProgress, ErrorMessage } from "@/components/common/Loading";

function NewScanContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const repoUrl = searchParams.get("url") || "";
  const scanType = (searchParams.get("type") as "quick" | "full") || "full";
  const startedKeyRef = useRef<string | null>(null);

  const { scan, error: scanError, startScan } = useScan();
  const { analysis, stage, stageLabel, error: analysisError, progress, startAnalysis } = useAnalysis();

  useEffect(() => {
    const key = `${scanType}:${repoUrl}`;
    if (!repoUrl || startedKeyRef.current === key) return;

    startedKeyRef.current = key;
    if (scanType === "quick") {
      startScan(repoUrl);
    } else {
      startAnalysis(repoUrl);
    }
  }, [repoUrl, scanType, startScan, startAnalysis]);

  // Redirect on completion
  useEffect(() => {
    if (scanType === "quick" && scan) {
      router.push(`/scans/${scan.scanId}`);
    } else if (scanType === "full" && analysis) {
      router.push(`/scans/${analysis.scanId}/analysis`);
    }
  }, [scan, analysis, scanType, router]);

  const error = scanError || analysisError;

  return (
    <div className="card p-8 sm:p-10 space-y-8 border-border">
      <div className="space-y-2 text-center border-b border-border pb-6">
        <span className="text-xs font-mono uppercase tracking-wider text-accent">
          Execution Monitor
        </span>
        <h1 className="text-2xl font-display font-semibold text-primary">
          {scanType === "quick" ? "Quick Scan" : "Full AI Analysis"} in Progress
        </h1>
        <p className="text-sm font-mono text-secondary truncate max-w-full">
          Target: <span className="text-primary">{repoUrl}</span>
        </p>
      </div>

      {error && <ErrorMessage message={error} />}

      {!error && (
        <div>
          {scanType === "quick" ? (
            <div className="py-8 space-y-6 text-center">
              <LoadingSpinner size="lg" text="Scanning dependency manifests..." />
              <p className="text-xs text-secondary font-mono">
                Querying OSV, NVD, GitHub Advisory Database, and CISA KEV catalog...
              </p>
            </div>
          ) : (
            <PipelineProgress stage={stage} progress={progress} stageLabel={stageLabel} />
          )}
        </div>
      )}

      <div className="p-4 rounded-lg bg-surface border border-border text-xs text-secondary font-body leading-relaxed">
        {scanType === "quick"
          ? "Quick Scan executes lightweight manifest parsing and CVE lookup (~10–30s)."
          : "Full AI Analysis constructs the Repository Knowledge Graph, performs hybrid BM25+Dense retrieval, runs LLM reasoning chains, and computes the 5-dimension RSIS score (~1–3 mins)."}
      </div>
    </div>
  );
}

export default function NewScanPage() {
  return (
    <div className="min-h-screen bg-background py-16">
      <div className="max-w-2xl mx-auto px-6">
        <Suspense fallback={<LoadingSpinner size="lg" text="Loading scan parameters..." />}>
          <NewScanContent />
        </Suspense>
      </div>
    </div>
  );
}
