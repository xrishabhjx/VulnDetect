"use client";

import { useCallback, useEffect, useState } from "react";
import apiClient from "@/lib/api-client";
import type { AnalysisResult, ScanReport } from "@/lib/types";

type ScanStatus = "idle" | "loading" | "success" | "error";
type AnalysisStage =
  | "idle"
  | "dependency-scanning"
  | "repository-understanding"
  | "chunking"
  | "embedding"
  | "building-graph"
  | "enriching-threats"
  | "finding-similar-repos"
  | "reasoning"
  | "scoring"
  | "finalizing"
  | "complete"
  | "error";

export function useScan() {
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [scan, setScan] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const startScan = useCallback(
    async (repoUrl: string, options?: { useNVD?: boolean; skipDev?: boolean }) => {
      setStatus("loading");
      setError(null);
      try {
        const result = await apiClient.startQuickScan(repoUrl, options);
        setScan(result);
        setStatus("success");
      } catch (err: any) {
        const message =
          err?.response?.data?.error ??
          (err instanceof Error ? err.message : "Scan failed");
        setError(message);
        setStatus("error");
      }
    },
    []
  );

  const getScan = useCallback(async (scanId: string) => {
    setStatus("loading");
    setError(null);
    try {
      const result = await apiClient.getQuickScan(scanId);
      setScan(result);
      setStatus("success");
    } catch (err: any) {
      const message =
        err?.response?.data?.error ??
        (err instanceof Error ? err.message : "Failed to fetch scan");
      setError(message);
      setStatus("error");
    }
  }, []);

  return { scan, status, error, startScan, getScan };
}

export function useAnalysis() {
  const [stage, setStage] = useState<AnalysisStage>("idle");
  const [analysis, setAnalysis] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  const stages: AnalysisStage[] = [
    "dependency-scanning",
    "repository-understanding",
    "chunking",
    "embedding",
    "building-graph",
    "enriching-threats",
    "finding-similar-repos",
    "reasoning",
    "scoring",
    "finalizing",
    "complete",
  ];

  const stageLabels: Record<AnalysisStage, string> = {
    "idle": "Ready",
    "dependency-scanning": "Vulnerability scanning & dependency parsing",
    "repository-understanding": "Repository understanding & profile generation",
    "chunking": "Semantic chunking",
    "embedding": "Embedding generation",
    "building-graph": "Constructing repository knowledge graph",
    "enriching-threats": "KEV threat enrichment",
    "finding-similar-repos": "Finding similar repositories",
    "reasoning": "Running context-aware reasoning",
    "scoring": "Computing RSIS score",
    "finalizing": "Building intelligence summary",
    "complete": "Analysis complete",
    "error": "Error occurred",
  };

  // Simulate progress through stages
  useEffect(() => {
    if (stage === "idle" || stage === "complete" || stage === "error") return;

    const stageIndex = stages.indexOf(stage);
    const calculatedProgress = Math.round(((stageIndex + 1) / stages.length) * 100);
    setProgress(calculatedProgress);
  }, [stage, stages]);

  const startAnalysis = useCallback(
    async (
      repoUrl: string,
      options?: {
        useNVD?: boolean;
        skipDev?: boolean;
        skipEmbedding?: boolean;
        skipSimilarRepos?: boolean;
        skipReasoning?: boolean;
        maxRemediations?: number;
      }
    ) => {
      setStage("dependency-scanning");
      setError(null);
      setProgress(0);

      try {
        const stageSequence: AnalysisStage[] = [
          "dependency-scanning",
          "repository-understanding",
          "chunking",
          "embedding",
          "building-graph",
          "enriching-threats",
          "finding-similar-repos",
          "reasoning",
          "scoring",
          "finalizing",
          "complete",
        ];

        for (const nextStage of stageSequence.slice(0, -1)) {
          setStage(nextStage);
          await new Promise((resolve) => setTimeout(resolve, 700 + Math.random() * 350));
        }

        const result = await apiClient.startFullAnalysis(repoUrl, options);
        setAnalysis(result);
        setStage("complete");
        setProgress(100);
      } catch (err: any) {
        const message =
          err?.response?.data?.error ??
          (err instanceof Error ? err.message : "Analysis failed");
        setError(message);
        setStage("error");
      }
    },
    []
  );

  const getAnalysis = useCallback(async (scanId: string) => {
    setStage("dependency-scanning");
    setError(null);
    setProgress(0);

    try {
      setStage("repository-understanding");
      await new Promise((resolve) => setTimeout(resolve, 300));

      const result = await apiClient.getAnalysis(scanId);
      const raw = result as any;
      const normalized = raw?.scan
        ? raw
        : {
            ...raw,
            scan: {
              scanId: raw?.scanId ?? scanId,
              repoUrl: raw?.repoUrl ?? "",
              repoOwner: raw?.repoOwner ?? "",
              repoName: raw?.repoName ?? "",
              scannedAt: raw?.scannedAt ?? raw?.createdAt ?? new Date().toISOString(),
              totalDependencies: raw?.totalDependencies ?? 0,
              totalVulnerabilities: raw?.totalVulnerabilities ?? 0,
              severityCounts: raw?.severityCounts ?? {
                CRITICAL: 0,
                HIGH: 0,
                MEDIUM: 0,
                LOW: 0,
                UNKNOWN: 0,
              },
              results: raw?.results ?? [],
            },
            rsis: raw?.rsis ?? raw?.rsisScore ?? {
              totalScore: 0,
              securityScore: 0,
              retrievalScore: 0,
              validationScore: 0,
              maintainabilityScore: 0,
              compatibilityScore: 0,
              weights: { security: 0.3, retrieval: 0.2, validation: 0.2, maintainability: 0.15, compatibility: 0.15 },
              signals: {
                criticalVulns: 0,
                highVulns: 0,
                mediumVulns: 0,
                lowVulns: 0,
                totalVulns: 0,
                totalDeps: 0,
                highConfidenceCandidates: 0,
                totalCandidates: 0,
                meanRetrievalSimilarity: 0,
                hybridMRR: 0,
                validatedCandidates: 0,
                totalValidated: 0,
                recentDeps: 0,
                kevCount: 0,
                semverCompatRate: 0,
              },
              rationale: {
                formula: "",
                citations: [],
                ablationNotes: "",
              },
              grade: "F",
            },
            intelligenceSummary: raw?.intelligenceSummary ?? {
              repositoryUnderstanding: "",
              stackDescription: "",
              graphStats: {
                totalNodes: 0,
                totalEdges: 0,
                fileCount: 0,
                moduleCount: 0,
                packageCount: 0,
                threatCount: 0,
                kevCount: 0,
              },
              similarRepoInfluence: "",
              threatIntelSummary: "",
              projectedRsisAfterRemediation: raw?.rsisScore?.totalScore ?? 0,
            },
          };
      setAnalysis(normalized);
      setStage("complete");
      setProgress(100);
    } catch (err: any) {
      const message =
        err?.response?.data?.error ??
        (err instanceof Error ? err.message : "Failed to fetch analysis");
      setError(message);
      setStage("error");
    }
  }, []);

  return {
    analysis,
    stage,
    stageLabel: stageLabels[stage],
    error,
    progress,
    startAnalysis,
    getAnalysis,
  };
}
