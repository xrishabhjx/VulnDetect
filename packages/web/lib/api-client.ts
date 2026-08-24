import axios from "axios";
import type {
  AnalysisResult,
  ScanReport,
  EvalMetrics,
  RSISScore,
  SimilarRepo,
} from "./types";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3005";

type AnalysisOptions = {
  useNVD?: boolean;
  skipDev?: boolean;
  skipEmbedding?: boolean;
  skipSimilarRepos?: boolean;
  skipReasoning?: boolean;
  maxRemediations?: number;
};

export type AnalysisProgressEvent = {
  stage: string;
  status: "started" | "completed";
  progress: number;
  message: string;
};

const api = axios.create({
  baseURL: API_URL,
  timeout: 300000, // 5 min timeout for long-running analysis
  headers: {
    "Content-Type": "application/json",
  },
});

export const apiClient = {
  // Health check
  async health() {
    const res = await api.get("/api/health");
    return res.data;
  },

  // Scanning endpoints
  async startQuickScan(repoUrl: string, options?: { useNVD?: boolean; skipDev?: boolean }) {
    const res = await api.post("/api/scan", {
      repoUrl,
      useNVD: options?.useNVD || false,
      skipDev: options?.skipDev || false,
    });
    return res.data as ScanReport;
  },

  async getQuickScan(scanId: string) {
    const res = await api.get(`/api/scan/${scanId}`);
    return res.data as ScanReport;
  },

  async listScans() {
    const res = await api.get("/api/scans");
    return res.data as Array<{
      id: string;
      repoUrl: string;
      repoOwner: string;
      repoName: string;
      status: string;
      totalDeps: number;
      totalVulns: number;
      createdAt: string;
      completedAt?: string;
      errorMessage?: string;
    }>;
  },

  // Analysis endpoints
  async startFullAnalysis(
    repoUrl: string,
    options?: AnalysisOptions
  ) {
    const res = await api.post("/api/analyze", {
      repoUrl,
      useNVD: options?.useNVD || false,
      skipDev: options?.skipDev || false,
      skipEmbedding: options?.skipEmbedding || false,
      skipSimilarRepos: options?.skipSimilarRepos || false,
      skipReasoning: options?.skipReasoning || false,
      maxRemediations: options?.maxRemediations ?? 3,
    });
    return res.data as AnalysisResult;
  },

  async streamFullAnalysis(
    repoUrl: string,
    options: AnalysisOptions | undefined,
    onProgress: (event: AnalysisProgressEvent) => void
  ) {
    const response = await fetch(`${API_URL}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "text/event-stream" },
      body: JSON.stringify({
        repoUrl,
        useNVD: options?.useNVD || false,
        skipDev: options?.skipDev || false,
        skipEmbedding: options?.skipEmbedding || false,
        skipSimilarRepos: options?.skipSimilarRepos || false,
        skipReasoning: options?.skipReasoning || false,
        maxRemediations: options?.maxRemediations ?? 3,
      }),
    });

    if (!response.ok || !response.body) {
      throw new Error((await response.text()) || "Unable to start analysis stream");
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    let result: AnalysisResult | null = null;

    const handleEvent = (block: string) => {
      const event = block.match(/^event: (.+)$/m)?.[1];
      const rawData = block.match(/^data: (.+)$/m)?.[1];
      if (!event || !rawData) return;
      const data = JSON.parse(rawData);
      if (event === "progress") onProgress(data as AnalysisProgressEvent);
      if (event === "result") result = data as AnalysisResult;
      if (event === "error") throw new Error(data.error || "Analysis failed");
    };

    while (true) {
      const { value, done } = await reader.read();
      buffer += decoder.decode(value, { stream: !done });
      const events = buffer.split("\n\n");
      buffer = events.pop() ?? "";
      events.filter(Boolean).forEach(handleEvent);
      if (done) break;
    }

    if (!result) throw new Error("Analysis stream ended without a result");
    return result;
  },

  async getAnalysis(scanId: string) {
    const res = await api.get(`/api/analyze/${scanId}`);
    return res.data as AnalysisResult;
  },

  async getRSISScore(scanId: string) {
    const res = await api.get(`/api/analyze/${scanId}/rsis`);
    return res.data as RSISScore;
  },

  // Similar repos
  async getSimilarRepos(scanId: string) {
    const res = await api.get(`/api/similar/${scanId}`);
    return res.data as SimilarRepo[];
  },

  // Evaluation
  async runEvaluation(scanId: string) {
    const res = await api.post("/api/evaluate", { scanId });
    return res.data as { scanId: string; metrics: EvalMetrics };
  },

  async getEvaluationResults(scanId: string) {
    const res = await api.get(`/api/evaluate/${scanId}`);
    return res.data as {
      scanId: string;
      metrics: EvalMetrics;
      runAt: string;
    };
  },
};

export default apiClient;
