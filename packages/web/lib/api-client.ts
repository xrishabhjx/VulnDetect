import axios from "axios";
import type {
  AnalysisResult,
  ScanReport,
  EvalMetrics,
  RSISScore,
  SimilarRepo,
} from "./types";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3005";

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
    options?: {
      useNVD?: boolean;
      skipDev?: boolean;
      skipEmbedding?: boolean;
      skipSimilarRepos?: boolean;
      skipReasoning?: boolean;
      maxRemediations?: number;
    }
  ) {
    const res = await api.post("/api/analyze", {
      repoUrl,
      useNVD: options?.useNVD || false,
      skipDev: options?.skipDev || false,
      skipEmbedding: options?.skipEmbedding || false,
      skipSimilarRepos: options?.skipSimilarRepos || false,
      skipReasoning: options?.skipReasoning || false,
      maxRemediations: options?.maxRemediations || 10,
    });
    return res.data as AnalysisResult;
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
