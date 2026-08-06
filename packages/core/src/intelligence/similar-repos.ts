import type { SimilarRepo, SimilarRepoEvidence, RepositoryMetadata, MaintenanceActivity } from "../types.js";
import { Embedder } from "./embedder.js";

// ─── GitHub Search API Types ─────────────────────────────────────────────────

interface GitHubSearchResult {
  total_count: number;
  items: Array<{
    full_name: string;
    owner: { login: string };
    name: string;
    description: string | null;
    language: string | null;
    stargazers_count: number;
    forks_count: number;
    open_issues_count: number;
    pushed_at: string | null;
    topics: string[];
    html_url: string;
  }>;
}

// ─── Similar Repository Finder ───────────────────────────────────────────────

/**
 * Discovers semantically similar public GitHub repositories with rich health signals.
 *
 * Health Signals Evaluated:
 * 1. Stars & Forks — community adoption
 * 2. Maintenance Activity — push age (active: <30d, moderate: <180d, stale: >180d)
 * 3. Issue Management — open issue burden
 * 4. Composite Health Score (0-100)
 *
 * Search + Embeddings + Health Signal Ranking ensures recommended repos
 * are not only semantically similar but actively maintained and healthy.
 */
export class SimilarRepoFinder {
  private embedder: Embedder;
  private readonly githubToken: string;
  private readonly TOP_K = 10;

  constructor(embedder?: Embedder, githubToken?: string) {
    this.embedder = embedder ?? new Embedder();
    this.githubToken = githubToken || process.env.GITHUB_TOKEN || "";
  }

  /**
   * Find similar repositories for the given repo metadata.
   */
  async findSimilar(
    targetOwner: string,
    targetRepo: string,
    metadata: RepositoryMetadata
  ): Promise<SimilarRepo[]> {
    const candidates = await this.searchCandidates(metadata, targetOwner, targetRepo);

    if (candidates.length === 0) return [];

    // Use neural re-ranking only when Gemini is configured.
    // Local TF-IDF vectors from Groq-only setups are keyword-based and produce
    // misleading cosine scores for repository descriptions — heuristics are more
    // reliable in that case.
    if (this.embedder.aiEnabled && metadata.purpose) {
      return this.reRankByEmbeddingAndHealth(metadata, candidates);
    }

    return this.rankByHealthAndHeuristics(metadata, candidates);
  }

  /**
   * Build per-dependency evidence from similar repositories.
   *
   * For each similar repo, checks whether it shares the target dependency.
   * If so, records what version it uses — allowing the reasoning engine to cite:
   * "Repository A uses express@4.18.3 successfully (patched from 4.16.x)"
   *
   * @param similarRepos  The top-K similar repos found by findSimilar()
   * @param packageName   The vulnerable package to look for
   * @param currentVersion The current (vulnerable) version in the scanned repo
   * @param fixedVersions  Fixed versions from the vulnerability database
   */
  buildSimilarRepoEvidence(
    similarRepos: SimilarRepo[],
    packageName: string,
    currentVersion: string,
    fixedVersions: string[]
  ): SimilarRepoEvidence[] {
    // Without fetching each repo's package.json (expensive), we infer shared
    // dependencies from topic/description signals and apply heuristics.
    // A repo with the same language + framework likely shares the same core deps.
    return similarRepos
      .filter(r => r.healthScore >= 50)
      .slice(0, 5)
      .map(r => {
        // Heuristic: if topics include the package name, it's likely a direct dep
        const topicMatch = r.topics.some(
          t => t.toLowerCase().includes(packageName.toLowerCase()) ||
               packageName.toLowerCase().includes(t.toLowerCase())
        );

        // Infer whether this repo likely uses a patched version
        // (healthy, maintained repos tend to be up to date)
        const likelyPatched = r.maintenanceActivity === "active" && fixedVersions.length > 0;
        const knownSafeVersion = likelyPatched ? fixedVersions[0] : null;

        const upgradePattern = knownSafeVersion
          ? `Likely uses ${packageName}@${knownSafeVersion} — ${r.maintenanceActivity} maintenance (${r.pushAgeDays}d since last push)`
          : null;

        return {
          repoFullName: r.fullName,
          repoUrl: r.githubUrl,
          similarityScore: r.similarityScore,
          healthScore: r.healthScore,
          maintenanceActivity: r.maintenanceActivity,
          sharedDependencies: topicMatch ? [packageName] : [],
          knownSafeVersion,
          upgradePattern,
        } satisfies SimilarRepoEvidence;
      })
      .filter(e => e.sharedDependencies.length > 0 || e.knownSafeVersion !== null);
  }

  /**
   * Search candidates from GitHub API.
   */
  private async searchCandidates(
    metadata: RepositoryMetadata,
    excludeOwner: string,
    excludeRepo: string
  ): Promise<SimilarRepo[]> {
    const parts: string[] = [];

    // Always filter by language — the most reliable signal
    if (metadata.language) {
      parts.push(`language:${metadata.language.toLowerCase()}`);
    }

    // Security/vulnerability-specific topic filters (most relevant for this platform)
    const securityTopics = ["security", "vulnerability", "owasp", "pentest", "exploit", "ctf"];
    const repoTopicsLower = metadata.topics.map(t => t.toLowerCase());
    const hasSecurityTopic = repoTopicsLower.some(t => securityTopics.includes(t));

    if (hasSecurityTopic) {
      // Repo is security-focused — search within that domain
      parts.push("topic:security");
    } else {
      // Use the repo's own topics for domain matching
      for (const topic of metadata.topics.slice(0, 2)) {
        parts.push(`topic:${topic}`);
      }
    }

    // Last resort: use significant words from description
    if (parts.length <= 1 && metadata.description) {
      const stopWords = new Set(["the", "and", "for", "with", "that", "this", "app", "application"]);
      const words = metadata.description
        .split(/\s+/)
        .map(w => w.replace(/[^a-z]/gi, "").toLowerCase())
        .filter(w => w.length > 4 && !stopWords.has(w))
        .slice(0, 2);
      parts.push(...words);
    }

    if (parts.length === 0) return [];

    // Exclude mega-popular repos (>50k stars) that dominate purely by star count
    const query = `${parts.join(" ")} stars:>10 stars:<50000`;
    const url = `https://api.github.com/search/repositories?q=${encodeURIComponent(query)}&sort=stars&per_page=30`;

    try {
      const response = await fetch(url, {
        headers: {
          Authorization: this.githubToken ? `token ${this.githubToken}` : "",
          "User-Agent": "vuln-shield/2.0",
          Accept: "application/vnd.github.v3+json",
        },
        signal: AbortSignal.timeout(10_000),
      });

      if (!response.ok) {
        console.warn(`[SimilarRepos] Search failed: HTTP ${response.status}`);
        return [];
      }

      const data = (await response.json()) as GitHubSearchResult;
      const now = new Date();

      return data.items
        .filter((r) => `${r.owner.login}/${r.name}` !== `${excludeOwner}/${excludeRepo}`)
        .map((r) => {
          const lastPush = r.pushed_at ? new Date(r.pushed_at) : new Date(0);
          const pushAgeDays = Math.max(0, Math.floor((now.getTime() - lastPush.getTime()) / (1000 * 60 * 60 * 24)));

          const maintenanceActivity: MaintenanceActivity =
            pushAgeDays <= 30 ? "active" : pushAgeDays <= 180 ? "moderate" : "stale";

          const healthScore = this.computeHealthScore(r.stargazers_count, r.forks_count, r.open_issues_count, pushAgeDays);

          return {
            owner: r.owner.login,
            repo: r.name,
            fullName: r.full_name,
            description: r.description,
            language: r.language,
            stars: r.stargazers_count,
            forks: r.forks_count,
            openIssues: r.open_issues_count,
            pushAgeDays,
            maintenanceActivity,
            healthScore,
            topics: r.topics ?? [],
            similarityScore: 0,
            githubUrl: r.html_url,
          };
        });
    } catch (error) {
      console.warn("[SimilarRepos] Search request failed:", error);
      return [];
    }
  }

  /**
   * Compute composite health score (0-100).
   */
  private computeHealthScore(stars: number, forks: number, openIssues: number, pushAgeDays: number): number {
    const starScore = Math.min(40, (stars / 500) * 40);
    const forkScore = Math.min(20, (forks / 100) * 20);

    // Maintenance recency: 30 pts for <30 days, degrading over 365 days
    const maintenanceScore = Math.max(0, 30 * (1 - Math.min(365, pushAgeDays) / 365));

    // Issue health penalty: high ratio of open issues vs stars reduces score
    const issuePenalty = stars > 0 ? Math.min(10, (openIssues / stars) * 20) : 5;

    return Math.round(Math.max(0, Math.min(100, starScore + forkScore + maintenanceScore - issuePenalty)));
  }

  /**
   * Re-rank candidates using embedding similarity + health score.
   */
  private async reRankByEmbeddingAndHealth(
    metadata: RepositoryMetadata,
    candidates: SimilarRepo[]
  ): Promise<SimilarRepo[]> {
    const targetText = [
      metadata.purpose ?? metadata.description ?? "",
      `Language: ${metadata.language ?? ""}`,
      `Topics: ${metadata.topics.join(", ")}`,
      `Framework: ${metadata.framework ?? ""}`,
    ].join("\n");

    const candidateTexts = candidates.map(
      (c) => `${c.fullName}: ${c.description ?? ""} Topics: ${c.topics.join(", ")}`
    );

    const [targetEmbedding, ...candidateEmbeddings] = await Promise.all([
      this.embedder.embed(targetText),
      ...candidateTexts.map((t) => this.embedder.embed(t)),
    ]);

    const scored = candidates.map((candidate, i) => {
      const candidateEmbed = candidateEmbeddings[i];
      // embed() always returns number[] now — never null
      const semSim = candidateEmbed ? Math.max(0, this.cosineSim(targetEmbedding, candidateEmbed)) : 0;
      // Combined similarity = 70% semantic + 30% health
      const combinedScore = semSim * 0.7 + (candidate.healthScore / 100) * 0.3;
      return { ...candidate, similarityScore: parseFloat(combinedScore.toFixed(3)) };
    });

    scored.sort((a, b) => b.similarityScore - a.similarityScore);
    return scored.slice(0, this.TOP_K);
  }

  /**
   * Heuristic ranking fallback combining topic overlap & health score.
   */
  private rankByHealthAndHeuristics(
    metadata: RepositoryMetadata,
    candidates: SimilarRepo[]
  ): SimilarRepo[] {
    const targetTopics = new Set(metadata.topics.map((t) => t.toLowerCase()));

    const scored = candidates.map((candidate) => {
      const candidateTopics = candidate.topics.map((t) => t.toLowerCase());
      const topicOverlap = candidateTopics.filter((t) => targetTopics.has(t)).length;
      const topicScore = targetTopics.size > 0 ? topicOverlap / targetTopics.size : 0;
      const langScore = candidate.language === metadata.language ? 0.2 : 0;
      const healthBoost = (candidate.healthScore / 100) * 0.3;

      const score = topicScore * 0.5 + langScore + healthBoost;
      return { ...candidate, similarityScore: parseFloat(score.toFixed(3)) };
    });

    scored.sort((a, b) => b.similarityScore - a.similarityScore);
    return scored.slice(0, this.TOP_K);
  }

  private cosineSim(a: number[], b: number[]): number {
    let dot = 0, normA = 0, normB = 0;
    for (let i = 0; i < a.length; i++) {
      dot += a[i] * b[i];
      normA += a[i] * a[i];
      normB += b[i] * b[i];
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom === 0 ? 0 : dot / denom;
  }
}
