import { VulnerabilityScanner } from "./scanner.js";
import { GitHubClient } from "./github/index.js";
import { RepoUnderstander } from "./intelligence/repo-understander.js";
import { RepoChunker } from "./intelligence/chunker.js";
import { Embedder } from "./intelligence/embedder.js";
import { SimilarRepoFinder } from "./intelligence/similar-repos.js";
import { ReasoningEngine } from "./intelligence/reasoner.js";
import { RemediationValidator } from "./intelligence/validator.js";
import { CandidateRanker } from "./intelligence/candidate-ranker.js";
import { RSISScorer } from "./intelligence/rsis-scorer.js";
import { ContextRetriever } from "./intelligence/retriever.js";
import { RepoKnowledgeGraphBuilder } from "./intelligence/knowledge-graph.js";
import { cisaKEV } from "./vulndb/cisa-kev-client.js";
import { getDB } from "./db.js";
import type {
  AnalysisResult,
  RepositoryProfile,
  RepositoryContext,
  IntelligenceSummary,
  SimilarRepo,
  RemediationReport,
  Ecosystem,
  RepositoryKnowledgeGraph,
} from "./types.js";
import type { ScanOptions } from "./scanner.js";

// ─── Analysis Options ─────────────────────────────────────────────────────────

export interface AnalysisOptions extends ScanOptions {
  skipEmbedding?: boolean;
  skipSimilarRepos?: boolean;
  skipReasoning?: boolean;
  maxRemediations?: number;
}

const DEFAULT_ANALYSIS_OPTIONS: Required<AnalysisOptions> = {
  useNVD: false,
  skipDev: false,
  persist: true,
  skipEmbedding: false,
  skipSimilarRepos: false,
  skipReasoning: false,
  maxRemediations: 10,
};

// ─── Intelligence Analyzer ────────────────────────────────────────────────────

/**
 * Main Orchestrator for the Repository Security Intelligence Platform.
 *
 * Unified Pipeline:
 *   1.  Vulnerability Scan          → ScanReport + scanId
 *   2.  Repository Understanding    → RepositoryProfile (global context)
 *   3.  Semantic Chunking           → RepoChunk[]
 *   4.  Embedding Generation        → pgvector columns populated
 *   5.  Knowledge Graph (RKG)       → RepositoryKnowledgeGraph
 *   6.  CISA KEV Enrichment         → vuln.kev flags set
 *   7.  RKG Threat Enrichment       → CVSS + KEV + Patch sub-graphs
 *   8.  Similar Repository Discovery→ SimilarRepo[]
 *   9.  Repository Context Build    → RepositoryContext (unified pre-LLM object)
 *  10.  Reasoning Engine            → RemediationReport[] (Groq→Gemini→Heuristic)
 *  11.  Validation + Ranking        → Validated, ranked candidates
 *  12.  RSIS Scoring                → 5-dimension RSISScore
 *  13.  Intelligence Summary        → IntelligenceSummary
 *  14.  Database Persistence
 *
 * Every stage consumes outputs from previous stages.
 * No stage operates independently.
 */
export class IntelligenceAnalyzer {
  private scanner: VulnerabilityScanner;
  private understander: RepoUnderstander;
  private chunker: RepoChunker;
  private embedder: Embedder;
  private similarFinder: SimilarRepoFinder;
  private reasoningEngine: ReasoningEngine;
  private validator: RemediationValidator;
  private candidateRanker: CandidateRanker;
  private scorer: RSISScorer;
  private retriever: ContextRetriever;
  private rkgBuilder: RepoKnowledgeGraphBuilder;
  private github: GitHubClient;

  constructor() {
    this.embedder        = new Embedder();
    this.scanner         = new VulnerabilityScanner();
    this.understander    = new RepoUnderstander();
    this.chunker         = new RepoChunker();
    this.similarFinder   = new SimilarRepoFinder(this.embedder);
    this.reasoningEngine = new ReasoningEngine(this.embedder);
    this.validator       = new RemediationValidator();
    this.candidateRanker = new CandidateRanker();
    this.scorer          = new RSISScorer();
    this.retriever       = new ContextRetriever(this.embedder);
    this.rkgBuilder      = new RepoKnowledgeGraphBuilder();
    this.github          = new GitHubClient();
  }

  /**
   * Run the full unified intelligence pipeline on a repository.
   * Every stage consumes outputs from previous stages.
   */
  async analyze(
    repoUrl: string,
    options: AnalysisOptions = {}
  ): Promise<AnalysisResult> {
    const opts = { ...DEFAULT_ANALYSIS_OPTIONS, ...options };
    const { owner, repo } = this.github.parseRepoUrl(repoUrl);

    console.log(`\n[Analyzer] Starting unified intelligence pipeline for ${owner}/${repo}`);

    // ── Step 1: Vulnerability Scan ───────────────────────────────────────────
    console.log("[Analyzer] Step 1/13: Vulnerability scanning & dependency parsing...");
    const scanReport = await this.scanner.scan(repoUrl, {
      useNVD: opts.useNVD,
      skipDev: opts.skipDev,
      persist: opts.persist,
    });
    const scanId = scanReport.scanId;
    console.log(`[Analyzer]   → ${scanReport.totalDependencies} deps, ${scanReport.totalVulnerabilities} vulnerabilities found`);

    // ── Step 2: Repository Understanding → RepositoryProfile ─────────────────
    console.log("[Analyzer] Step 2/13: Repository understanding & profile generation...");
    let repositoryProfile: RepositoryProfile | null = null;
    try {
      repositoryProfile = await this.understander.understand(owner, repo);
      console.log(`[Analyzer]   → Profile: ${repositoryProfile.framework ?? "unknown framework"} | ${repositoryProfile.architecture ?? "unknown arch"} | ${repositoryProfile.repositoryType}`);
      console.log(`[Analyzer]   → Stack: DB=${repositoryProfile.database ?? "none"}, ORM=${repositoryProfile.orm ?? "none"}, Auth=${repositoryProfile.authentication ?? "none"}, Deploy=${repositoryProfile.deployment ?? "none"}`);
      if (opts.persist && scanId) {
        await this.persistMetadata(scanId, repositoryProfile);
      }
    } catch (err) {
      console.warn("[Analyzer] Repository profile extraction failed:", err);
    }

    // ── Step 3: Semantic Chunking ────────────────────────────────────────────
    let chunksIndexed = 0;
    let chunks: import("./types.js").RepoChunk[] = [];
    if (!opts.skipEmbedding && scanId) {
      console.log("[Analyzer] Step 3/13: Semantic chunking (function/class boundary splitting)...");
      try {
        chunks = await this.chunker.chunkRepository(owner, repo);
        console.log(`[Analyzer]   → ${chunks.length} chunks extracted from ${new Set(chunks.map(c => c.filePath)).size} files`);
      } catch (err) {
        console.warn("[Analyzer] Chunking failed:", err);
      }
    }

    // ── Step 4: Embedding Generation → pgvector columns ──────────────────────
    if (!opts.skipEmbedding && scanId && chunks.length > 0) {
      console.log("[Analyzer] Step 4/13: Embedding generation → pgvector storage (HNSW indexed)...");
      try {
        chunksIndexed = await this.embedder.indexChunks(scanId, chunks);
        console.log(`[Analyzer]   → ${chunksIndexed} chunks embedded and stored in pgvector`);
      } catch (err) {
        console.warn("[Analyzer] Embedding failed:", err);
      }
    }

    // ── Step 5: Repository Knowledge Graph Construction ───────────────────────
    console.log("[Analyzer] Step 5/13: Constructing Repository Knowledge Graph...");
    const tree = await this.github.getRepoTree(owner, repo);
    const knowledgeGraph: RepositoryKnowledgeGraph = this.rkgBuilder.buildGraph(
      repoUrl,
      tree,
      scanReport.results,
      chunks
    );
    console.log(`[Analyzer]   → Graph: ${knowledgeGraph.nodes.length} nodes, ${knowledgeGraph.edges.length} edges`);

    // ── Step 6: CISA KEV Threat Intel Enrichment ─────────────────────────────
    console.log("[Analyzer] Step 6/13: CISA KEV threat intelligence enrichment...");
    const allCveIds = scanReport.results.flatMap(r => r.vulnerabilities.map(v => v.cveId));
    const kevSet = await cisaKEV.filterKEV(allCveIds);
    for (const result of scanReport.results) {
      for (const vuln of result.vulnerabilities) {
        if (vuln.cveId && kevSet.has(vuln.cveId)) {
          vuln.kev = true;
        }
      }
    }
    console.log(`[Analyzer]   → ${kevSet.size} actively exploited CVEs flagged (CISA KEV)`);

    // ── Step 7: Knowledge Graph Threat Enrichment ─────────────────────────────
    console.log("[Analyzer] Step 7/13: Enriching Knowledge Graph with threat sub-graphs...");
    const enrichedGraph: RepositoryKnowledgeGraph = this.rkgBuilder.enrichWithThreatIntel(scanReport.results);
    // Mutate the reference so knowledgeGraph reflects enriched state
    (knowledgeGraph as { nodes: typeof enrichedGraph.nodes; edges: typeof enrichedGraph.edges }).nodes = enrichedGraph.nodes;
    (knowledgeGraph as { nodes: typeof enrichedGraph.nodes; edges: typeof enrichedGraph.edges }).edges = enrichedGraph.edges;
    const threatEdges = enrichedGraph.edges.filter(e =>
      e.relationship === "HAS_CVSS" || e.relationship === "IN_KEV" || e.relationship === "FIXED_BY"
    ).length;
    console.log(`[Analyzer]   → Graph enriched: ${enrichedGraph.nodes.length} nodes, ${enrichedGraph.edges.length} edges (+${threatEdges} threat intel edges)`);

    // Build graph summary text now — used in RepositoryContext and IntelligenceSummary
    const graphSummary = this.rkgBuilder.buildGraphSummary();

    // ── Step 8: Similar Repository Discovery ──────────────────────────────────
    let similarRepos: SimilarRepo[] = [];
    if (!opts.skipSimilarRepos && repositoryProfile) {
      console.log("[Analyzer] Step 8/13: Discovering similar repositories with health signals...");
      try {
        similarRepos = await this.similarFinder.findSimilar(owner, repo, repositoryProfile);
        if (opts.persist && scanId && similarRepos.length > 0) {
          await this.persistSimilarRepos(scanId, similarRepos);
        }
        console.log(`[Analyzer]   → ${similarRepos.length} similar repos found (top: ${similarRepos.slice(0, 3).map(r => r.fullName).join(", ")})`);
      } catch (err) {
        console.warn("[Analyzer] Similar repo discovery failed:", err);
      }
    }

    // ── Step 9: Reasoning + Validation + Ranking ──────────────────────────────
    console.log("[Analyzer] Step 9/13: Running context-aware reasoning pipeline...");
    const remediations: RemediationReport[] = [];

    const vulnsToRemediate = scanReport.results
      .flatMap(r =>
        r.vulnerabilities.map(v => ({ dep: r.dependency, vuln: v }))
      )
      .sort((a, b) => {
        const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
        return (order[a.vuln.severity] ?? 5) - (order[b.vuln.severity] ?? 5);
      })
      .slice(0, opts.maxRemediations);

    for (const { dep, vuln } of vulnsToRemediate) {
      try {
        // ── Step 9a: Graph traversal for this specific package ─────────────
        const graphPaths = this.rkgBuilder.traverseContext(dep.name, vuln.cveId);

        // ── Step 9b: Build SimilarRepoEvidence for this package ───────────
        const similarRepoEvidence = this.similarFinder.buildSimilarRepoEvidence(
          similarRepos,
          dep.name,
          dep.version,
          vuln.fixedVersions
        );

        // ── Step 9c: Build unified RepositoryContext ───────────────────────
        // All intelligence from previous stages flows into one object.
        // The reasoning engine receives this single context — nothing re-fetched.
        const threatSummary = [
          `Severity: ${vuln.severity}`,
          vuln.cvssScore && `CVSS: ${vuln.cvssScore}`,
          vuln.kev && "⚠️ Actively exploited (CISA KEV)",
          kevSet.size > 0 && `${kevSet.size} KEV CVEs in this scan`,
        ].filter(Boolean).join(" | ");

        const ctx: RepositoryContext = {
          profile: repositoryProfile,
          graphSummary,
          graphPaths,
          retrievedChunks: [],   // populated by reasoner.reason() via pgvector retrieval
          similarRepos,
          similarRepoEvidence,
          threatSummary,
        };

        // ── Step 10: Reasoning Engine (Groq → Gemini → Heuristic) ─────────
        const report = await this.reasoningEngine.reason(
          scanId ?? "",
          vuln,
          dep.name,
          dep.version,
          dep.ecosystem as Ecosystem,
          ctx
        );

        // ── Step 11: Validation & Candidate Ranking ────────────────────────
        const validatedReport = await this.validator.validate(report, report.ecosystem, dep.version);
        const rankedCandidates = this.candidateRanker.rankCandidates(
          validatedReport.candidates,
          vuln,
          dep.version,
          similarRepos
        );

        remediations.push({ ...validatedReport, candidates: rankedCandidates });
      } catch (err) {
        console.warn(`[Analyzer] Pipeline failed for ${dep.name}:`, err);
      }
    }

    console.log(`[Analyzer]   → ${remediations.length} remediation reports generated`);

    // ── Step 12: RSIS Score ───────────────────────────────────────────────────
    console.log("[Analyzer] Step 12/13: Computing 5-dimension RSIS score...");
    const meanSimilarity = scanId
      ? await this.retriever.computeMeanSimilarity(
          scanId,
          vulnsToRemediate.map(v => `${v.dep.name} ${v.vuln.summary}`),
          5
        )
      : 0;
    const rsis = this.scorer.compute(scanReport.results, remediations, meanSimilarity);

    // ── Step 13: Intelligence Summary ─────────────────────────────────────────
    console.log("[Analyzer] Step 13/13: Building intelligence summary...");
    const intelligenceSummary = this.buildIntelligenceSummary(
      repositoryProfile,
      knowledgeGraph,
      similarRepos,
      scanReport.results,
      kevSet,
      rsis.totalScore
    );

    // ── Persistence ───────────────────────────────────────────────────────────
    if (opts.persist && scanId) {
      await this.persistRemediations(scanId, remediations);
      await this.persistRSIS(scanId, rsis);
    }

    console.log(`\n[Analyzer] ✅ Analysis complete!`);
    console.log(`[Analyzer]    RSIS: ${rsis.totalScore}/100 (Grade ${rsis.grade})`);
    console.log(`[Analyzer]    Projected after remediation: ${intelligenceSummary.projectedRsisAfterRemediation}/100`);

    return {
      scanId: scanId ?? "",
      scan: scanReport,
      metadata: repositoryProfile,           // backward compat
      repositoryProfile,
      knowledgeGraph,
      chunksIndexed,
      similarRepos,
      remediations,
      rsis,
      intelligenceSummary,
      aiEnabled: this.embedder.aiEnabled,
    };
  }

  // ─── Intelligence Summary Builder ────────────────────────────────────────────

  private buildIntelligenceSummary(
    profile: RepositoryProfile | null,
    graph: RepositoryKnowledgeGraph,
    similarRepos: SimilarRepo[],
    scanResults: import("./types.js").DependencyScanResult[],
    kevSet: Set<string | null>,
    currentRsis: number
  ): IntelligenceSummary {
    // Repository understanding
    const repoParts = [
      profile?.framework && `${profile.framework} framework`,
      profile?.architecture && `${profile.architecture} architecture`,
      profile?.repositoryType !== "unknown" && profile?.repositoryType && `${profile.repositoryType} project`,
      profile?.language && `primarily ${profile.language}`,
    ].filter(Boolean);
    const repositoryUnderstanding = repoParts.length > 0
      ? `${repoParts.join(", ")}.${profile?.purpose ? ` Purpose: ${profile.purpose.substring(0, 150)}` : ""}`
      : "Repository structure could not be fully determined.";

    // Stack description
    const stackParts = [
      profile?.framework,
      profile?.database && `${profile.database} database`,
      profile?.orm && `${profile.orm} ORM`,
      profile?.authentication && `${profile.authentication} auth`,
      profile?.deployment && `deployed on ${profile.deployment}`,
      profile?.testingFramework && `tested with ${profile.testingFramework}`,
    ].filter(Boolean);
    const stackDescription = stackParts.length > 0
      ? stackParts.join(", ")
      : `${profile?.language ?? "unknown"} project`;

    // Graph stats
    const nodesByType = new Map<string, number>();
    for (const node of graph.nodes) {
      nodesByType.set(node.type, (nodesByType.get(node.type) ?? 0) + 1);
    }
    const kevCount = graph.nodes.filter(n => n.properties.subType === "KEV").length;

    // Similar repo influence
    const activeRepos = similarRepos.filter(r => r.maintenanceActivity === "active");
    const similarRepoInfluence = similarRepos.length > 0
      ? `Found ${similarRepos.length} similar repositories. ${activeRepos.length} are actively maintained. ` +
        `Top similar: ${similarRepos.slice(0, 3).map(r => `${r.fullName} (${r.stars}⭐)`).join(", ")}.`
      : "No similar repositories discovered (GitHub API may be rate-limited or no strong matches).";

    // Threat intel summary
    const critCount = scanResults.flatMap(r => r.vulnerabilities).filter(v => v.severity === "CRITICAL").length;
    const highCount  = scanResults.flatMap(r => r.vulnerabilities).filter(v => v.severity === "HIGH").length;
    const threatIntelSummary = [
      `${scanResults.flatMap(r => r.vulnerabilities).length} total vulnerabilities`,
      critCount > 0 && `${critCount} CRITICAL`,
      highCount > 0 && `${highCount} HIGH`,
      kevSet.size > 0 && `${kevSet.size} actively exploited (CISA KEV)`,
      `across ${scanResults.length} dependencies`,
    ].filter(Boolean).join(", ");

    // Projected RSIS after remediation (estimate: each remediation improves score by ~3 points)
    const criticalVulnsResolvable = scanResults
      .flatMap(r => r.vulnerabilities)
      .filter(v => v.severity === "CRITICAL" || v.severity === "HIGH")
      .filter(v => v.fixedVersions.length > 0).length;
    const projectedRsisAfterRemediation = Math.min(100, Math.round(currentRsis + criticalVulnsResolvable * 3));

    return {
      repositoryUnderstanding,
      stackDescription,
      graphStats: {
        totalNodes: graph.nodes.length,
        totalEdges: graph.edges.length,
        fileCount: nodesByType.get("File") ?? 0,
        moduleCount: nodesByType.get("Module") ?? 0,
        packageCount: nodesByType.get("Package") ?? 0,
        threatCount: nodesByType.get("Threat") ?? 0,
        kevCount,
      },
      similarRepoInfluence,
      threatIntelSummary,
      projectedRsisAfterRemediation,
    };
  }

  // ─── Persistence Helpers ─────────────────────────────────────────────────────

  private async persistMetadata(scanId: string, profile: RepositoryProfile): Promise<void> {
    const db = getDB();
    await db.repositoryMetadata.upsert({
      where: { scanId },
      update: {},
      create: {
        scanId,
        language: profile.language,
        languages: JSON.stringify(profile.languages),
        framework: profile.framework,
        purpose: profile.purpose,
        topics: JSON.stringify(profile.topics),
        description: profile.description,
        folderHierarchy: JSON.stringify(profile.folderHierarchy),
        totalFiles: profile.totalFiles,
        hasDockerfile: profile.hasDockerfile,
        hasCiCd: profile.hasCiCd,
        hasTests: profile.hasTests,
        stars: profile.stars,
        forks: profile.forks,
        openIssues: profile.openIssues,
        lastPushed: profile.lastPushed ? new Date(profile.lastPushed) : null,
      },
    });
  }

  private async persistSimilarRepos(scanId: string, repos: SimilarRepo[]): Promise<void> {
    const db = getDB();
    for (const r of repos) {
      await db.similarRepository.create({
        data: {
          scanId,
          owner: r.owner,
          repo: r.repo,
          fullName: r.fullName,
          description: r.description,
          language: r.language,
          stars: r.stars,
          topics: JSON.stringify(r.topics),
          similarityScore: r.similarityScore,
          githubUrl: r.githubUrl,
        },
      });
    }
  }

  private async persistRemediations(
    scanId: string,
    remediations: RemediationReport[]
  ): Promise<void> {
    const db = getDB();
    for (const r of remediations) {
      await db.remediationReport.create({
        data: {
          scanId,
          cveId: r.cveId,
          packageName: r.packageName,
          ecosystem: r.ecosystem,
          candidates: JSON.stringify(r.candidates),
          reasoningTrace: r.reasoningTrace,
          contextUsed: JSON.stringify(r.contextChunks.map(c => c.filePath)),
          validationPassed: r.validationPassed,
          validationNotes: r.candidates
            .filter(c => c.validationNotes)
            .map(c => c.validationNotes)
            .join("; ") || null,
        },
      });
    }
  }

  private async persistRSIS(scanId: string, rsis: import("./types.js").RSISScore): Promise<void> {
    const db = getDB();
    await db.rSISScore.upsert({
      where: { scanId },
      update: {
        totalScore: rsis.totalScore,
        severityScore: rsis.securityScore,
        remediationScore: rsis.compatibilityScore,
        retrievalScore: rsis.retrievalScore,
        validationScore: rsis.validationScore,
        maintainabilityScore: rsis.maintainabilityScore,
        weights: JSON.stringify(rsis.weights),
        signals: JSON.stringify(rsis.signals),
      },
      create: {
        scanId,
        totalScore: rsis.totalScore,
        severityScore: rsis.securityScore,
        remediationScore: rsis.compatibilityScore,
        retrievalScore: rsis.retrievalScore,
        validationScore: rsis.validationScore,
        maintainabilityScore: rsis.maintainabilityScore,
        weights: JSON.stringify(rsis.weights),
        signals: JSON.stringify(rsis.signals),
      },
    });
  }
}
