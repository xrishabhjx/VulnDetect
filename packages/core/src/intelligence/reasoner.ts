import type {
  UnifiedVulnerability,
  RepositoryContext,
  RetrievedChunk,
  RemediationCandidate,
  RemediationReport,
  Ecosystem,
  GraphContextPath,
  ChainStep,
  EvidenceReference,
} from "../types.js";
import { Embedder } from "./embedder.js";
import { ContextRetriever } from "./retriever.js";

// ─── LLM Provider Configuration ──────────────────────────────────────────────

const GROQ_DEFAULT_MODEL   = "qwen/qwen3.8-27b";
const GEMINI_DEFAULT_MODEL = "gemini-3.6-flash";
const MAX_PROMPT_CHARS = clampConfig("LLM_MAX_PROMPT_CHARS", 5_500, 2_000, 20_000);
const GROQ_MAX_OUTPUT_TOKENS = clampConfig("GROQ_MAX_OUTPUT_TOKENS", 450, 256, 1_000);
const GEMINI_MAX_OUTPUT_TOKENS = clampConfig("GEMINI_MAX_OUTPUT_TOKENS", 1_200, 512, 4_000);

function clampConfig(key: string, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(process.env[key] ?? "", 10);
  return Number.isFinite(parsed) ? Math.min(Math.max(parsed, min), max) : fallback;
}

function fitPrompt(prompt: string): string {
  if (prompt.length <= MAX_PROMPT_CHARS) return prompt;
  return `${prompt.slice(0, MAX_PROMPT_CHARS)}\n\n[Context truncated to stay within the configured provider token budget.]`;
}

interface LLMProvider {
  name: string;
  baseUrl: string;
  apiKey: string;
  modelName: string;
  type: "groq" | "gemini";
}

// ─── Prompt Builder ────────────────────────────────────────────────────────────

function buildContextAwarePrompt(
  vulnerability: UnifiedVulnerability,
  packageName: string,
  version: string,
  ecosystem: Ecosystem,
  ctx: RepositoryContext
): string {
  const sections: string[] = [];

  // ── Section 1: Repository Profile ─────────────────────────────────────────
  if (ctx.profile) {
    const p = ctx.profile;
    const stack = [
      p.language && `Language: ${p.language}`,
      p.framework && `Framework: ${p.framework}`,
      p.architecture && `Architecture: ${p.architecture}`,
      p.repositoryType !== "unknown" && `Type: ${p.repositoryType}`,
      p.database && `Database: ${p.database}`,
      p.orm && `ORM: ${p.orm}`,
      p.authentication && `Auth: ${p.authentication}`,
      p.deployment && `Deployment: ${p.deployment}`,
      p.testingFramework && `Testing: ${p.testingFramework}`,
      p.packageManagers.length > 0 && `Package Managers: ${p.packageManagers.join(", ")}`,
    ].filter(Boolean).join("\n");

    sections.push(`## 1. Repository Profile
${stack}
Purpose: ${p.purpose ?? p.description ?? "Unknown"}
Has CI/CD: ${p.hasCiCd} | Has Tests: ${p.hasTests} | Has Dockerfile: ${p.hasDockerfile}`);
  }

  // ── Section 2: Knowledge Graph Context ────────────────────────────────────
  if (ctx.graphSummary) {
    sections.push(`## 2. Repository Knowledge Graph\n${ctx.graphSummary}`);
  }

  if (ctx.graphPaths.length > 0) {
    const graphTraversal = ctx.graphPaths
      .map(g => [
        `- Package: ${g.package}`,
        `  Impacted Files (${g.impactedFiles.length}): ${g.impactedFiles.slice(0, 5).join(", ")}`,
        g.affectedModules.length > 0 && `  Affected Modules: ${g.affectedModules.slice(0, 5).join(", ")}`,
        g.patchVersions.length > 0 && `  ✅ Graph-confirmed patch versions: ${g.patchVersions.join(", ")}`,
        g.kevStatus && `  ⚠️ CISA KEV: This CVE is actively exploited in the wild`,
        `  Explanation: ${g.explanation}`,
      ].filter(Boolean).join("\n"))
      .join("\n\n");
    sections.push(`## 3. Graph Traversal Results\n${graphTraversal}`);
  }

  // ── Section 3: Retrieved Code Evidence ────────────────────────────────────
  if (ctx.retrievedChunks.length > 0) {
    const codeContext = ctx.retrievedChunks
      .map((c, i) =>
        `### Code Evidence ${i + 1} — ${c.filePath}:${c.startLine ?? "?"}-${c.endLine ?? "?"} (RRF: ${c.similarityScore.toFixed(3)})\n\`\`\`${c.language ?? ""}\n${c.content.substring(0, 500)}\n\`\`\``
      )
      .join("\n\n");
    sections.push(`## 4. Retrieved Code Context (Hybrid BM25+pgvector Search)\n${codeContext}`);
  }

  // ── Section 4: Threat Intelligence ────────────────────────────────────────
  const kevWarning = vulnerability.kev
    ? "\n⚠️ CRITICAL: This CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog — active exploitation confirmed."
    : "";

  sections.push(`## 5. Threat Intelligence
CVE: ${vulnerability.cveId ?? "N/A"} | GHSA: ${vulnerability.githubAdvisoryId ?? "N/A"}
Package: ${packageName}@${version} (${ecosystem})
Severity: ${vulnerability.severity} | CVSS: ${vulnerability.cvssScore ?? "N/A"}
Vector: ${vulnerability.cvssVector ?? "N/A"}
Source: ${vulnerability.source}
Fixed Versions: ${vulnerability.fixedVersions.join(", ") || "Unknown"}
Summary: ${vulnerability.summary}
${vulnerability.mitigationGuidance ? `Mitigation Guidance: ${vulnerability.mitigationGuidance}` : ""}${kevWarning}`);

  // ── Section 5: Similar Repository Evidence ────────────────────────────────
  if (ctx.similarRepoEvidence.length > 0) {
    const simEvidence = ctx.similarRepoEvidence.map(e => {
      const parts = [
        `- ${e.repoFullName} (similarity: ${(e.similarityScore * 100).toFixed(0)}%, health: ${e.healthScore}/100, ${e.maintenanceActivity})`,
        e.sharedDependencies.length > 0 && `  Shared dependencies: ${e.sharedDependencies.slice(0, 5).join(", ")}`,
        e.knownSafeVersion && `  Uses ${packageName}@${e.knownSafeVersion} successfully`,
        e.upgradePattern && `  Pattern: ${e.upgradePattern}`,
      ].filter(Boolean).join("\n");
      return parts;
    }).join("\n");
    sections.push(`## 6. Similar Repository Evidence\nThese repositories share your technology stack and have handled this dependency:\n${simEvidence}`);
  } else if (ctx.similarRepos.length > 0) {
    const simText = ctx.similarRepos
      .slice(0, 3)
      .map(r => `- ${r.fullName} (${r.stars}⭐, health: ${r.healthScore}/100, ${r.maintenanceActivity}) — ${r.description ?? ""}`)
      .join("\n");
    sections.push(`## 6. Similar Repositories\n${simText}`);
  }

  // ── Section 6: Reasoning Instructions ─────────────────────────────────────
  const framework = ctx.profile?.framework ?? "this project";
  const architecture = ctx.profile?.architecture ?? "unknown architecture";

  sections.push(`## 7. Reasoning Task

You are analysing ${packageName}@${version} in a ${framework} application with ${architecture} architecture.

For EACH candidate remediation:
1. Explain WHY this vulnerability matters in THIS specific codebase (reference graph traversal results).
2. State WHICH files and modules are affected (from Section 3 graph traversal).
3. Assess whether the vulnerability is actually REACHABLE based on the retrieved code evidence.
4. Reference WHICH similar repositories used the proposed fix (from Section 6).
5. Propose a version from Fixed Versions: [${vulnerability.fixedVersions.join(", ")}] or a justified alternative.
6. Assess compatibility risk for ${framework} specifically.

Evidence requirements:
- chainOfReasoning MUST reference specific file paths from the graph traversal.
- evidence MUST reference actual code snippets from Section 4.
- confidence MUST be derived from evidence strength, not assumed.`);

  return sections.join("\n\n");
}

const OUTPUT_SCHEMA = `Return ONLY compact JSON, with no markdown or extra keys:
{"candidates":[{"action":"upgrade|replace|mitigate|accept","explanation":"short","reasoning":"short","confidence":0.0,"compatibilityRisk":"low|medium|high","proposedVersion":"X.Y.Z or null"}]}
Return exactly one candidate. Use a proposedVersion only from Fixed Versions. Keep explanation and reasoning under 160 characters each. Do not include evidence, chainOfReasoning, or reasoningTrace.`;

// ─── Context-Aware Reasoning Engine ──────────────────────────────────────────

/**
 * Context-Aware Reasoning Engine with provider fallback chain.
 *
 * Provider priority: Groq (LLaMA 3.3-70B) → Gemini (1.5-flash) → Heuristic fallback
 *
 * Key design:
 * 1. Accepts a unified RepositoryContext object — not individual parameters.
 * 2. The context carries profile, graph, retrieved chunks, similar repo evidence.
 * 3. If Groq fails (rate limit, 429, 500), automatically falls back to Gemini.
 * 4. If both fail, applies evidence-based heuristic candidates.
 * 5. Provider used is recorded in the reasoning trace for transparency.
 */
export class ContextReasoner {
  private providers: LLMProvider[];
  private retriever: ContextRetriever;
  private disabledProviders = new Set<string>();

  get aiEnabled(): boolean {
    return this.providers.length > 0;
  }

  constructor(embedder?: Embedder) {
    this.providers = this.buildProviderChain();
    this.retriever = new ContextRetriever(embedder);

    if (this.providers.length > 0) {
      console.log(`[Reasoner] Provider chain: ${this.providers.map(p => p.name).join(" → ")} → Heuristic`);
    } else {
      console.log("[Reasoner] No LLM API keys found — heuristic fallback will be used");
    }
  }

  // ─── Provider chain builder ──────────────────────────────────────────────

  private buildProviderChain(): LLMProvider[] {
    const chain: LLMProvider[] = [];

    const groqKey = process.env.GROQ_API_KEY?.trim();
    if (groqKey) {
      chain.push({
        name: `Groq (${process.env.GROQ_MODEL ?? GROQ_DEFAULT_MODEL})`,
        baseUrl: "https://api.groq.com/openai/v1",
        apiKey: groqKey,
        modelName: process.env.GROQ_MODEL ?? GROQ_DEFAULT_MODEL,
        type: "groq",
      });
    }

    const geminiKey = process.env.GEMINI_API_KEY?.trim();
    if (geminiKey) {
      chain.push({
        name: `Gemini (${process.env.GEMINI_MODEL ?? GEMINI_DEFAULT_MODEL})`,
        baseUrl: "https://generativelanguage.googleapis.com/v1beta",
        apiKey: geminiKey,
        modelName: process.env.GEMINI_MODEL ?? GEMINI_DEFAULT_MODEL,
        type: "gemini",
      });
    }

    return chain;
  }

  // ─── Main entry ─────────────────────────────────────────────────────────

  /**
   * Generate evidence-grounded remediation report using full RepositoryContext.
   *
   * The context object must be pre-built by the analyzer before calling this.
   * This method only: retrieves chunks, builds prompt, calls LLM with fallback.
   */
  async reason(
    scanId: string,
    vulnerability: UnifiedVulnerability,
    packageName: string,
    version: string,
    ecosystem: Ecosystem,
    ctx: RepositoryContext
  ): Promise<RemediationReport> {
    // Retrieve semantically relevant chunks using hybrid BM25+pgvector
    const query = `${packageName} ${vulnerability.summary} ${vulnerability.cveId ?? ""}`;
    let retrievedChunks: RetrievedChunk[] = [];
    try {
      retrievedChunks = await Promise.race([
        this.retriever.retrieve(scanId, query, 5),
        new Promise<RetrievedChunk[]>((_, reject) =>
          setTimeout(() => reject(new Error("retrieval timeout")), 1_000)
        ),
      ]);
    } catch (error) {
      if (process.env.REQUIRE_NEURAL_EMBEDDINGS?.toLowerCase() === "true" && (error as Error).message.includes("embedding")) {
        throw error;
      }
      console.warn("[Reasoner] Context retrieval unavailable; continuing with supplied context:", (error as Error).message);
    }

    // Merge retrieved chunks into context (context may already have some from prior steps)
    const fullCtx: RepositoryContext = {
      ...ctx,
      retrievedChunks: retrievedChunks.length > 0 ? retrievedChunks : ctx.retrievedChunks,
    };

    if (!this.aiEnabled) {
      if (process.env.REQUIRE_AI_REASONING?.toLowerCase() === "true") {
        throw new Error("Required AI reasoning provider is not configured");
      }
      return this.heuristicFallback(scanId, vulnerability, packageName, version, ecosystem, fullCtx);
    }

    const userPrompt = fitPrompt(
      buildContextAwarePrompt(vulnerability, packageName, version, ecosystem, fullCtx)
    );

    // Try each provider in order — fallback to next on failure
    for (const provider of this.providers) {
      if (this.disabledProviders.has(provider.name)) continue;
      try {
        const candidates = await this.callProvider(provider, userPrompt, vulnerability, fullCtx.retrievedChunks);
        const providerTrace = `Context-Aware Reasoning via ${provider.name} — ${fullCtx.retrievedChunks.length} code chunks, ${fullCtx.graphPaths.length} graph paths, ${fullCtx.similarRepoEvidence.length} similar repo evidence items`;

        return {
          scanId,
          cveId: vulnerability.cveId,
          packageName,
          ecosystem,
          candidates,
          reasoningTrace: providerTrace,
          contextChunks: fullCtx.retrievedChunks,
          graphContext: fullCtx.graphPaths,
          validationPassed: false,
        };
      } catch (err) {
        const message = (err as Error).message;
        if (this.shouldDisableProvider(message)) {
          this.disabledProviders.add(provider.name);
          console.warn(`[Reasoner] ${provider.name} is temporarily unavailable (${message}). Disabled for the rest of this analysis — trying next provider`);
        } else {
          console.warn(`[Reasoner] ${provider.name} failed:`, message, "— trying next provider");
        }
      }
    }

    // All providers exhausted
    if (process.env.REQUIRE_AI_REASONING?.toLowerCase() === "true") {
      throw new Error("Required AI reasoning providers failed");
    }
    console.warn("[Reasoner] All providers failed — applying heuristic fallback");
    return this.heuristicFallback(scanId, vulnerability, packageName, version, ecosystem, fullCtx);
  }

  // ─── Provider call implementations ───────────────────────────────────────

  private async callProvider(
    provider: LLMProvider,
    userPrompt: string,
    vulnerability: UnifiedVulnerability,
    chunks: RetrievedChunk[]
  ): Promise<RemediationCandidate[]> {
    if (provider.type === "groq") {
      return this.callGroq(provider, userPrompt, vulnerability, chunks);
    }
    return this.callGemini(provider, userPrompt, vulnerability, chunks);
  }

  private async callGroq(
    provider: LLMProvider,
    userPrompt: string,
    vulnerability: UnifiedVulnerability,
    chunks: RetrievedChunk[]
  ): Promise<RemediationCandidate[]> {
    const url = `${provider.baseUrl}/chat/completions`;
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${provider.apiKey}`,
      },
      body: JSON.stringify({
        model: provider.modelName,
        temperature: 0.2,
        max_tokens: GROQ_MAX_OUTPUT_TOKENS,
        response_format: { type: "json_object" },
        messages: [
          {
            role: "system",
            content: "You are an expert security intelligence reasoning engine. Provide evidence-grounded remediation recommendations in JSON format. Every recommendation must reference specific files, code, and evidence from the context provided.",
          },
          {
            role: "user",
            content: `${userPrompt}\n\n${OUTPUT_SCHEMA}`,
          },
        ],
      }),
      signal: AbortSignal.timeout(45_000),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`Groq HTTP ${response.status}: ${body.substring(0, 200)}`);
    }

    const data = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
    };
    const text = data.choices?.[0]?.message?.content;
    if (!text) throw new Error("Groq returned empty content");

    const parsed = JSON.parse(text) as { candidates: RemediationCandidate[] };
    return (parsed.candidates ?? []).map(c => this.completeCandidate(c, vulnerability, chunks));
  }

  private async callGemini(
    provider: LLMProvider,
    userPrompt: string,
    vulnerability: UnifiedVulnerability,
    chunks: RetrievedChunk[]
  ): Promise<RemediationCandidate[]> {
    const url = `${provider.baseUrl}/models/${provider.modelName}:generateContent?key=${provider.apiKey}`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{
          role: "user",
          parts: [{
            text: `You are an expert security intelligence reasoning engine. Provide evidence-grounded remediation recommendations.\n\n${userPrompt}\n\n${OUTPUT_SCHEMA}`,
          }],
        }],
        generationConfig: {
          temperature: 0.2,
          maxOutputTokens: GEMINI_MAX_OUTPUT_TOKENS,
          responseMimeType: "application/json",
        },
      }),
      signal: AbortSignal.timeout(45_000),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`Gemini HTTP ${response.status}: ${body.substring(0, 200)}`);
    }

    const data = (await response.json()) as {
      candidates?: Array<{ content: { parts: Array<{ text: string }> }; finishReason?: string }>;
    };
    const candidate = data.candidates?.[0];
    const text = candidate?.content?.parts?.[0]?.text;
    if (!text) throw new Error("Gemini returned empty content");

    if (candidate?.finishReason === "MAX_TOKENS") {
      throw new Error(`Gemini response reached the ${GEMINI_MAX_OUTPUT_TOKENS}-token output limit`);
    }

    let parsed: { candidates: RemediationCandidate[] };
    try {
      parsed = JSON.parse(text) as { candidates: RemediationCandidate[] };
    } catch {
      throw new Error("Gemini returned incomplete or invalid JSON");
    }
    return (parsed.candidates ?? []).map(c => this.completeCandidate(c, vulnerability, chunks));
  }

  // ─── Evidence enrichment ─────────────────────────────────────────────────

  /**
   * Ensure evidence references are properly populated from retrieved chunks.
   * If LLM didn't provide evidence, backfill from top retrieved chunks.
   */
  private enrichCandidateEvidence(
    candidate: RemediationCandidate,
    chunks: RetrievedChunk[]
  ): RemediationCandidate {
    const chainOfReasoning: ChainStep[] = candidate.chainOfReasoning?.length
      ? candidate.chainOfReasoning
      : [
          { stepNumber: 1, observation: candidate.explanation, deduction: candidate.reasoning },
        ];

    const evidence: EvidenceReference[] = candidate.evidence?.length
      ? candidate.evidence
      : chunks.slice(0, 2).map(c => ({
          filePath: c.filePath,
          startLine: c.startLine,
          endLine: c.endLine,
          codeSnippet: c.content.substring(0, 150),
          relevance: `Hybrid BM25+pgvector retrieval — RRF score: ${c.similarityScore.toFixed(3)}, dense: ${(c.denseScore ?? 0).toFixed(3)}`,
        }));

    return { ...candidate, chainOfReasoning, evidence };
  }

  private completeCandidate(
    candidate: Partial<RemediationCandidate>,
    vulnerability: UnifiedVulnerability,
    chunks: RetrievedChunk[]
  ): RemediationCandidate {
    const completed: RemediationCandidate = {
      action: candidate.action === "upgrade" || candidate.action === "replace" || candidate.action === "mitigate" || candidate.action === "accept"
        ? candidate.action : vulnerability.fixedVersions.length > 0 ? "upgrade" : "mitigate",
      explanation: candidate.explanation || `Address ${vulnerability.cveId ?? "the vulnerability"}`,
      reasoning: candidate.reasoning || "Recommendation derived from the advisory record and repository context.",
      confidence: typeof candidate.confidence === "number" ? Math.max(0, Math.min(1, candidate.confidence)) : 0.5,
      compatibilityRisk: candidate.compatibilityRisk === "low" || candidate.compatibilityRisk === "high" ? candidate.compatibilityRisk : "medium",
      proposedVersion: typeof candidate.proposedVersion === "string" && vulnerability.fixedVersions.includes(candidate.proposedVersion) ? candidate.proposedVersion : null,
      alternativePackage: null,
      dependencyImpact: [],
      validated: false,
      rejected: false,
      rejectionReason: null,
      validationNotes: null,
    };
    return this.enrichCandidateEvidence(completed, chunks);
  }

  private shouldDisableProvider(message: string): boolean {
    return /HTTP (400|401|403|404|429|503)|model_not_found|invalid.*model|rate limit|quota|high demand|UNAVAILABLE/i.test(message);
  }

  // ─── Heuristic fallback ──────────────────────────────────────────────────

  private heuristicCandidates(
    vuln: UnifiedVulnerability,
    chunks: RetrievedChunk[],
    graphPaths: GraphContextPath[]
  ): RemediationCandidate[] {
    const evidence: EvidenceReference[] = chunks.slice(0, 2).map(c => ({
      filePath: c.filePath,
      startLine: c.startLine,
      endLine: c.endLine,
      codeSnippet: c.content.substring(0, 150),
      relevance: "Retrieved code context",
    }));

    // Use graph-confirmed patch versions or normalized fixedVersions
    const graphPatchVersions = graphPaths.flatMap(g => g.patchVersions);
    const allFixed = Array.from(new Set([...graphPatchVersions, ...vuln.fixedVersions])).filter(Boolean);
    const bestVersion = allFixed[0] ?? null;
    const isKev = graphPaths.some(g => g.kevStatus) || vuln.kev;

    if (bestVersion) {
      const impactedFiles = graphPaths.flatMap(g => g.impactedFiles).slice(0, 3);
      return [{
        action: "upgrade",
        explanation: `Upgrade package to version ${bestVersion} to resolve ${vuln.cveId ?? "vulnerability"}${isKev ? " (CISA KEV — actively exploited)" : ""}`,
        reasoning: `Upstream advisories confirm patch version ${bestVersion} resolves this issue. ${impactedFiles.length > 0 ? `Graph context shows ${impactedFiles.join(", ")} import this package.` : "Package identified in manifest."} Available patch versions: [${allFixed.join(", ")}].`,
        chainOfReasoning: [
          { stepNumber: 1, observation: `${vuln.cveId ?? "Vulnerability"} detected (source: ${vuln.source}, severity: ${vuln.severity})`, deduction: `Patched version ${bestVersion} is available in database` },
          { stepNumber: 2, observation: impactedFiles.length > 0 ? `Graph shows ${impactedFiles.length} file(s) import this package` : "Declared in manifest", deduction: `Upgrade to ${bestVersion} mitigates threat across impacted modules` },
        ],
        evidence,
        confidence: isKev ? 0.90 : 0.80,
        compatibilityRisk: "medium",
        proposedVersion: bestVersion,
        alternativePackage: null,
        dependencyImpact: [],
        validated: false,
        rejected: false,
        rejectionReason: null,
        validationNotes: `Heuristic candidate — fixed version ${bestVersion} extracted from vulnerability database`,
      }];
    }

    return [{
      action: "mitigate",
      explanation: "Apply compensating controls — no fixed version listed in advisory databases",
      reasoning: `No fixed version identified in OSV/NVD/GitHub Advisories for ${vuln.cveId ?? "this vulnerability"}. Compensating security controls must be applied until upstream patch is released.`,
      chainOfReasoning: [
        { stepNumber: 1, observation: "No fixed version listed in vulnerability database", deduction: "Version upgrade is not yet available" },
        { stepNumber: 2, observation: "Vulnerability is present in current version", deduction: "Compensating controls must be applied" },
      ],
      evidence,
      confidence: 0.3,
      compatibilityRisk: "low",
      proposedVersion: null,
      alternativePackage: null,
      dependencyImpact: [],
      validated: false,
      rejected: false,
      rejectionReason: null,
      validationNotes: "Heuristic candidate — no fixed version available",
    }];
  }

  private heuristicFallback(
    scanId: string,
    vuln: UnifiedVulnerability,
    packageName: string,
    version: string,
    ecosystem: Ecosystem,
    ctx: RepositoryContext
  ): RemediationReport {
    return {
      scanId,
      cveId: vuln.cveId,
      packageName,
      ecosystem,
      candidates: this.heuristicCandidates(vuln, ctx.retrievedChunks, ctx.graphPaths),
      reasoningTrace: "Heuristic fallback — all LLM providers unavailable. Graph traversal and retrieval evidence used for candidate generation.",
      contextChunks: ctx.retrievedChunks,
      graphContext: ctx.graphPaths,
      validationPassed: false,
    };
  }
}

/** Export alias for vendor-agnostic framing */
export { ContextReasoner as ReasoningEngine };
