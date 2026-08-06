import type { RepoChunk } from "../types.js";
import { getDB } from "../db.js";

// ─── Configuration ────────────────────────────────────────────────────────────

const GEMINI_EMBED_MODEL  = "text-embedding-004";
const EMBEDDING_DIMENSIONS = 768;
const BATCH_SIZE           = 100;

// ─── Provider detection ───────────────────────────────────────────────────────

/**
 * Resolve which embedding provider to use.
 *
 * Priority order:
 *   1. GEMINI_API_KEY  → Google Gemini text-embedding-004  (768-dim, best quality)
 *   2. Neither key     → local TF-IDF fallback             (768-dim, no API needed)
 *
 * NOTE: Groq does NOT offer an embeddings API — it provides LLM completions only.
 *       If only GROQ_API_KEY is set, we use the local TF-IDF fallback for
 *       embeddings and still use Groq for the reasoning / LLM steps.
 */
function resolveProvider(): "gemini" | "local" {
  if (process.env.GEMINI_API_KEY?.length) return "gemini";
  return "local";
}

// ─── Local TF-IDF Embedder ───────────────────────────────────────────────────

/**
 * Lightweight local embedding using TF-IDF inspired term weighting.
 *
 * This is NOT a neural embedding — it is a bag-of-words vector used as a
 * graceful fallback when no external embedding API is available.
 *
 * Properties:
 *   - Deterministic (same text → same vector every time)
 *   - 768-dimensional to match Gemini output shape
 *   - Cosine-comparable (L2-normalised)
 *   - Good enough for keyword-based retrieval when neural embeddings are absent
 *
 * Research note: the hybrid retrieval pipeline also uses BM25, which does not
 * require embeddings. When only local embeddings are available, BM25 dominates
 * retrieval quality. This is explicitly flagged in the RSIS retrieval score.
 */
function localEmbed(text: string): number[] {
  const tokens = tokenise(text);
  const tf     = termFrequency(tokens);
  return projectToFixed768(tf);
}

function tokenise(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9_\-./\s]/g, " ")
    .split(/\s+/)
    .filter(t => t.length > 1 && t.length < 40);
}

function termFrequency(tokens: string[]): Map<string, number> {
  const tf = new Map<string, number>();
  for (const t of tokens) tf.set(t, (tf.get(t) ?? 0) + 1);
  const max = Math.max(...tf.values(), 1);
  for (const [k, v] of tf) tf.set(k, v / max);
  return tf;
}

/**
 * Project a TF map into a fixed 768-dim vector using a stable hash.
 * Each dimension accumulates weighted term contributions via a double-hash
 * trick (similar to feature hashing / the hashing trick used in sklearn).
 */
function projectToFixed768(tf: Map<string, number>): number[] {
  const dim = EMBEDDING_DIMENSIONS;
  const vec = new Float64Array(dim);

  for (const [term, weight] of tf) {
    const h1 = stableHash(term);
    const h2 = stableHash(term + "_2");
    const idx = Math.abs(h1) % dim;
    const sign = h2 % 2 === 0 ? 1 : -1;
    vec[idx] += sign * weight;
  }

  // L2-normalise
  let norm = 0;
  for (const v of vec) norm += v * v;
  norm = Math.sqrt(norm) || 1;
  return Array.from(vec).map(v => v / norm);
}

function stableHash(s: string): number {
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = (h * 16777619) >>> 0;
  }
  return h;
}

// ─── Gemini API types ─────────────────────────────────────────────────────────

interface GeminiEmbedRequest {
  model: string;
  content: { parts: Array<{ text: string }> };
  taskType?: string;
}
interface GeminiEmbedResponse   { embedding: { values: number[] } }
interface GeminiBatchResponse   { embeddings: Array<{ values: number[] }> }

// ─── Embedder ─────────────────────────────────────────────────────────────────

/**
 * Embedder — generates dense text vectors for semantic retrieval.
 *
 * Provider selection (automatic, based on .env):
 *   GEMINI_API_KEY set → Google Gemini text-embedding-004 (best)
 *   Neither key set    → Local TF-IDF fallback (deterministic, no API)
 *
 * Groq is intentionally NOT used for embeddings because Groq does not offer
 * an embeddings endpoint. When GROQ_API_KEY is present, it is used only by
 * the ReasoningEngine (LLM completions).
 */
export class Embedder {
  private readonly geminiKey: string | null;
  private provider: "gemini" | "local";

  /** True when a neural embedding API is available */
  get aiEnabled(): boolean {
    return this.provider === "gemini";
  }

  /** True when any embedding is available (always true — local fallback exists) */
  get embeddingAvailable(): boolean {
    return true;
  }

  constructor() {
    this.geminiKey = process.env.GEMINI_API_KEY?.length
      ? process.env.GEMINI_API_KEY
      : null;
    this.provider  = resolveProvider();

    if (this.provider === "gemini") {
      console.log("[Embedder] Using Gemini text-embedding-004 (neural, 768-dim)");
    } else {
      const reason = process.env.GROQ_API_KEY?.length
        ? "Groq does not provide an embeddings API — using local TF-IDF fallback"
        : "No GEMINI_API_KEY set — using local TF-IDF fallback";
      console.log(`[Embedder] ${reason}`);
      console.log("[Embedder] BM25 retrieval remains active; set GEMINI_API_KEY for neural embeddings");
    }
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  async embed(text: string): Promise<number[]> {
    if (this.provider === "gemini") {
      const result = await this.geminiEmbed(text, "RETRIEVAL_DOCUMENT");
      if (result) return result;
      console.warn("[Embedder] Gemini embed failed — falling back to local TF-IDF");
    }
    return localEmbed(text);
  }

  async embedQuery(query: string): Promise<number[]> {
    if (this.provider === "gemini") {
      const result = await this.geminiEmbed(query, "RETRIEVAL_QUERY");
      if (result) return result;
    }
    return localEmbed(query);
  }

  async embedBatch(texts: string[]): Promise<number[][]> {
    if (texts.length === 0) return [];

    if (this.provider === "gemini") {
      const results = await this.geminiBatchEmbed(texts);
      // Fill any nulls with local fallback
      return results.map((r, i) => r ?? localEmbed(texts[i]!));
    }

    // Local: synchronous, no rate limits
    return texts.map(t => localEmbed(t));
  }

  /** Index chunks into the database with embeddings. */
  async indexChunks(scanId: string, chunks: RepoChunk[]): Promise<number> {
    const db = getDB();
    let stored = 0;

    for (let i = 0; i < chunks.length; i += BATCH_SIZE) {
      const batch      = chunks.slice(i, i + BATCH_SIZE);
      const texts      = batch.map(c => this.buildChunkText(c));
      const embeddings = await this.embedBatch(texts);

      for (let j = 0; j < batch.length; j++) {
        const chunk     = batch[j]!;
        const embedding = embeddings[j]!;
        const vecStr    = `[${embedding.join(",")}]`;

        try {
          // Use raw SQL to write the vector(768) column — Prisma doesn't
          // expose Unsupported() types via the regular client API.
          await db.$executeRawUnsafe(`
            INSERT INTO "RepositoryChunk"
              (id, "scanId", "filePath", "chunkType", language, content,
               "startLine", "endLine", "embeddingVec", "embeddingJson", "createdAt")
            VALUES (
              gen_random_uuid()::text,
              $1, $2, $3, $4, $5, $6, $7,
              $8::vector,
              $9,
              NOW()
            )
          `,
            scanId,
            chunk.filePath,
            chunk.chunkType,
            chunk.language ?? null,
            chunk.content,
            chunk.startLine ?? null,
            chunk.endLine ?? null,
            vecStr,           // cast to vector(768)
            vecStr,           // keep JSON copy for local-only fallback
          );
          stored++;
        } catch (err) {
          console.warn(`[Embedder] Failed to store chunk from ${chunk.filePath}:`, err);
        }
      }

      // Gemini rate-limit pause only
      if (this.provider === "gemini" && i + BATCH_SIZE < chunks.length) {
        await new Promise(r => setTimeout(r, 500));
      }
    }

    return stored;
  }

  get dimensions(): number {
    return EMBEDDING_DIMENSIONS;
  }

  // ─── Gemini implementation ───────────────────────────────────────────────────

  private async geminiEmbed(text: string, taskType: string): Promise<number[] | null> {
    if (this.provider === "local") return null;

    const url  = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_EMBED_MODEL}:embedContent?key=${this.geminiKey}`;
    const body: GeminiEmbedRequest = {
      model:    `models/${GEMINI_EMBED_MODEL}`,
      content:  { parts: [{ text: text.substring(0, 8000) }] },
      taskType,
    };

    try {
      const res = await fetch(url, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify(body),
        signal:  AbortSignal.timeout(15_000),
      });
      if (!res.ok) {
        const err = await res.text();
        console.warn(`[Embedder] Gemini embed HTTP ${res.status}: ${err.substring(0, 80)}`);
        console.warn("[Embedder] Switching provider to local TF-IDF fallback.");
        this.provider = "local";
        return null;
      }
      const data = (await res.json()) as GeminiEmbedResponse;
      return data.embedding?.values ?? null;
    } catch (err) {
      console.warn("[Embedder] Gemini embed network error:", err);
      this.provider = "local";
      return null;
    }
  }

  private async geminiBatchEmbed(texts: string[]): Promise<Array<number[] | null>> {
    if (this.provider === "local") return texts.map(() => null);

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_EMBED_MODEL}:batchEmbedContents?key=${this.geminiKey}`;
    const requests = texts.map(text => ({
      model:    `models/${GEMINI_EMBED_MODEL}`,
      content:  { parts: [{ text: text.substring(0, 8000) }] },
      taskType: "RETRIEVAL_DOCUMENT",
    }));

    try {
      const res = await fetch(url, {
        method:  "POST",
        headers: { "Content-Type": "application/json" },
        body:    JSON.stringify({ requests }),
        signal:  AbortSignal.timeout(30_000),
      });

      if (!res.ok) {
        console.warn(`[Embedder] Gemini batch embed HTTP ${res.status} — switching to local TF-IDF fallback`);
        this.provider = "local";
        return texts.map(() => null);
      }

      const data = (await res.json()) as GeminiBatchResponse;
      return data.embeddings?.map(e => e.values ?? null) ?? texts.map(() => null);
    } catch (err) {
      console.warn("[Embedder] Gemini batch embed network error:", err);
      this.provider = "local";
      return texts.map(() => null);
    }
  }

  private buildChunkText(chunk: RepoChunk): string {
    return `File: ${chunk.filePath}\nType: ${chunk.chunkType}\nLanguage: ${chunk.language ?? "unknown"}\n\n${chunk.content}`;
  }
}
