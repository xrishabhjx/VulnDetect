import type { RetrievedChunk, RetrievalFilter, ChunkType } from "../types.js";
import { getDB } from "../db.js";
import { Embedder } from "./embedder.js";

// ─── Constants ────────────────────────────────────────────────────────────────

const BM25_K1     = 1.2;
const BM25_B      = 0.75;
const RRF_K       = 60;   // Reciprocal Rank Fusion smoothing constant

// ─── BM25 Helpers ─────────────────────────────────────────────────────────────

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9_]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 2);
}

// ─── Hybrid Context Retriever ─────────────────────────────────────────────────

/**
 * Hybrid Context Retriever — Sparse BM25 + Dense pgvector + Reciprocal Rank Fusion.
 *
 * Dense search:
 *   Uses pgvector's native <=> cosine distance operator with HNSW index.
 *   This runs entirely inside Postgres and returns top-K results in sub-ms,
 *   vs the previous approach of loading all JSON blobs into Node and computing
 *   cosine in JS (O(n × d) where d = 768).
 *
 * Sparse search:
 *   BM25 over tokenised chunk content (computed in-memory after DB fetch).
 *   Excellent for exact code symbol / CVE-ID matches.
 *
 * Fusion:
 *   Reciprocal Rank Fusion (RRF) — rank-based combination that is robust to
 *   score scale differences between BM25 and cosine similarity.
 *
 * Research: Cormack et al. "Reciprocal Rank Fusion outperforms Condorcet and
 *   individual Rank Learning Methods" (SIGIR 2009).
 */
export class ContextRetriever {
  private embedder: Embedder;

  constructor(embedder?: Embedder) {
    this.embedder = embedder ?? new Embedder();
  }

  // ─── Main entry ─────────────────────────────────────────────────────────────

  async retrieve(
    scanId: string,
    query: string,
    k = 5,
    filter?: RetrievalFilter
  ): Promise<RetrievedChunk[]> {
    const db = getDB();

    // ── 1. Embed the query ───────────────────────────────────────────────────
    const queryVec    = await this.embedder.embedQuery(query);
    const queryVecStr = `[${queryVec.join(",")}]`;

    // ── 2. pgvector ANN search — top 4×k candidates via HNSW cosine index ───
    //    <=> is the cosine distance operator (1 − similarity).
    //    We retrieve 4×k candidates so BM25 re-ranking has enough headroom.
    const vectorCandidateCount = k * 4;

    type RawRow = {
      id: string;
      filePath: string;
      content: string;
      chunkType: string;
      language: string | null;
      startLine: number | null;
      endLine: number | null;
      cosineDist: number;
    };

    let vectorRows: RawRow[] = [];

    try {
      vectorRows = await db.$queryRawUnsafe<RawRow[]>(`
        SELECT
          id,
          "filePath",
          content,
          "chunkType",
          language,
          "startLine",
          "endLine",
          ("embeddingVec" <=> $1::vector) AS "cosineDist"
        FROM "RepositoryChunk"
        WHERE "scanId" = $2
          AND "embeddingVec" IS NOT NULL
        ORDER BY "embeddingVec" <=> $1::vector
        LIMIT $3
      `, queryVecStr, scanId, vectorCandidateCount);
    } catch (err) {
      // Fallback if vector column not yet populated (e.g. old chunks indexed before migration)
      console.warn("[Retriever] pgvector query failed — falling back to JSON cosine:", (err as Error).message);
      return this.retrieveFallback(scanId, query, queryVec, k, filter);
    }

    // ── 3. Apply metadata filters on the pgvector candidates ────────────────
    const filtered = vectorRows.filter(row => {
      if (filter?.languages?.length) {
        if (!row.language || !filter.languages.includes(row.language)) return false;
      }
      if (filter?.chunkTypes?.length) {
        if (!filter.chunkTypes.includes(row.chunkType as ChunkType)) return false;
      }
      if (filter?.filePaths?.length) {
        if (!filter.filePaths.includes(row.filePath)) return false;
      }
      if (filter?.frameworks?.length) {
        const pathLower    = row.filePath.toLowerCase();
        const contentLower = row.content.toLowerCase();
        const match = filter.frameworks.some(fw =>
          pathLower.includes(fw.toLowerCase()) ||
          contentLower.includes(`from '${fw.toLowerCase()}'`) ||
          contentLower.includes(`require('${fw.toLowerCase()}')`)
        );
        if (!match) return false;
      }
      if (filter?.dependencyNames?.length) {
        const contentLower = row.content.toLowerCase();
        const match = filter.dependencyNames.some(dep =>
          contentLower.includes(`'${dep.toLowerCase()}'`) ||
          contentLower.includes(`"${dep.toLowerCase()}"`)
        );
        if (!match) return false;
      }
      return true;
    });

    if (filtered.length === 0) return [];

    // ── 4. BM25 over the pgvector candidates ────────────────────────────────
    //    Running BM25 only over the pre-filtered ~4k candidates (not the whole
    //    collection) keeps this O(k × d_query) instead of O(n × d_query).
    const bm25Scores = this.computeBM25(query, filtered);

    // ── 5. Dense rank from pgvector cosine distance ──────────────────────────
    //    cosineDist = 1 − similarity → lower is better → we negate for ranking
    const denseScores = new Map<string, number>(
      filtered.map(r => [r.id, 1 - r.cosineDist])  // convert distance → similarity
    );

    // ── 6. Build rank maps ───────────────────────────────────────────────────
    const bm25Ranked = [...bm25Scores.entries()].sort((a, b) => b[1] - a[1]);
    const bm25RankMap = new Map(bm25Ranked.map(([id], i) => [id, i + 1]));

    const denseRanked = [...denseScores.entries()].sort((a, b) => b[1] - a[1]);
    const denseRankMap = new Map(denseRanked.map(([id], i) => [id, i + 1]));

    // ── 7. Reciprocal Rank Fusion ────────────────────────────────────────────
    const fused = filtered.map(row => {
      const bm25Rank  = bm25RankMap.get(row.id)  ?? (filtered.length + 1);
      const denseRank = denseRankMap.get(row.id) ?? (filtered.length + 1);
      const rrf = (1 / (RRF_K + bm25Rank)) + (1 / (RRF_K + denseRank));
      return {
        row,
        rrf,
        bm25:  bm25Scores.get(row.id)  ?? 0,
        dense: denseScores.get(row.id) ?? 0,
      };
    });

    fused.sort((a, b) => b.rrf - a.rrf);

    return fused.slice(0, k).map(({ row, rrf, bm25, dense }) => ({
      id:             row.id,
      filePath:       row.filePath,
      chunkType:      row.chunkType as ChunkType,
      language:       row.language,
      content:        row.content,
      startLine:      row.startLine,
      endLine:        row.endLine,
      similarityScore: rrf,
      denseScore:     dense,
      bm25Score:      bm25,
      rrfScore:       rrf,
    }));
  }

  // ─── Fallback: JSON cosine (for chunks indexed before pgvector migration) ──

  private async retrieveFallback(
    scanId: string,
    query: string,
    queryVec: number[],
    k: number,
    filter?: RetrievalFilter
  ): Promise<RetrievedChunk[]> {
    const db = getDB();

    const rawChunks = await db.repositoryChunk.findMany({ where: { scanId } });

    const filteredChunks = rawChunks.filter(chunk => {
      if (filter?.languages?.length && (!chunk.language || !filter.languages.includes(chunk.language))) return false;
      if (filter?.chunkTypes?.length && !filter.chunkTypes.includes(chunk.chunkType as ChunkType)) return false;
      return true;
    });

    if (filteredChunks.length === 0) return [];

    const bm25Scores = this.computeBM25(query, filteredChunks);

    const denseScores = new Map<string, number>();
    for (const chunk of filteredChunks) {
      if (chunk.embeddingJson) {
        try {
          const vec = JSON.parse(chunk.embeddingJson) as number[];
          let dot = 0, na = 0, nb = 0;
          for (let i = 0; i < queryVec.length; i++) {
            dot += queryVec[i]! * vec[i]!;
            na  += queryVec[i]! ** 2;
            nb  += vec[i]! ** 2;
          }
          const denom = Math.sqrt(na) * Math.sqrt(nb);
          denseScores.set(chunk.id, denom === 0 ? 0 : dot / denom);
        } catch { /* skip */ }
      }
    }

    const bm25Ranked  = [...bm25Scores.entries()].sort((a, b) => b[1] - a[1]);
    const denseRanked = [...denseScores.entries()].sort((a, b) => b[1] - a[1]);
    const bm25RankMap  = new Map(bm25Ranked.map(([id], i)  => [id, i + 1]));
    const denseRankMap = new Map(denseRanked.map(([id], i) => [id, i + 1]));

    const fused = filteredChunks.map(chunk => {
      const bm25Rank  = bm25RankMap.get(chunk.id)  ?? (filteredChunks.length + 1);
      const denseRank = denseRankMap.get(chunk.id) ?? (filteredChunks.length + 1);
      const rrf = (1 / (RRF_K + bm25Rank)) + (denseScores.size > 0 ? (1 / (RRF_K + denseRank)) : 0);
      return { chunk, rrf, bm25: bm25Scores.get(chunk.id) ?? 0, dense: denseScores.get(chunk.id) ?? 0 };
    });

    fused.sort((a, b) => b.rrf - a.rrf);

    return fused.slice(0, k).map(({ chunk, rrf, bm25, dense }) => ({
      id:             chunk.id,
      filePath:       chunk.filePath,
      chunkType:      chunk.chunkType as ChunkType,
      language:       chunk.language,
      content:        chunk.content,
      startLine:      chunk.startLine,
      endLine:        chunk.endLine,
      similarityScore: rrf,
      denseScore:     dense,
      bm25Score:      bm25,
      rrfScore:       rrf,
    }));
  }

  // ─── BM25 implementation ─────────────────────────────────────────────────────

  private computeBM25(
    query: string,
    chunks: Array<{ id: string; content: string }>
  ): Map<string, number> {
    const scores      = new Map<string, number>();
    const queryTokens = tokenize(query);
    if (queryTokens.length === 0 || chunks.length === 0) return scores;

    const docTokens = new Map<string, string[]>();
    const docFreqs  = new Map<string, number>();
    let totalLength = 0;

    for (const chunk of chunks) {
      const tokens = tokenize(chunk.content);
      docTokens.set(chunk.id, tokens);
      totalLength += tokens.length;
      for (const token of new Set(tokens)) {
        docFreqs.set(token, (docFreqs.get(token) ?? 0) + 1);
      }
    }

    const avgdl = totalLength / chunks.length;
    const N     = chunks.length;

    for (const chunk of chunks) {
      const tokens = docTokens.get(chunk.id) ?? [];
      const docLen = tokens.length;
      const tfMap  = new Map<string, number>();
      for (const t of tokens) tfMap.set(t, (tfMap.get(t) ?? 0) + 1);

      let score = 0;
      for (const qToken of queryTokens) {
        const tf = tfMap.get(qToken) ?? 0;
        if (tf === 0) continue;
        const df  = docFreqs.get(qToken) ?? 0;
        const idf = Math.log((N - df + 0.5) / (df + 0.5) + 1.0);
        const num = tf * (BM25_K1 + 1.0);
        const den = tf + BM25_K1 * (1.0 - BM25_B + BM25_B * (docLen / avgdl));
        score += idf * (num / den);
      }
      scores.set(chunk.id, Math.max(0, score));
    }

    return scores;
  }

  // ─── Evaluation helper ───────────────────────────────────────────────────────

  async computeMeanSimilarity(scanId: string, queries: string[], k = 5): Promise<number> {
    if (queries.length === 0) return 0;
    const scores: number[] = [];

    for (const query of queries.slice(0, 10)) {
      const results = await this.retrieve(scanId, query, k);
      if (results.length > 0) {
        scores.push(results.reduce((s, r) => s + r.similarityScore, 0) / results.length);
      }
    }

    return scores.length > 0 ? scores.reduce((s, v) => s + v, 0) / scores.length : 0;
  }
}
