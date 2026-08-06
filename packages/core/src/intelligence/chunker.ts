import type { RepoChunk, ChunkType } from "../types.js";
import { GitHubClient } from "../github/index.js";

// ─── Language Detection ──────────────────────────────────────────────────────

const EXTENSION_LANGUAGE_MAP: Record<string, string> = {
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".py": "python",
  ".java": "java",
  ".go": "go",
  ".rs": "rust",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".cpp": "cpp",
  ".c": "c",
  ".md": "markdown",
  ".json": "json",
  ".yaml": "yaml",
  ".yml": "yaml",
  ".toml": "toml",
  ".env": "config",
  ".sh": "shell",
};

const TEXT_EXTENSIONS = new Set(Object.keys(EXTENSION_LANGUAGE_MAP));
const DOC_EXTENSIONS = new Set([".md", ".txt", ".rst"]);
const CONFIG_EXTENSIONS = new Set([".json", ".yaml", ".yml", ".toml", ".env"]);

// ─── Chunk Size Configuration ────────────────────────────────────────────────
/** Maximum characters per chunk (~ 512 tokens) */
const MAX_CHUNK_CHARS = 2048;
/** Overlap between adjacent window chunks (characters) */
const CHUNK_OVERLAP = 200;

// ─── Language-Specific Splitters ─────────────────────────────────────────────

/**
 * TypeScript/JavaScript function/class boundary splitter.
 * Finds top-level function declarations, arrow functions assigned to variables,
 * and class declarations.
 */
function splitTypeScript(content: string): Array<{ code: string; startLine: number; endLine: number; type: ChunkType }> {
  const lines = content.split("\n");
  const chunks: Array<{ code: string; startLine: number; endLine: number; type: ChunkType }> = [];

  const BOUNDARY = /^(export\s+)?(async\s+)?(function|class|const|let|var)\s+\w+/;
  let currentStart = 0;
  let currentLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isBoundary = BOUNDARY.test(line) && i > 0;

    if (isBoundary && currentLines.length > 0) {
      const code = currentLines.join("\n").trim();
      if (code.length > 10) {
        chunks.push({
          code,
          startLine: currentStart + 1,
          endLine: i,
          type: code.startsWith("class") || /^export\s+class/.test(code) ? "class" : "function",
        });
      }
      currentStart = i;
      currentLines = [line];
    } else {
      currentLines.push(line);
    }
  }

  // Push the last segment
  if (currentLines.length > 0) {
    const code = currentLines.join("\n").trim();
    if (code.length > 10) {
      chunks.push({
        code,
        startLine: currentStart + 1,
        endLine: lines.length,
        type: "module",
      });
    }
  }

  return chunks;
}

/**
 * Python def/class splitter.
 */
function splitPython(content: string): Array<{ code: string; startLine: number; endLine: number; type: ChunkType }> {
  const lines = content.split("\n");
  const chunks: Array<{ code: string; startLine: number; endLine: number; type: ChunkType }> = [];

  const BOUNDARY = /^(def |class |async def )/;
  let currentStart = 0;
  let currentLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isBoundary = BOUNDARY.test(line) && i > 0;

    if (isBoundary && currentLines.length > 0) {
      const code = currentLines.join("\n").trim();
      if (code.length > 10) {
        chunks.push({
          code,
          startLine: currentStart + 1,
          endLine: i,
          type: code.startsWith("class ") ? "class" : "function",
        });
      }
      currentStart = i;
      currentLines = [line];
    } else {
      currentLines.push(line);
    }
  }

  if (currentLines.length > 0) {
    const code = currentLines.join("\n").trim();
    if (code.length > 10) {
      chunks.push({ code, startLine: currentStart + 1, endLine: lines.length, type: "module" });
    }
  }

  return chunks;
}

/**
 * Fixed-window fallback chunker with overlap.
 * Used for languages without a specific splitter.
 */
function splitWindow(
  content: string,
  type: ChunkType
): Array<{ code: string; startLine: number; endLine: number; type: ChunkType }> {
  const chunks: Array<{ code: string; startLine: number; endLine: number; type: ChunkType }> = [];
  const lines = content.split("\n");

  let charCount = 0;
  let chunkStart = 0;
  let chunkLines: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    chunkLines.push(lines[i]);
    charCount += lines[i].length + 1;

    if (charCount >= MAX_CHUNK_CHARS) {
      chunks.push({
        code: chunkLines.join("\n").trim(),
        startLine: chunkStart + 1,
        endLine: i + 1,
        type,
      });

      // Apply overlap: keep last CHUNK_OVERLAP chars
      const overlap: string[] = [];
      let overlapChars = 0;
      for (let j = chunkLines.length - 1; j >= 0 && overlapChars < CHUNK_OVERLAP; j--) {
        overlap.unshift(chunkLines[j]);
        overlapChars += chunkLines[j].length;
      }
      chunkLines = overlap;
      chunkStart = i + 1 - overlap.length;
      charCount = overlapChars;
    }
  }

  if (chunkLines.length > 0) {
    const code = chunkLines.join("\n").trim();
    if (code.length > 10) {
      chunks.push({ code, startLine: chunkStart + 1, endLine: lines.length, type });
    }
  }

  return chunks;
}

// ─── Main Chunker ─────────────────────────────────────────────────────────────

/**
 * Semantically chunks repository source files.
 *
 * Strategy:
 * 1. Fetch up to 50 text files from the repo (prioritizes README, configs, entry points).
 * 2. For TypeScript/JS → function/class boundary splitting.
 * 3. For Python → def/class boundary splitting.
 * 4. For docs/config → fixed-window with overlap.
 * 5. Returns list of RepoChunk objects ready for embedding.
 */
export class RepoChunker {
  private github: GitHubClient;

  /** Max number of files to fetch from GitHub API (rate limit safety) */
  private readonly MAX_FILES = 50;

  constructor(githubToken?: string) {
    this.github = new GitHubClient(githubToken);
  }

  /**
   * Main entry point: fetches and chunks a repository.
   * Returns up to ~500 semantic chunks.
   */
  async chunkRepository(owner: string, repo: string): Promise<RepoChunk[]> {
    const tree = await this.github.getRepoTree(owner, repo);

    // Select files to process: prioritize by importance
    const filesToFetch = this.prioritizeFiles(tree);

    const chunks: RepoChunk[] = [];

    for (const file of filesToFetch) {
      try {
        const content = await this.github.getFileContent(owner, repo, file.path);
        const fileChunks = this.chunkFile(file.path, content);
        chunks.push(...fileChunks);
      } catch {
        // File might be too large, binary, or deleted — skip silently
      }
    }

    return chunks;
  }

  /**
   * Select and prioritize files to chunk.
   * Order: README → configs → entry points → source files (smallest first)
   */
  private prioritizeFiles(
    tree: Array<{ path: string; type: string; size?: number }>
  ): Array<{ path: string; size?: number }> {
    const blobs = tree.filter((n) => n.type === "blob");

    const priority: typeof blobs = [];
    const rest: typeof blobs = [];

    for (const node of blobs) {
      const name = node.path.toLowerCase();
      const ext = name.includes(".") ? "." + name.split(".").pop()! : "";

      if (!TEXT_EXTENSIONS.has(ext)) continue;  // skip non-text

      // High priority: README, package.json, entry points
      if (
        name.endsWith("readme.md") ||
        name === "package.json" ||
        name.endsWith("/index.ts") ||
        name.endsWith("/index.js") ||
        name.endsWith("/main.py") ||
        name.endsWith("/app.py") ||
        name.endsWith("/main.java") ||
        CONFIG_EXTENSIONS.has(ext)
      ) {
        priority.push(node);
      } else {
        rest.push(node);
      }
    }

    // Sort rest by size ascending (smaller files first = more complete coverage)
    rest.sort((a, b) => (a.size ?? 0) - (b.size ?? 0));

    return [...priority, ...rest].slice(0, this.MAX_FILES);
  }

  /**
   * Chunk a single file's content based on its language.
   */
  private chunkFile(filePath: string, content: string): RepoChunk[] {
    const ext = filePath.includes(".")
      ? "." + filePath.split(".").pop()!
      : "";
    const language = EXTENSION_LANGUAGE_MAP[ext.toLowerCase()] ?? null;

    // Detect chunk type from extension
    const isDoc = DOC_EXTENSIONS.has(ext.toLowerCase());
    const isConfig = CONFIG_EXTENSIONS.has(ext.toLowerCase());
    const baseType: ChunkType = isDoc ? "documentation" : isConfig ? "config" : "module";

    // Apply language-specific splitter
    let rawChunks: Array<{ code: string; startLine: number; endLine: number; type: ChunkType }>;

    if (language === "typescript" || language === "javascript") {
      rawChunks = splitTypeScript(content);
    } else if (language === "python") {
      rawChunks = splitPython(content);
    } else {
      rawChunks = splitWindow(content, baseType);
    }

    // Post-process: enforce MAX_CHUNK_CHARS, build RepoChunk objects
    return rawChunks
      .filter((c) => c.code.length > 20)
      .flatMap((c) => {
        if (c.code.length <= MAX_CHUNK_CHARS) {
          return [{
            filePath,
            chunkType: c.type,
            language,
            content: c.code,
            startLine: c.startLine,
            endLine: c.endLine,
          } satisfies RepoChunk];
        }
        // Over-large chunk: re-split with window
        return splitWindow(c.code, c.type).map((w) => ({
          filePath,
          chunkType: w.type,
          language,
          content: w.code,
          startLine: c.startLine + w.startLine - 1,
          endLine: c.startLine + w.endLine - 1,
        } satisfies RepoChunk));
      });
  }
}
