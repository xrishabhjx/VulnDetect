import { Octokit } from "octokit";
import { MANIFEST_FILENAMES } from "../parsers/index.js";
import type { ManifestFile, Ecosystem, FolderNode } from "../types.js";

export function collectManifestPathsFromTree(tree: FolderNode[]): string[] {
  return tree
    .filter((node) => node.type === "blob")
    .map((node) => node.path)
    .filter((path) => MANIFEST_FILENAMES.includes(path.split("/").pop() || ""));
}

/**
 * GitHub API client for fetching repository contents and manifest files.
 */
export class GitHubClient {
  private octokit: Octokit;

  constructor(token?: string) {
    this.octokit = new Octokit({
      auth: token || process.env.GITHUB_TOKEN,
    });
  }

  /**
   * Parse a GitHub URL into owner and repo name.
   * Supports: https://github.com/owner/repo, github.com/owner/repo, owner/repo
   */
  parseRepoUrl(repoUrl: string): { owner: string; repo: string } {
    // Remove trailing slashes and .git suffix
    const cleaned = repoUrl.replace(/\/+$/, "").replace(/\.git$/, "");

    // Try to extract owner/repo from URL
    const urlMatch = cleaned.match(
      /(?:github\.com\/|^)([a-zA-Z0-9._-]+)\/([a-zA-Z0-9._-]+)$/
    );

    if (!urlMatch) {
      throw new Error(
        `Invalid GitHub URL: ${repoUrl}. Expected format: https://github.com/owner/repo`
      );
    }

    return { owner: urlMatch[1], repo: urlMatch[2] };
  }

  /**
   * Search the repository root and common subdirectories for manifest files.
   * Returns a list of paths that match known manifest filenames.
   */
  async detectManifests(owner: string, repo: string): Promise<string[]> {
    const foundPaths: string[] = [];

    try {
      const { data } = await this.octokit.rest.repos.getContent({
        owner,
        repo,
        path: "",
      });

      if (Array.isArray(data)) {
        for (const item of data) {
          if (
            item.type === "file" &&
            MANIFEST_FILENAMES.includes(item.name)
          ) {
            foundPaths.push(item.path);
          }
        }
      }
    } catch (error) {
      console.error(`Failed to list root directory for ${owner}/${repo}`);
    }

    try {
      const tree = await this.getRepoTree(owner, repo);
      const treeManifests = collectManifestPathsFromTree(tree);
      for (const manifestPath of treeManifests) {
        if (!foundPaths.includes(manifestPath)) {
          foundPaths.push(manifestPath);
        }
      }
    } catch (error) {
      console.warn(`Failed to inspect repository tree for ${owner}/${repo}:`, error);
    }

    return foundPaths;
  }

  /**
   * Fetch the raw content of a file from the repository.
   */
  async getFileContent(
    owner: string,
    repo: string,
    path: string
  ): Promise<string> {
    const { data } = await this.octokit.rest.repos.getContent({
      owner,
      repo,
      path,
      mediaType: { format: "raw" },
    });

    // When requesting raw format, data is the file content as a string
    return data as unknown as string;
  }

  /**
   * Detect the ecosystem for a given manifest filename.
   */
  private detectEcosystem(filename: string): Ecosystem {
    const basename = filename.split("/").pop() || filename;

    if (basename === "package.json") return "npm";
    if (basename === "pom.xml") return "maven";
    if (
      basename.startsWith("requirements") ||
      basename === "Pipfile"
    ) {
      return "pypi";
    }

    throw new Error(`Unknown manifest type: ${filename}`);
  }

  /**
   * Fetch all manifest files from a repository.
   * Main entry point — detects manifests, downloads them, returns structured data.
   */
  async fetchManifests(repoUrl: string): Promise<ManifestFile[]> {
    const { owner, repo } = this.parseRepoUrl(repoUrl);
    const manifestPaths = await this.detectManifests(owner, repo);

    const manifests: ManifestFile[] = [];

    for (const path of manifestPaths) {
      try {
        const content = await this.getFileContent(owner, repo, path);
        manifests.push({
          path,
          content,
          ecosystem: this.detectEcosystem(path),
        });
      } catch (error) {
        console.error(`Failed to fetch ${path}:`, error);
      }
    }

    return manifests;
  }

  // ─── Phase 2 Extensions ───────────────────────────────────────────────────

  /**
   * Fetch structured metadata for a repository from the GitHub REST API.
   * Used by the Repository Understanding Engine.
   *
   * Returns raw GitHub repo data including language, topics, description, stats.
   */
  async getRepoMetadata(owner: string, repo: string): Promise<Record<string, unknown>> {
    try {
      const { data } = await this.octokit.rest.repos.get({ owner, repo });
      return data as unknown as Record<string, unknown>;
    } catch (error) {
      console.warn(`[GitHubClient] Failed to fetch metadata for ${owner}/${repo}:`, error);
      return {};
    }
  }

  /**
   * Fetch the full recursive file tree of a repository without cloning.
   * Uses the Git Trees API with recursive=1.
   *
   * Returns a filtered list of FolderNodes (max 500 entries).
   * Skips binary-likely files (images, videos, compiled artifacts).
   */
  async getRepoTree(owner: string, repo: string): Promise<FolderNode[]> {
    const SKIP_EXTENSIONS = new Set([
      ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
      ".mp4", ".mov", ".avi", ".pdf", ".zip", ".tar", ".gz",
      ".class", ".jar", ".war", ".pyc", ".pyo", ".min.js", ".map",
      ".lock", // package-lock.json, pnpm-lock.yaml already parsed separately
    ]);

    const SKIP_DIRS = new Set([
      "node_modules", ".git", "dist", "build", ".next", "coverage",
      "__pycache__", ".venv", "venv", "target", ".mvn",
    ]);

    try {
      const { data } = await this.octokit.rest.git.getTree({
        owner,
        repo,
        tree_sha: "HEAD",
        recursive: "1",
      });

      if (data.truncated) {
        console.warn(`[GitHubClient] Tree truncated for ${owner}/${repo} — large repo`);
      }

      return (data.tree || [])
        .filter((node) => {
          const path = node.path || "";
          // Skip hidden dirs, build artifacts, binaries
          const parts = path.split("/");
          if (parts.some((p) => SKIP_DIRS.has(p) || p.startsWith("."))) return false;
          const ext = path.includes(".") ? "." + path.split(".").pop()! : "";
          if (SKIP_EXTENSIONS.has(ext.toLowerCase())) return false;
          return true;
        })
        .slice(0, 500)  // hard cap to avoid oversized payloads
        .map((node) => ({
          path: node.path || "",
          type: (node.type === "blob" ? "blob" : "tree") as "blob" | "tree",
          size: node.size ?? undefined,
        }));
    } catch (error) {
      console.warn(`[GitHubClient] Failed to fetch tree for ${owner}/${repo}:`, error);
      return [];
    }
  }

  /**
   * Fetch languages breakdown for a repository.
   * Returns { "TypeScript": 12345, "JavaScript": 4567, ... } (bytes)
   */
  async getLanguages(owner: string, repo: string): Promise<Record<string, number>> {
    try {
      const { data } = await this.octokit.rest.repos.listLanguages({ owner, repo });
      return data as Record<string, number>;
    } catch {
      return {};
    }
  }
}

