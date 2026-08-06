import type { Ecosystem, RepositoryMetadata, RepositoryProfile, FolderNode } from "../types.js";
import { GitHubClient } from "../github/index.js";

// ─── Framework Detection Heuristics ─────────────────────────────────────────

const FRAMEWORK_SIGNALS: Array<{ pattern: string | RegExp; framework: string }> = [
  { pattern: /\"express\"/, framework: "express" },
  { pattern: /\"fastify\"/, framework: "fastify" },
  { pattern: /\"next\"/, framework: "next.js" },
  { pattern: /\"react\"/, framework: "react" },
  { pattern: /\"vue\"/, framework: "vue" },
  { pattern: /\"angular\/core\"/, framework: "angular" },
  { pattern: /\"django\"/, framework: "django" },
  { pattern: /\"flask\"/, framework: "flask" },
  { pattern: /\"fastapi\"/, framework: "fastapi" },
  { pattern: /spring-boot/, framework: "spring-boot" },
  { pattern: /\"nest\"/, framework: "nest.js" },
  { pattern: /\"hono\"/, framework: "hono" },
];

const CI_FILES = new Set([
  ".github/workflows",
  ".gitlab-ci.yml",
  "Jenkinsfile",
  "circle.yml",
  ".circleci",
  "azure-pipelines.yml",
  ".travis.yml",
]);

const TEST_PATTERNS = [
  /\/__tests__\//,
  /\.test\.(ts|js|py|java)$/,
  /\.spec\.(ts|js|py|java)$/,
  /\/test\//,
  /\/tests\//,
];

// ─── Architecture Pattern Detection ─────────────────────────────────────────

function detectArchitecture(tree: FolderNode[], framework: string | null): string | null {
  const paths = tree.map(n => n.path.toLowerCase());
  const dirs = new Set(paths.filter(p => !p.includes(".")));

  if (paths.some(p => p.includes("docker-compose") || p.includes("kubernetes") || p.includes("k8s"))) {
    return "microservices";
  }
  if (dirs.has("src/controllers") || dirs.has("src/routes") || dirs.has("src/models") || dirs.has("controllers") || dirs.has("models")) {
    return "MVC";
  }
  if (dirs.has("packages") || dirs.has("apps") || dirs.has("libs")) {
    return "monorepo";
  }
  if (dirs.has("src/layers") || dirs.has("src/domain") || dirs.has("src/infrastructure") || dirs.has("src/application")) {
    return "layered";
  }
  if (framework && (framework === "next.js" || framework === "react" || framework === "vue" || framework === "angular")) {
    return "SPA/SSR";
  }
  return "monolith";
}

function detectRepositoryType(
  framework: string | null,
  tree: FolderNode[],
  packageJson: string
): RepositoryProfile["repositoryType"] {
  const paths = tree.map(n => n.path.toLowerCase());
  if (paths.some(p => p.includes("packages/") || p.includes("apps/") || p.includes("libs/"))) return "monorepo";
  if (packageJson.includes('"bin"')) return "cli";
  if (packageJson.includes('"main"') && !packageJson.includes('"scripts"')) return "library";
  if (framework && ["react", "vue", "angular", "next.js", "svelte"].includes(framework)) return "web-app";
  if (framework && ["express", "fastify", "hono", "nest.js", "django", "flask", "fastapi", "spring-boot"].includes(framework)) return "api";
  if (paths.some(p => p.includes("notebook") || p.endsWith(".ipynb") || p.includes("dataset"))) return "data";
  return "unknown";
}

function detectDatabase(packageJson: string, readme: string): string | null {
  const combined = packageJson + " " + readme;
  if (/pg|postgres|postgresql/i.test(combined)) return "postgresql";
  if (/mysql|mariadb/i.test(combined)) return "mysql";
  if (/mongodb|mongoose/i.test(combined)) return "mongodb";
  if (/sqlite/i.test(combined)) return "sqlite";
  if (/redis/i.test(combined)) return "redis";
  if (/cassandra/i.test(combined)) return "cassandra";
  if (/dynamodb/i.test(combined)) return "dynamodb";
  return null;
}

function detectORM(packageJson: string): string | null {
  if (/\"prisma\"/i.test(packageJson)) return "prisma";
  if (/\"sequelize\"/i.test(packageJson)) return "sequelize";
  if (/\"typeorm\"/i.test(packageJson)) return "typeorm";
  if (/\"mongoose\"/i.test(packageJson)) return "mongoose";
  if (/\"knex\"/i.test(packageJson)) return "knex";
  if (/\"drizzle-orm\"/i.test(packageJson)) return "drizzle";
  if (/sqlalchemy/i.test(packageJson)) return "sqlalchemy";
  if (/hibernate/i.test(packageJson)) return "hibernate";
  return null;
}

function detectAuthentication(packageJson: string, readme: string): string | null {
  const combined = packageJson + " " + readme;
  if (/jsonwebtoken|jose|jwt/i.test(combined)) return "jwt";
  if (/passport/i.test(combined)) return "passport";
  if (/oauth2?|\"@auth\//i.test(combined)) return "oauth2";
  if (/session|express-session/i.test(combined)) return "session";
  if (/\"next-auth\"/i.test(combined)) return "nextauth";
  if (/\"lucia\"/i.test(combined)) return "lucia";
  return null;
}

function detectDeployment(tree: FolderNode[], readme: string, packageJson: string): string | null {
  const paths = tree.map(n => n.path.toLowerCase());
  const combined = readme + " " + packageJson;
  if (paths.some(p => p === "dockerfile" || p.includes("docker-compose"))) return "docker";
  if (paths.some(p => p.includes("kubernetes") || p.includes("k8s") || p.endsWith(".helm"))) return "kubernetes";
  if (paths.some(p => p.includes("vercel.json") || p === ".vercelignore")) return "vercel";
  if (paths.some(p => p.includes("netlify.toml"))) return "netlify";
  if (paths.some(p => p.includes("app.yaml") || p.includes("app.json"))) return "heroku";
  if (/aws|lambda|sam|cdk|cloudformation/i.test(combined)) return "aws";
  if (/render\.com/i.test(combined)) return "render";
  if (/railway\.app/i.test(combined)) return "railway";
  return null;
}

function detectCiCdPlatform(tree: FolderNode[]): string | null {
  const paths = tree.map(n => n.path.toLowerCase());
  if (paths.some(p => p.startsWith(".github/workflows"))) return "github-actions";
  if (paths.some(p => p.includes(".gitlab-ci"))) return "gitlab-ci";
  if (paths.some(p => p.includes("jenkinsfile"))) return "jenkins";
  if (paths.some(p => p.includes(".circleci"))) return "circleci";
  if (paths.some(p => p.includes("azure-pipelines"))) return "azure-devops";
  if (paths.some(p => p.includes(".travis"))) return "travis-ci";
  return null;
}

function detectTestingFramework(packageJson: string): string | null {
  if (/\"vitest\"/i.test(packageJson)) return "vitest";
  if (/\"jest\"/i.test(packageJson)) return "jest";
  if (/\"mocha\"/i.test(packageJson)) return "mocha";
  if (/\"jasmine\"/i.test(packageJson)) return "jasmine";
  if (/pytest/i.test(packageJson)) return "pytest";
  if (/junit/i.test(packageJson)) return "junit";
  if (/rspec/i.test(packageJson)) return "rspec";
  if (/\"@playwright\/test\"/i.test(packageJson)) return "playwright";
  if (/\"cypress\"/i.test(packageJson)) return "cypress";
  return null;
}

function detectPackageManagers(tree: FolderNode[]): string[] {
  const paths = new Set(tree.map(n => n.path.toLowerCase()));
  const managers: string[] = [];
  if (paths.has("pnpm-lock.yaml") || paths.has("pnpm-workspace.yaml")) managers.push("pnpm");
  else if (paths.has("yarn.lock")) managers.push("yarn");
  else if (paths.has("package-lock.json") || paths.has("package.json")) managers.push("npm");
  if (paths.has("requirements.txt") || paths.has("pyproject.toml") || paths.has("poetry.lock")) managers.push("pip/poetry");
  if (paths.has("pom.xml")) managers.push("maven");
  if (paths.has("build.gradle") || paths.has("build.gradle.kts")) managers.push("gradle");
  if (paths.has("cargo.toml")) managers.push("cargo");
  if (paths.has("go.mod")) managers.push("go-modules");
  return managers;
}

function extractPrimaryDependencies(packageJson: string): string[] {
  try {
    const parsed = JSON.parse(packageJson) as {
      dependencies?: Record<string, string>;
    };
    return Object.keys(parsed.dependencies ?? {}).slice(0, 20);
  } catch {
    return [];
  }
}

// ─── Repository Understander ─────────────────────────────────────────────────

/**
 * Understands a GitHub repository's purpose, structure, and characteristics.
 *
 * Produces a RepositoryProfile — a superset of RepositoryMetadata that includes
 * architecture pattern, deployment platform, ORM, auth mechanism, and more.
 *
 * This profile becomes the global context passed to every downstream module.
 * No LLM is used here — all detection is deterministic signal-based heuristics.
 */
export class RepoUnderstander {
  private github: GitHubClient;

  constructor(githubToken?: string) {
    this.github = new GitHubClient(githubToken);
  }

  /**
   * Main entry point: produces a full RepositoryProfile from GitHub signals.
   * RepositoryProfile extends RepositoryMetadata — fully backward compatible.
   */
  async understand(owner: string, repo: string): Promise<RepositoryProfile> {
    // Fetch all data sources in parallel for speed
    const [rawMeta, languages, tree] = await Promise.all([
      this.github.getRepoMetadata(owner, repo),
      this.github.getLanguages(owner, repo),
      this.github.getRepoTree(owner, repo),
    ]);

    // Fetch README and package.json for heuristic detection (best-effort)
    let readmeContent = "";
    let packageJsonContent = "";
    try {
      readmeContent = await this.github.getFileContent(owner, repo, "README.md");
    } catch {
      try {
        readmeContent = await this.github.getFileContent(owner, repo, "readme.md");
      } catch { /* no README — that's ok */ }
    }
    try {
      packageJsonContent = await this.github.getFileContent(owner, repo, "package.json");
    } catch { /* not a Node.js project */ }

    const topLevelDirs = this.extractTopLevelDirs(tree);
    const primaryLanguage = (rawMeta.language as string | null) ?? null;
    const framework = this.detectFramework(packageJsonContent, primaryLanguage);
    const architecture = detectArchitecture(tree, framework);

    return {
      // ── RepositoryMetadata fields ──────────────────────────────────────────
      language: primaryLanguage,
      languages,
      framework,
      purpose: this.extractPurpose(
        (rawMeta.description as string | null) ?? null,
        readmeContent
      ),
      topics: (rawMeta.topics as string[]) ?? [],
      description: (rawMeta.description as string | null) ?? null,
      folderHierarchy: topLevelDirs,
      totalFiles: tree.filter((n) => n.type === "blob").length,
      hasDockerfile: tree.some(
        (n) => n.path === "Dockerfile" || n.path === "docker-compose.yml"
      ),
      hasCiCd: tree.some((n) =>
        [...CI_FILES].some((ci) => n.path.includes(ci))
      ),
      hasTests: tree.some((n) => TEST_PATTERNS.some((p) => p.test(n.path))),
      stars: (rawMeta.stargazers_count as number) ?? 0,
      forks: (rawMeta.forks_count as number) ?? 0,
      openIssues: (rawMeta.open_issues_count as number) ?? 0,
      lastPushed: (rawMeta.pushed_at as string | null) ?? null,

      // ── RepositoryProfile extended fields ─────────────────────────────────
      architecture,
      repositoryType: detectRepositoryType(framework, tree, packageJsonContent),
      database: detectDatabase(packageJsonContent, readmeContent),
      orm: detectORM(packageJsonContent),
      authentication: detectAuthentication(packageJsonContent, readmeContent),
      deployment: detectDeployment(tree, readmeContent, packageJsonContent),
      ciCdPlatform: detectCiCdPlatform(tree),
      testingFramework: detectTestingFramework(packageJsonContent),
      packageManagers: detectPackageManagers(tree),
      primaryDependencies: extractPrimaryDependencies(packageJsonContent),
    };
  }

  /**
   * Extract top-level directory structure for the hierarchy field.
   */
  private extractTopLevelDirs(tree: FolderNode[]): FolderNode[] {
    const topLevel = new Map<string, FolderNode>();

    for (const node of tree) {
      const parts = node.path.split("/");
      const top = parts[0];
      if (!topLevel.has(top)) {
        topLevel.set(top, {
          path: top,
          type: parts.length === 1 && node.type === "blob" ? "blob" : "tree",
        });
      }
    }

    return Array.from(topLevel.values()).slice(0, 30);
  }

  /**
   * Detect the primary framework from package.json content or language signals.
   */
  private detectFramework(packageJson: string, language: string | null): string | null {
    if (packageJson) {
      for (const { pattern, framework } of FRAMEWORK_SIGNALS) {
        if (typeof pattern === "string") {
          if (packageJson.includes(pattern)) return framework;
        } else {
          if (pattern.test(packageJson)) return framework;
        }
      }
    }

    if (language === "Python") return "python";
    if (language === "Java") return "java";
    if (language === "Go") return "go";

    return null;
  }

  /**
   * Extract a concise purpose statement from the repo description and README.
   */
  private extractPurpose(description: string | null, readme: string): string | null {
    if (readme) {
      // Remove markdown headers, badges, and HTML
      const cleaned = readme
        .replace(/!\[.*?\]\(.*?\)/g, "")   // images
        .replace(/\[![.*?]\(.*?\)]\(.*?\)/g, "")  // badge links
        .replace(/<[^>]+>/g, "")            // HTML tags
        .replace(/^#+\s.+$/gm, "")         // headers
        .replace(/\n{3,}/g, "\n\n")        // excessive newlines
        .trim();

      // Find the first non-empty paragraph (>30 chars)
      const paragraphs = cleaned
        .split(/\n\n+/)
        .map((p) => p.replace(/\n/g, " ").trim())
        .filter((p) => p.length > 30);

      if (paragraphs.length > 0) {
        return paragraphs[0].substring(0, 500);
      }
    }

    return description;
  }
}
