import type { ManifestParser, ParsedDependency } from "../types.js";

/**
 * Parser for Python requirements.txt and Pipfile files.
 * Handles various version specifier formats: ==, >=, ~=, etc.
 */
export class PythonParser implements ManifestParser {
  ecosystem = "pypi" as const;
  supportedFiles = ["requirements.txt", "requirements-dev.txt", "requirements_dev.txt"];

  canParse(filename: string): boolean {
    const basename = filename.split("/").pop() || "";
    return (
      basename === "requirements.txt" ||
      basename === "requirements-dev.txt" ||
      basename === "requirements_dev.txt" ||
      basename === "Pipfile" || basename === "Pipfile.lock"
    );
  }

  parse(content: string, filepath: string): ParsedDependency[] {
    const basename = (filepath.split("/").pop() || "").toLowerCase();

    if (basename === "pipfile") {
      return this.parsePipfile(content, filepath);
    }
    if (basename === "pipfile.lock") return this.parsePipfileLock(content, filepath);

    return this.parseRequirements(content, filepath);
  }

  private parsePipfileLock(content: string, filepath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];
    try {
      const lockfile = JSON.parse(content) as Record<string, Record<string, { version?: string }>>;
      for (const [section, packages] of Object.entries(lockfile)) {
        if (section !== "default" && section !== "develop") continue;
        for (const [name, entry] of Object.entries(packages ?? {})) {
          const declared = entry?.version ?? "";
          const version = declared.match(/^==\s*(\d+(?:\.\d+)+(?:[.-][0-9A-Za-z.-]+)?)$/)?.[1];
          if (version) deps.push({ name: this.normalizePyPIName(name), version, ecosystem: "pypi", isDev: section === "develop", manifestPath: filepath });
        }
      }
    } catch (error) {
      console.error(`Failed to parse ${filepath}:`, error);
    }
    return deps;
  }

  /**
   * Parse requirements.txt format:
   * flask==2.0.1
   * requests>=2.25.0
   * numpy~=1.21
   * django  # latest
   */
  private parseRequirements(
    content: string,
    filepath: string
  ): ParsedDependency[] {
    const deps: ParsedDependency[] = [];
    const isDev = filepath.includes("dev");

    const lines = content.split("\n");

    for (const rawLine of lines) {
      // Remove comments and trim
      const line = rawLine.split("#")[0].trim();

      // Skip empty lines, comments, options, and file references
      if (!line || line.startsWith("-") || line.startsWith("git+")) continue;

      // Parse package name and version
      // Patterns: pkg==1.0, pkg>=1.0, pkg~=1.0, pkg!=1.0, pkg<=1.0, pkg<1.0, pkg>1.0
      const match = line.match(
        /^([a-zA-Z0-9._-]+)\s*(?:\[.*?\])?\s*([=<>!~]+)\s*(.+?)$/
      );

      if (match) {
        const declaredVersion = match[3].trim().split(",")[0].trim();
        const isExact = match[2] === "==" && /^\d+(?:\.\d+)+(?:[.-][0-9A-Za-z.-]+)?$/.test(declaredVersion);
        deps.push({
          name: this.normalizePyPIName(match[1]),
          version: isExact ? declaredVersion : "UNKNOWN",
          versionSpec: `${match[2]}${match[3].trim()}`,
          ecosystem: "pypi",
          isDev,
          manifestPath: filepath,
        });
      } else if (line.match(/^[a-zA-Z0-9._-]+$/)) {
        // Package name without version
        deps.push({
          name: this.normalizePyPIName(line),
          version: "latest",
          ecosystem: "pypi",
          isDev,
          manifestPath: filepath,
        });
      }
    }

    return deps;
  }

  /**
   * Basic Pipfile parser — extracts from [packages] and [dev-packages] sections.
   */
  private parsePipfile(
    content: string,
    filepath: string
  ): ParsedDependency[] {
    const deps: ParsedDependency[] = [];
    let currentSection: "packages" | "dev-packages" | null = null;

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();

      if (line === "[packages]") {
        currentSection = "packages";
        continue;
      } else if (line === "[dev-packages]") {
        currentSection = "dev-packages";
        continue;
      } else if (line.startsWith("[")) {
        currentSection = null;
        continue;
      }

      if (!currentSection || !line || line.startsWith("#")) continue;

      const match = line.match(/^([a-zA-Z0-9._-]+)\s*=\s*"(.+)"$/);
      if (match) {
        const declaredVersion = match[2];
        const isExact = declaredVersion !== "*" && /^=\s*\d+(?:\.\d+)+(?:[.-][0-9A-Za-z.-]+)?$/.test(declaredVersion);
        const version = isExact ? declaredVersion.replace(/^=\s*/, "") : "UNKNOWN";
        deps.push({
          name: this.normalizePyPIName(match[1]),
          version,
          versionSpec: declaredVersion,
          ecosystem: "pypi",
          isDev: currentSection === "dev-packages",
          manifestPath: filepath,
        });
      }
    }

    return deps;
  }

  /**
   * Normalize PyPI package names (PEP 503):
   * Convert to lowercase, replace underscores/dots with hyphens.
   */
  private normalizePyPIName(name: string): string {
    return name.toLowerCase().replace(/[_.]+/g, "-");
  }
}
