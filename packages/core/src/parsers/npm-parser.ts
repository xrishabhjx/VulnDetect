import type { ManifestParser, ParsedDependency } from "../types.js";

/**
 * Parser for npm package.json files.
 * Extracts dependencies and devDependencies with their pinned versions.
 */
export class NpmParser implements ManifestParser {
  ecosystem = "npm" as const;
  supportedFiles = ["package.json"];

  canParse(filename: string): boolean {
    return filename.endsWith("package.json");
  }

  parse(content: string, filepath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];

    try {
      const pkg = JSON.parse(content);

      // Extract regular dependencies
      if (pkg.dependencies && typeof pkg.dependencies === "object") {
        for (const [name, version] of Object.entries(pkg.dependencies)) {
          if (typeof version === "string") {
            deps.push({
              name,
              version: this.cleanVersion(version),
              ecosystem: "npm",
              isDev: false,
              manifestPath: filepath,
            });
          }
        }
      }

      // Extract dev dependencies
      if (pkg.devDependencies && typeof pkg.devDependencies === "object") {
        for (const [name, version] of Object.entries(pkg.devDependencies)) {
          if (typeof version === "string") {
            deps.push({
              name,
              version: this.cleanVersion(version),
              ecosystem: "npm",
              isDev: true,
              manifestPath: filepath,
            });
          }
        }
      }
    } catch (error) {
      console.error(`Failed to parse ${filepath}:`, error);
    }

    return deps;
  }

  /**
   * Clean version strings by removing range specifiers.
   * "^1.2.3" → "1.2.3", "~2.0.0" → "2.0.0", ">=3.0.0" → "3.0.0"
   */
  private cleanVersion(version: string): string {
    return version.replace(/^[\^~>=<]*\s*/, "").trim();
  }
}
