import type { ManifestParser, ParsedDependency } from "../types.js";
import { parse as parseYaml } from "yaml";

/**
 * Parser for npm package.json files.
 * Extracts dependencies and devDependencies with their pinned versions.
 */
export class NpmParser implements ManifestParser {
  ecosystem = "npm" as const;
  supportedFiles = ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"];

  canParse(filename: string): boolean {
    return filename.endsWith("package.json") || filename.endsWith("package-lock.json") || filename.endsWith("pnpm-lock.yaml") || filename.endsWith("yarn.lock");
  }

  parse(content: string, filepath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];

    try {
      if (filepath.endsWith("yarn.lock")) return this.parseYarnLock(content, filepath);
      const pkg = filepath.endsWith("pnpm-lock.yaml") ? parseYaml(content) : JSON.parse(content);

      if (filepath.endsWith("package-lock.json") || filepath.endsWith("pnpm-lock.yaml")) {
        return this.parseLockfile(pkg, filepath);
      }

      // Extract regular dependencies
      if (pkg.dependencies && typeof pkg.dependencies === "object") {
        for (const [name, version] of Object.entries(pkg.dependencies)) {
          if (typeof version === "string") {
            const resolvedVersion = this.cleanVersion(version);
            deps.push({
              name,
              version: this.isExactVersion(version.trim()) ? resolvedVersion : "UNKNOWN",
              versionSpec: version,
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
            const resolvedVersion = this.cleanVersion(version);
            deps.push({
              name,
              version: this.isExactVersion(version.trim()) ? resolvedVersion : "UNKNOWN",
              versionSpec: version,
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

  private parseYarnLock(content: string, filepath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];
    let names: string[] = [];
    for (const line of content.split("\n")) {
      const header = line.match(/^(.+):$/);
      if (header && !line.startsWith(" ")) {
        names = header[1].split(",").map((entry) => entry.trim().replace(/^['"]|['"]$/g, ""))
          .map((entry) => entry.slice(0, entry.lastIndexOf("@")))
          .filter(Boolean);
        continue;
      }
      const version = line.match(/^\s+version\s+["']([^"']+)["']/)?.[1];
      if (!version) continue;
      for (const name of names) {
        deps.push({ name, version, ecosystem: "npm", isDev: false, manifestPath: filepath });
      }
      names = [];
    }
    return deps;
  }

  private parseLockfile(pkg: unknown, filepath: string): ParsedDependency[] {
    if (!pkg || typeof pkg !== "object") return [];
    const lockfile = pkg as {
      packages?: Record<string, { name?: string; version?: string; dev?: boolean }>;
      dependencies?: Record<string, { version?: string; dev?: boolean }>;
    };
    const deps: ParsedDependency[] = [];

    if (filepath.endsWith("pnpm-lock.yaml")) {
      const lockfile = pkg as {
        importers?: Record<string, { dependencies?: Record<string, { version?: string }>; devDependencies?: Record<string, { version?: string }> }>;
        packages?: Record<string, unknown>;
      };
      const resolved = new Map<string, string>();
      for (const importer of Object.values(lockfile.importers ?? {})) {
        for (const section of [importer.dependencies, importer.devDependencies]) {
          for (const [name, entry] of Object.entries(section ?? {})) {
            const version = entry?.version?.split("(")[0];
            if (version && !version.startsWith("link:")) resolved.set(name, version);
          }
        }
      }
      for (const [name, version] of resolved) {
        deps.push({ name, version, ecosystem: "npm", isDev: false, manifestPath: filepath });
      }
      return deps;
    }

    if (lockfile.packages) {
      for (const [location, entry] of Object.entries(lockfile.packages)) {
        if (!location || !entry?.version) continue;
        const name = entry.name ?? this.packageNameFromLockPath(location);
        if (!name) continue;
        deps.push({
          name,
          version: entry.version,
          ecosystem: "npm",
          isDev: Boolean(entry.dev),
          manifestPath: filepath,
        });
      }
    } else if (lockfile.dependencies) {
      for (const [name, entry] of Object.entries(lockfile.dependencies)) {
        if (!entry?.version) continue;
        deps.push({
          name,
          version: entry.version,
          ecosystem: "npm",
          isDev: Boolean(entry.dev),
          manifestPath: filepath,
        });
      }
    }

    return deps;
  }

  private packageNameFromLockPath(location: string): string | null {
    const name = location.replace(/^.*(?:^|\/)node_modules\//, "");
    if (!name) return null;
    if (name.startsWith("@")) {
      const scopedParts = name.split("/");
      return scopedParts.length >= 2 ? scopedParts.slice(0, 2).join("/") : null;
    }
    return name.split("/")[0] || null;
  }

  /**
   * Clean version strings by removing range specifiers.
   * "^1.2.3" → "1.2.3", "~2.0.0" → "2.0.0", ">=3.0.0" → "3.0.0"
   */
  private cleanVersion(version: string): string {
    return version.replace(/^[\^~>=<]*\s*/, "").trim();
  }

  private isExactVersion(version: string): boolean {
    return /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version);
  }
}
