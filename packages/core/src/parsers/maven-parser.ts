import { XMLParser } from "fast-xml-parser";
import type { ManifestParser, ParsedDependency } from "../types.js";

/**
 * Parser for Maven pom.xml files.
 * Extracts <dependency> entries from both regular and dependency management sections.
 */
export class MavenParser implements ManifestParser {
  ecosystem = "maven" as const;
  supportedFiles = ["pom.xml"];

  canParse(filename: string): boolean {
    return filename.endsWith("pom.xml");
  }

  parse(content: string, filepath: string): ParsedDependency[] {
    const deps: ParsedDependency[] = [];

    try {
      const parser = new XMLParser({
        ignoreAttributes: false,
        isArray: (tagName) => tagName === "dependency",
      });

      const parsed = parser.parse(content);
      const project = parsed.project;

      if (!project) return deps;

      // Extract from <dependencies>
      const directDeps = project.dependencies?.dependency;
      if (directDeps) {
        this.extractDeps(directDeps, filepath, false, deps);
      }

      // Extract from <dependencyManagement><dependencies>
      const managedDeps =
        project.dependencyManagement?.dependencies?.dependency;
      if (managedDeps) {
        this.extractDeps(managedDeps, filepath, false, deps);
      }

      // Check for properties-based version resolution
      const properties = project.properties || {};

      // Resolve ${property} references in versions
      for (const dep of deps) {
        if (dep.version.startsWith("${") && dep.version.endsWith("}")) {
          const propName = dep.version.slice(2, -1);
          if (properties[propName]) {
            dep.version = String(properties[propName]);
          }
        }
      }
    } catch (error) {
      console.error(`Failed to parse ${filepath}:`, error);
    }

    return deps;
  }

  private extractDeps(
    rawDeps: any | any[],
    filepath: string,
    isDev: boolean,
    output: ParsedDependency[]
  ): void {
    const depList = Array.isArray(rawDeps) ? rawDeps : [rawDeps];

    for (const dep of depList) {
      if (!dep.groupId || !dep.artifactId) continue;

      const version = dep.version ? String(dep.version) : "UNKNOWN";
      const scope = dep.scope || "compile";

      output.push({
        name: `${dep.groupId}:${dep.artifactId}`,
        version,
        ecosystem: "maven",
        isDev: scope === "test" || scope === "provided",
        manifestPath: filepath,
      });
    }
  }
}
