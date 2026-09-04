import { NpmParser } from "./npm-parser.js";
import { MavenParser } from "./maven-parser.js";
import { PythonParser } from "./python-parser.js";
import type { ManifestParser, ParsedDependency } from "../types.js";

/**
 * Registry of all available manifest parsers.
 * Add new parsers here to support additional ecosystems.
 */
const parsers: ManifestParser[] = [
  new NpmParser(),
  new MavenParser(),
  new PythonParser(),
];

/**
 * Known manifest filenames we look for when scanning a repository.
 */
export const MANIFEST_FILENAMES = [
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "pom.xml",
  "requirements.txt",
  "requirements-dev.txt",
  "requirements_dev.txt",
  "Pipfile",
  "Pipfile.lock",
];

/**
 * Find the right parser for a given filename.
 */
export function getParserForFile(filename: string): ManifestParser | null {
  const basename = filename.split("/").pop() || filename;
  return parsers.find((p) => p.canParse(basename)) || null;
}

/**
 * Parse a manifest file and return its dependencies.
 */
export function parseManifest(
  content: string,
  filepath: string
): ParsedDependency[] {
  const parser = getParserForFile(filepath);
  if (!parser) {
    console.warn(`No parser found for: ${filepath}`);
    return [];
  }
  return parser.parse(content, filepath);
}

export { NpmParser, MavenParser, PythonParser };
export type { ManifestParser };
