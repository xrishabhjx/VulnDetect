import { describe, it, expect } from "vitest";
import { collectManifestPathsFromTree } from "../src/github/client.js";

describe("collectManifestPathsFromTree", () => {
  it("finds manifests in nested directories", () => {
    const tree = [
      { path: "mobile/package.json", type: "blob" as const },
      { path: "web/package.json", type: "blob" as const },
      { path: "README.md", type: "blob" as const },
    ];

    const manifests = collectManifestPathsFromTree(tree);

    expect(manifests).toEqual(["mobile/package.json", "web/package.json"]);
  });

  it("ignores non-manifest files", () => {
    const tree = [
      { path: "src/index.ts", type: "blob" as const },
      { path: "package-lock.json", type: "blob" as const },
      { path: "requirements-dev.txt", type: "blob" as const },
    ];

    const manifests = collectManifestPathsFromTree(tree);

    expect(manifests).toEqual(["requirements-dev.txt"]);
  });
});
