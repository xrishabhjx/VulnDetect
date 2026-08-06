import type {
  RKGNode,
  RKGEdge,
  RKGEdgeType,
  RepositoryKnowledgeGraph,
  GraphContextPath,
  DependencyScanResult,
  UnifiedVulnerability,
  RepoChunk,
  FolderNode,
} from "../types.js";

/**
 * Repository Knowledge Graph (RKG) — Builder, Enricher & Query Engine.
 *
 * Phase 1 — Structural Layer (repository structure):
 *   [Repository] ──CONTAINS──▶ [File] ──CONTAINS──▶ [Module]
 *                                │
 *                           DEPENDS_ON
 *                                │
 *                                ▼
 *                          [Dependency] ──IMPORTS──▶ [Package]
 *
 * Phase 2 — Security Enrichment Layer (threat intelligence integration):
 *   [Package] ──AFFECTS──▶ [Threat/CVE] ──HAS_CVSS──▶ [CVSSNode]
 *                                         ──IN_KEV──▶  [KEVNode]
 *                                         ──FIXED_BY──▶ [PatchNode]
 *                                         ──REPLACED_BY──▶ [AlternativeNode]
 *
 * The graph is enriched AFTER scan completion, so Threat nodes carry full
 * CVSS, KEV, patch, and alternative library metadata — not just CVE IDs.
 * This transforms the graph from "repository structure" into
 * "Repository + Security Knowledge" — enabling relationship-aware reasoning.
 */
export class RepoKnowledgeGraphBuilder {
  private nodes: Map<string, RKGNode> = new Map();
  private edges: RKGEdge[] = [];

  // ─── Phase 1: Structural Build ─────────────────────────────────────────────

  buildGraph(
    repoUrl: string,
    tree: FolderNode[],
    scanResults: DependencyScanResult[],
    chunks: RepoChunk[]
  ): RepositoryKnowledgeGraph {
    this.nodes.clear();
    this.edges = [];

    const repoNodeId = `repo:${repoUrl}`;
    this.addNode({
      id: repoNodeId,
      label: repoUrl,
      type: "Repository",
      properties: { url: repoUrl },
    });

    // File nodes
    for (const item of tree.slice(0, 200)) {
      if (item.type === "blob") {
        const fileNodeId = `file:${item.path}`;
        this.addNode({
          id: fileNodeId,
          label: item.path,
          type: "File",
          properties: { path: item.path, size: item.size },
        });
        this.addEdge(repoNodeId, fileNodeId, "CONTAINS");
      }
    }

    // Module nodes from semantic chunks
    for (const chunk of chunks) {
      if (chunk.chunkType === "function" || chunk.chunkType === "class") {
        const fileNodeId = `file:${chunk.filePath}`;
        if (!this.nodes.has(fileNodeId)) {
          this.addNode({
            id: fileNodeId,
            label: chunk.filePath,
            type: "File",
            properties: { path: chunk.filePath },
          });
          this.addEdge(repoNodeId, fileNodeId, "CONTAINS");
        }

        const moduleId = `module:${chunk.filePath}#L${chunk.startLine ?? 0}`;
        const firstLine = chunk.content.split("\n")[0].trim().substring(0, 60);
        this.addNode({
          id: moduleId,
          label: firstLine,
          type: "Module",
          properties: {
            filePath: chunk.filePath,
            chunkType: chunk.chunkType,
            startLine: chunk.startLine,
            endLine: chunk.endLine,
          },
        });
        this.addEdge(fileNodeId, moduleId, "CONTAINS");
      }
    }

    // Dependency, Package, and bare Threat nodes
    for (const res of scanResults) {
      const dep = res.dependency;
      const manifestFileId = `file:${dep.manifestPath}`;
      if (!this.nodes.has(manifestFileId)) {
        this.addNode({
          id: manifestFileId,
          label: dep.manifestPath,
          type: "File",
          properties: { path: dep.manifestPath },
        });
        this.addEdge(repoNodeId, manifestFileId, "CONTAINS");
      }

      const depId = `dep:${dep.ecosystem}:${dep.name}@${dep.version}`;
      this.addNode({
        id: depId,
        label: `${dep.name}@${dep.version}`,
        type: "Dependency",
        properties: { name: dep.name, version: dep.version, ecosystem: dep.ecosystem, isDev: dep.isDev },
      });
      this.addEdge(manifestFileId, depId, "DEPENDS_ON");

      const pkgId = `pkg:${dep.ecosystem}:${dep.name}`;
      this.addNode({
        id: pkgId,
        label: dep.name,
        type: "Package",
        properties: { name: dep.name, ecosystem: dep.ecosystem },
      });
      this.addEdge(depId, pkgId, "IMPORTS");

      // Bare threat nodes (pre-enrichment)
      for (const vuln of res.vulnerabilities) {
        const threatId = this.threatId(vuln);
        this.addNode({
          id: threatId,
          label: vuln.cveId ?? vuln.osvId ?? "Vulnerability",
          type: "Threat",
          properties: {
            cveId: vuln.cveId,
            osvId: vuln.osvId,
            severity: vuln.severity,
            cvssScore: vuln.cvssScore,
            summary: vuln.summary,
            kev: vuln.kev,
            // enriched fields (populated in Phase 2)
            enriched: false,
          },
        });
        this.addEdge(pkgId, threatId, "AFFECTS");
      }
    }

    this.inferImportEdges(chunks);

    return {
      nodes: Array.from(this.nodes.values()),
      edges: this.edges,
    };
  }

  // ─── Phase 2: Security Enrichment ─────────────────────────────────────────

  /**
   * Enrich the graph with full threat intelligence data.
   *
   * After enrichment, each Threat node expands into a sub-graph:
   *
   *   [Threat/CVE]
   *       ├──HAS_CVSS──▶  [CVSSNode]       { score, vector, severity }
   *       ├──IN_KEV──▶    [KEVNode]         { exploited: true }
   *       ├──FIXED_BY──▶  [PatchNode]       { version, ecosystem }
   *       └──REPLACED_BY──▶ [AlternativeNode] { name, reason }
   *
   * This transforms the graph from repository structure into
   * "Repository + Security Knowledge Graph".
   */
  enrichWithThreatIntel(scanResults: DependencyScanResult[]): RepositoryKnowledgeGraph {
    for (const res of scanResults) {
      for (const vuln of res.vulnerabilities) {
        const threatId = this.threatId(vuln);
        const threatNode = this.nodes.get(threatId);
        if (!threatNode) continue;

        // Mark as enriched
        threatNode.properties.enriched = true;

        // 1. CVSS Node
        if (vuln.cvssScore !== null) {
          const cvssId = `cvss:${threatId}`;
          this.addNode({
            id: cvssId,
            label: `CVSS ${vuln.cvssScore}`,
            type: "Threat",   // sub-type via properties.subType
            properties: {
              subType: "CVSS",
              score: vuln.cvssScore,
              vector: vuln.cvssVector,
              severity: vuln.severity,
            },
          });
          this.addEdge(threatId, cvssId, "HAS_CVSS");
        }

        // 2. KEV Node — only if actively exploited
        if (vuln.kev) {
          const kevId = `kev:${threatId}`;
          this.addNode({
            id: kevId,
            label: "CISA KEV",
            type: "Threat",
            properties: {
              subType: "KEV",
              exploited: true,
              cveId: vuln.cveId,
              source: "CISA Known Exploited Vulnerabilities",
            },
          });
          this.addEdge(threatId, kevId, "IN_KEV");
        }

        // 3. Patch Nodes — one per fixed version
        for (const fixedVersion of vuln.fixedVersions) {
          const patchId = `patch:${res.dependency.name}@${fixedVersion}`;
          this.addNode({
            id: patchId,
            label: `${res.dependency.name}@${fixedVersion}`,
            type: "Package",
            properties: {
              subType: "Patch",
              name: res.dependency.name,
              version: fixedVersion,
              ecosystem: res.dependency.ecosystem,
            },
          });
          this.addEdge(threatId, patchId, "FIXED_BY");
        }

        // 4. Alternative Library Node — derived from known safe alternatives map
        const alternatives = KNOWN_ALTERNATIVES[res.dependency.name];
        if (alternatives) {
          for (const alt of alternatives) {
            const altId = `alt:${alt.name}`;
            if (!this.nodes.has(altId)) {
              this.addNode({
                id: altId,
                label: alt.name,
                type: "Package",
                properties: {
                  subType: "Alternative",
                  name: alt.name,
                  reason: alt.reason,
                  ecosystem: res.dependency.ecosystem,
                },
              });
            }
            this.addEdge(threatId, altId, "REPLACED_BY");
          }
        }
      }
    }

    return {
      nodes: Array.from(this.nodes.values()),
      edges: this.edges,
    };
  }

  // ─── Graph Query / Traversal ────────────────────────────────────────────────

  /**
   * Traverse the graph to produce enriched context paths for a package.
   * Includes patch versions and KEV status from the enriched sub-graph.
   */
  traverseContext(packageName: string, cveId?: string | null): GraphContextPath[] {
    const paths: GraphContextPath[] = [];

    const pkgId = Array.from(this.nodes.keys()).find(
      (id) => id.startsWith("pkg:") && id.toLowerCase().endsWith(`:${packageName.toLowerCase()}`)
    );
    if (!pkgId) return paths;

    // Packages that import this package (deps)
    const depEdges = this.edges.filter((e) => e.target === pkgId && e.relationship === "IMPORTS");
    const depNodeIds = depEdges.map((e) => e.source);

    // Files that contain those deps
    const manifestEdges = this.edges.filter(
      (e) => depNodeIds.includes(e.target) && e.relationship === "DEPENDS_ON"
    );
    const manifestFileIds = manifestEdges.map((e) => e.source);

    // Files that directly import this package (code-level)
    const codeImportEdges = this.edges.filter(
      (e) => e.target === pkgId && e.relationship === "IMPORTS" && e.source.startsWith("file:")
    );
    const importingFileIds = codeImportEdges.map((e) => e.source);

    const allFileIds = Array.from(new Set([...manifestFileIds, ...importingFileIds]));
    const impactedFiles = allFileIds.map(
      (id) => (this.nodes.get(id)?.properties.path as string) || id
    );

    // Modules inside those files
    const moduleEdges = this.edges.filter(
      (e) => allFileIds.includes(e.source) && e.relationship === "CONTAINS"
    );
    const affectedModules = moduleEdges
      .map((e) => (this.nodes.get(e.target)?.label as string) || e.target)
      .slice(0, 10);

    // Threat info from enriched graph
    const threatNodeId = Array.from(this.nodes.keys()).find(
      (id) => id.startsWith("threat:") && (
        (cveId && id.includes(cveId)) ||
        this.edges.some((e) => e.source === pkgId && e.target === id && e.relationship === "AFFECTS")
      )
    );

    let patchVersions: string[] = [];
    let kevStatus = false;

    if (threatNodeId) {
      // Collect patch nodes
      patchVersions = this.edges
        .filter((e) => e.source === threatNodeId && e.relationship === "FIXED_BY")
        .map((e) => this.nodes.get(e.target)?.properties.version as string)
        .filter(Boolean);

      // Check KEV
      kevStatus = this.edges.some(
        (e) => e.source === threatNodeId && e.relationship === "IN_KEV"
      );
    }

    const explanation = [
      `Graph traversal: '${packageName}' → ${impactedFiles.length} impacted file(s) → ${affectedModules.length} module(s).`,
      patchVersions.length > 0 ? `Patch versions: [${patchVersions.join(", ")}].` : "",
      kevStatus ? "⚠️ Actively exploited (CISA KEV)." : "",
    ].filter(Boolean).join(" ");

    paths.push({
      dependency: packageName,
      package: packageName,
      threatId: cveId ?? null,
      affectedModules,
      impactedFiles: impactedFiles.slice(0, 10),
      patchVersions,
      kevStatus,
      explanation,
    });

    return paths;
  }

  snapshot(): RepositoryKnowledgeGraph {
    return {
      nodes: Array.from(this.nodes.values()),
      edges: this.edges,
    };
  }

  /**
   * Build a concise text summary of the knowledge graph for use in LLM prompts.
   * Describes node/edge counts, key relationships, and threat intelligence.
   */
  buildGraphSummary(): string {
    const nodesByType = new Map<string, number>();
    for (const node of this.nodes.values()) {
      nodesByType.set(node.type, (nodesByType.get(node.type) ?? 0) + 1);
    }

    const kevNodes   = Array.from(this.nodes.values()).filter(n => n.properties.subType === "KEV");
    const patchNodes = Array.from(this.nodes.values()).filter(n => n.properties.subType === "Patch");
    const altNodes   = Array.from(this.nodes.values()).filter(n => n.properties.subType === "Alternative");

    // Find all AFFECTS edges (Package → Threat)
    const affectedPackages = this.edges
      .filter(e => e.relationship === "AFFECTS")
      .map(e => this.nodes.get(e.source)?.label ?? e.source)
      .slice(0, 10);

    const lines = [
      `Repository Knowledge Graph: ${this.nodes.size} nodes, ${this.edges.length} edges`,
      `  Files: ${nodesByType.get("File") ?? 0}, Modules: ${nodesByType.get("Module") ?? 0}, Packages: ${nodesByType.get("Package") ?? 0}, Threats: ${nodesByType.get("Threat") ?? 0}`,
    ];

    if (kevNodes.length > 0) {
      lines.push(`  ⚠️  CISA KEV (Actively Exploited): ${kevNodes.map(n => n.properties.cveId ?? n.label).join(", ")}`);
    }
    if (patchNodes.length > 0) {
      lines.push(`  Patch versions available: ${patchNodes.map(n => n.label).slice(0, 8).join(", ")}`);
    }
    if (altNodes.length > 0) {
      lines.push(`  Safe alternative packages: ${altNodes.map(n => n.label).join(", ")}`);
    }
    if (affectedPackages.length > 0) {
      lines.push(`  Packages with known threats: ${affectedPackages.join(", ")}`);
    }

    return lines.join("\n");
  }

  // ─── Private Helpers ────────────────────────────────────────────────────────

  private threatId(vuln: UnifiedVulnerability): string {
    return `threat:${vuln.cveId || vuln.osvId || vuln.summary.substring(0, 30)}`;
  }

  private addNode(node: RKGNode): void {
    if (!this.nodes.has(node.id)) {
      this.nodes.set(node.id, node);
    }
  }

  private addEdge(source: string, target: string, relationship: RKGEdgeType, weight = 1.0): void {
    const exists = this.edges.some(
      (e) => e.source === source && e.target === target && e.relationship === relationship
    );
    if (!exists) {
      this.edges.push({ source, target, relationship, weight });
    }
  }

  private inferImportEdges(chunks: RepoChunk[]): void {
    const packageNodes = Array.from(this.nodes.values()).filter((n) => n.type === "Package");

    for (const chunk of chunks) {
      const fileId = `file:${chunk.filePath}`;
      if (!this.nodes.has(fileId)) continue;

      for (const pkgNode of packageNodes) {
        const pkgName = pkgNode.properties.name as string;
        if (!pkgName) continue;
        const importRegex = new RegExp(
          `['"]${pkgName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(/.*)?['"]`
        );
        if (importRegex.test(chunk.content)) {
          this.addEdge(fileId, pkgNode.id, "IMPORTS", 0.8);
        }
      }
    }
  }
}

// ─── Known Safe Alternative Libraries ─────────────────────────────────────────

/**
 * Curated map of packages to commonly recommended safer alternatives.
 * Used to populate REPLACED_BY edges during graph enrichment.
 *
 * Rationale: Rather than hallucinating alternatives from LLM, these are
 * well-known community-accepted alternatives that can be added to the graph
 * as deterministic nodes, making the graph structure more actionable.
 */
const KNOWN_ALTERNATIVES: Record<string, Array<{ name: string; reason: string }>> = {
  "node-uuid": [{ name: "uuid", reason: "Actively maintained successor" }],
  "request": [{ name: "axios", reason: "Modern Promise-based HTTP client" }, { name: "node-fetch", reason: "Lightweight fetch-compatible client" }],
  "moment": [{ name: "date-fns", reason: "Immutable, tree-shakeable" }, { name: "dayjs", reason: "Lightweight Moment.js-compatible API" }],
  "lodash": [{ name: "radash", reason: "Modern typed utility library" }],
  "serialize-javascript": [{ name: "devalue", reason: "Safe serialization without eval risks" }],
  "eval": [{ name: "vm2", reason: "Sandboxed evaluation environment" }],
  "node-forge": [{ name: "forge", reason: "Actively maintained fork with CVE patches" }],
  "jsonwebtoken": [{ name: "jose", reason: "W3C Web Crypto API based, fewer CVEs" }],
  "marked": [{ name: "dompurify+marked", reason: "XSS-safe combination" }],
  "qs": [{ name: "querystring", reason: "Node.js built-in, no CVE surface" }],
};
