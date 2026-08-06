# 📋 VulnShield — Project Workflow & Roadmap

> Full technical workflow, phase breakdown, and architectural decisions for the AI-Powered Vulnerability Detection & Mitigation System.

---

## 🗺️ Full Project Phases at a Glance

```
Phase 1 ✅   Phase 2 ⏳   Phase 3 ⏳   Phase 4 ⏳
────────────────────────────────────────────────────────
[Data Pipeline] → [AI/Vector] → [Dashboard] → [Extension]
    25%              50%           75%           100%
```

---

## ✅ Phase 1 — Core Data Pipeline (Initial Build) `COMPLETE`

**Goal:** Build the foundational scanning engine. No AI, no UI — just a rock-solid pipeline that correctly identifies vulnerabilities in real repositories.

### Data Flow

```
User provides GitHub URL
         │
         ▼
┌─────────────────────┐
│  GitHubClient       │  ← Octokit REST API
│  detectManifests()  │    Lists root + common subdirs
│  fetchManifests()   │    Downloads file contents
└────────┬────────────┘
         │  ManifestFile[]
         ▼
┌─────────────────────┐
│  Parser Registry    │
│  NpmParser          │  ← package.json → {name, version, isDev}
│  MavenParser        │  ← pom.xml → groupId:artifactId, version
│  PythonParser       │  ← requirements.txt / Pipfile
└────────┬────────────┘
         │  ParsedDependency[]
         ▼
┌─────────────────────────────────────────────────┐
│  OSVClient.queryBatch()                         │
│  ─────────────────────────────────────────────  │
│  POST /v1/querybatch  (up to 1000 per request)  │
│  ─────────────────────────────────────────────  │
│  enrichMissingSeverity()                        │
│    GET /v1/vulns/{id}  (parallel, 10 at a time) │
│    Extracts CVSS v3 vector → computes score     │
└────────┬────────────────────────────────────────┘
         │  Map<key, UnifiedVulnerability[]>
         ▼
┌─────────────────────┐
│  ScanReport         │  ← Aggregates all results
│  severityCounts     │  ← CRITICAL/HIGH/MEDIUM/LOW
│  persist to DB      │  ← Prisma → PostgreSQL
└────────┬────────────┘
         │
    ┌────┴────┐
    │  CLI    │  ← Coloured terminal output
    │  API    │  ← JSON via REST endpoint
    └─────────┘
```

### Key Technical Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Primary vuln source | OSV.dev | Free, no API key, aggregates GitHub Security Advisories + NVD + PyPA + more |
| Batch vs single queries | Batch first, enrich individually | Batch API is fast but omits severity — enrich in parallel after |
| CVSS scoring | Manual v3 formula | `cvss` npm package computed 0 for v3 vectors; hand-rolled formula matches NVD output exactly |
| DB provider | PostgreSQL via Docker (port 5433) | Avoids conflict with locally installed Postgres; matches synopsis requirement |
| Language | TypeScript ESM | Native fit for VS Code extension (Phase 4 goal) |

### Deliverables

- [x] TypeScript monorepo (`pnpm` workspaces)
- [x] Dependency parsers: npm, Maven, Python (9 unit tests)
- [x] GitHub API client (manifest auto-detection)
- [x] OSV.dev batch client with severity enrichment
- [x] NVD client with rate-limiting
- [x] CVSS v3 manual base score calculator
- [x] PostgreSQL schema (Scan → Dependency → Vulnerability)
- [x] Prisma ORM integration
- [x] CLI tool with coloured severity output
- [x] Express REST API (scan, get, list endpoints)

### Validated Against

| Repo | Deps Found | Vulns Found | CRITICAL |
|---|---|---|---|
| `snyk-labs/nodejs-goof` | 35 | 58 | 11 |

---

## ⏳ Phase 2 — AI / Vector Intelligence `NEXT`

**Goal:** Add semantic understanding to vulnerability data. Move from "list CVEs" to "explain what matters for this specific repository."

### Planned Data Flow

```
Phase 1 output: UnifiedVulnerability[]
         │
         ▼
┌─────────────────────────────────────────────┐
│  Embedding Pipeline                         │
│  ─────────────────────────────────────────  │
│  vuln.summary + vuln.details                │
│         ↓                                   │
│  Gemini text-embedding-004                  │
│         ↓                                   │
│  768-dimensional vector                     │
└────────┬────────────────────────────────────┘
         │  float[]
         ▼
┌─────────────────────────────────────────────┐
│  ChromaDB (Docker, port 8000)               │
│  Collection: "vuln-descriptions"            │
│  Stored with metadata:                      │
│    cveId, severity, ecosystem, package      │
└────────┬────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│  LLM Reasoning (Gemini Flash)               │
│  ─────────────────────────────────────────  │
│  Context: repo manifest + vuln embeddings   │
│  Prompt: "Which vulns are actually          │
│           exploitable in THIS project?"     │
│         ↓                                   │
│  Context-aware risk score (0–10)            │
│  Remediation recommendation                 │
│  Alternative package suggestion             │
└─────────────────────────────────────────────┘
```

### Tasks

- [ ] Set up ChromaDB via Docker (`docker-compose.yml` addition)
- [ ] Implement `EmbeddingService` using Gemini `text-embedding-004`
- [ ] Store all Phase 1 scan results as embeddings
- [ ] Build `SemanticRetriever` — query ChromaDB by package context
- [ ] Build `RemediationEngine` — LLM reasoning with RAG
- [ ] Add `contextScore` field to `UnifiedVulnerability` (0–10, beyond CVSS)
- [ ] Extend REST API with `/api/scan/:id/remediation`
- [ ] Unit tests for embedding pipeline

### New Services

```
packages/core/src/
├── ai/
│   ├── embedder.ts         ← Gemini embedding API client
│   ├── vector-store.ts     ← ChromaDB collection management
│   ├── retriever.ts        ← Semantic similarity search
│   └── remediator.ts       ← LLM prompt + response parser
```

### New Docker Services

```yaml
# Addition to docker-compose.yml
chromadb:
  image: chromadb/chroma
  container_name: vulnshield-chromadb
  ports:
    - "8000:8000"
  volumes:
    - chromadata:/chroma/chroma
```

---

## ⏳ Phase 3 — Interactive Dashboard `PLANNED`

**Goal:** A web-based UI that makes scan results accessible and visually compelling. This is the primary academic demo deliverable.

### Planned Stack

| Component | Technology |
|---|---|
| Framework | Next.js 14 (App Router) |
| UI Components | shadcn/ui + Tailwind CSS |
| Charts | Recharts |
| State | React Query (server state) |
| Auth | None (open for academic demo) |

### Planned Pages

```
/                    ← Landing: "Enter GitHub URL to scan"
/scan/[id]           ← Full report for a single scan
  ├── Overview        ← Severity breakdown pie chart, counts
  ├── Dependencies    ← Table: package, ecosystem, vuln count
  ├── Vulnerabilities ← Filterable table with CVE details
  └── Remediation     ← AI-generated fix suggestions (Phase 2)
/history             ← All past scans, compare over time
```

### Tasks

- [ ] Scaffold Next.js app in `packages/web/`
- [ ] Design system: colour palette, typography, spacing tokens
- [ ] Severity ring chart component
- [ ] Dependency vulnerability table (sortable, filterable)
- [ ] CVE detail drawer/panel
- [ ] Remediation card with diff-style upgrade suggestion
- [ ] Scan history timeline
- [ ] Responsive layout (desktop primary)
- [ ] Dark mode

---

## ⏳ Phase 4 — VS Code Extension + Polish `PLANNED`

**Goal:** Package the core engine as a VS Code extension. The extension reads the open workspace's dependency files and runs a scan inline — no GitHub URL needed.

### Extension Architecture

```
vscode-extension/
├── package.json           ← Extension manifest (activationEvents, contributes)
├── src/
│   ├── extension.ts       ← activate() entry point
│   ├── scanner-bridge.ts  ← Calls @vuln-shield/core directly (same TS)
│   ├── diagnostics.ts     ← Populates Problems panel with vuln squiggles
│   ├── webview/
│   │   └── panel.ts       ← Reuses Phase 3 React components as Webview
│   └── commands/
│       ├── scan.ts         ← "VulnShield: Scan Project" command
│       └── fix.ts          ← "VulnShield: Apply Fix" quick action
```

### VS Code Features

| Feature | VS Code API Used |
|---|---|
| Highlight vulnerable deps | `vscode.languages.createDiagnosticCollection` |
| Scan on file save | `vscode.workspace.createFileSystemWatcher` |
| Show report panel | `vscode.window.createWebviewPanel` |
| Status bar progress | `vscode.window.createStatusBarItem` |
| Inline fix suggestion | `vscode.CodeAction` + `WorkspaceEdit` |
| Secure key storage | `vscode.ExtensionContext.secrets` |

### Tasks

- [ ] Scaffold extension with `yo generator-code`
- [ ] Import `@vuln-shield/core` as local workspace package
- [ ] Implement file watcher → auto-scan on manifest change
- [ ] Diagnostic collection: underline vulnerable packages in `package.json`
- [ ] Webview panel: embed Phase 3 React components
- [ ] Command palette: "VulnShield: Scan Project"
- [ ] "Quick Fix" code action: auto-update version in manifest
- [ ] Package with `vsce` → produce `.vsix` file
- [ ] Write VSIX installation instructions

---

## 🔁 Development Workflow

### Daily Workflow

```bash
# 1. Start the database
docker compose up -d

# 2. Start the API in watch mode
pnpm --filter @vuln-shield/api dev

# 3. Work on core scanner
pnpm --filter @vuln-shield/core test:watch

# 4. Run a scan to test changes
pnpm --filter @vuln-shield/core scan scan snyk-labs/nodejs-goof --no-persist
```

### Adding a New Manifest Parser

1. Create `packages/core/src/parsers/go-parser.ts`
2. Implement the `ManifestParser` interface
3. Add to the registry in `packages/core/src/parsers/index.ts`
4. Add filename to `MANIFEST_FILENAMES` array
5. Write tests in `packages/core/tests/parsers.test.ts`
6. Add `go` to the `Ecosystem` union type in `types.ts`

### Adding a New Vulnerability Source

1. Create `packages/core/src/vulndb/new-client.ts`
2. Implement the `VulnDBClient` interface
3. Export from `packages/core/src/vulndb/index.ts`
4. Add to the scanner pipeline in `scanner.ts`

---

## 📊 Severity Classification (CVSS v3)

| Score Range | Severity | Icon | Color |
|---|---|---|---|
| 9.0 – 10.0 | CRITICAL | 🔴 | Red |
| 7.0 – 8.9 | HIGH | 🟠 | Orange |
| 4.0 – 6.9 | MEDIUM | 🟡 | Yellow |
| 0.1 – 3.9 | LOW | 🔵 | Blue |
| N/A | UNKNOWN | ⚪ | Gray |

---

## 🔑 API Keys Reference

| Key | Where to Get | Required? | Used In |
|---|---|---|---|
| `GITHUB_TOKEN` | github.com/settings/tokens | Strongly recommended | All phases (manifest fetching) |
| `NVD_API_KEY` | nvd.nist.gov/developers/request-an-api-key | Optional | Phase 1 (NVD enrichment, higher rate limits) |
| `GEMINI_API_KEY` | aistudio.google.com/apikey | Required for Phase 2 | Embeddings + LLM reasoning |

---

## 🧩 Database Schema

```
Scan
 ├── id          (cuid)
 ├── repoUrl
 ├── repoOwner
 ├── repoName
 ├── status      (pending | scanning | complete | failed)
 ├── totalDeps
 ├── totalVulns
 ├── createdAt
 └── completedAt

Dependency  (belongs to Scan)
 ├── id
 ├── scanId      → Scan.id
 ├── ecosystem   (npm | maven | pypi)
 ├── name
 ├── version
 ├── manifestPath
 └── isDev

Vulnerability  (belongs to Dependency)
 ├── id
 ├── dependencyId → Dependency.id
 ├── cveId        (CVE-YYYY-NNNNN or null)
 ├── severity     (CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN)
 ├── cvssScore    (float, 0–10)
 ├── cvssVector   (e.g. CVSS:3.1/AV:N/...)
 ├── summary      (short description)
 ├── details      (full advisory text)
 ├── fixedVersions (JSON array)
 ├── references   (JSON array of URLs)
 └── source       (OSV | NVD)
```

---

## 🐳 Docker Services

| Service | Image | Host Port | Purpose |
|---|---|---|---|
| `vulnshield-db` | `postgres:16-alpine` | 5433 | Primary relational store |
| `vulnshield-chromadb` *(Phase 2)* | `chromadb/chroma` | 8000 | Vector embedding store |

---

*Generated by VulnShield project setup — May 2026*
