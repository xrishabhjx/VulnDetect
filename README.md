# VulnShield — AI-Powered Vulnerability Detection & Mitigation System

> **An intelligent repository security platform that combines static dependency analysis, knowledge graph reasoning, and LLM-powered remediation planning into a unified 13-step pipeline.**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?style=flat-square&logo=typescript)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-22.x-339933?style=flat-square&logo=nodedotjs)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-pgvector-4169E1?style=flat-square&logo=postgresql)](https://github.com/pgvector/pgvector)
[![Groq](https://img.shields.io/badge/LLM-Groq%20LLaMA%203.3--70B-F55036?style=flat-square)](https://groq.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

---

## Overview

VulnShield is a final-year engineering research project that addresses a core limitation of traditional vulnerability scanners: they detect vulnerabilities but provide no intelligent guidance on how to fix them in the context of a specific codebase.

This system introduces the concept of a **Repository Security Intelligence Score (RSIS)** — a 5-dimensional quantitative metric that measures a repository's security posture across severity, retrieval confidence, validation, maintainability, and compatibility axes.

The platform does not simply list CVEs. It reasons about them in the context of your repository's architecture, knowledge graph, and similar open-source repositories — then generates ranked, evidence-grounded remediation candidates using a large language model with a Groq → Gemini → heuristic fallback chain.

---

## Key Capabilities

| Capability | Implementation |
|---|---|
| **Multi-source vulnerability scanning** | OSV, NVD, GitHub Advisory, CISA KEV |
| **Repository profile generation** | Detects framework, architecture, DB, ORM, auth, CI/CD, deployment — no LLM needed |
| **Repository Knowledge Graph (RKG)** | Graph of File → Module → Dependency → Threat nodes with CVSS, KEV, Patch sub-graphs |
| **Semantic chunking & hybrid retrieval** | BM25 + pgvector HNSW cosine similarity (RRF fusion) |
| **Similar repository discovery** | GitHub Search API + health scoring + upgrade pattern evidence |
| **LLM reasoning engine** | Groq LLaMA 3.3-70B → Gemini 1.5-flash → heuristic fallback |
| **Context-aware prompting** | 7-section prompt: profile + graph + code evidence + threat intel + similar repo evidence |
| **Candidate ranking** | 6-feature ML utility score (compatibility, security gain, evidence strength, validation, pattern alignment, dependency impact) |
| **RSIS scoring** | 5-dimensional weighted score (security, retrieval, validation, maintainability, compatibility) |
| **Interactive CLI** | Menu-driven terminal interface — no curl commands needed |
| **REST API** | Express-based API server for programmatic access |
| **Cross-project benchmark** | Automated RSIS comparison across curated vulnerable repositories |

---

## System Architecture

```
Repository URL
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│                   13-STEP INTELLIGENCE PIPELINE                  │
│                                                                   │
│  Step 1   Vulnerability Scan (OSV + NVD + GitHub Advisory)       │
│  Step 2   Repository Understanding → RepositoryProfile            │
│  Step 3   Semantic Chunking (function/class boundary splitting)   │
│  Step 4   Embedding Generation → pgvector HNSW columns           │
│  Step 5   Knowledge Graph Construction (RKG Phase 1)             │
│  Step 6   CISA KEV Threat Intel Enrichment                       │
│  Step 7   Knowledge Graph Threat Enrichment (RKG Phase 2)        │
│  Step 8   Similar Repository Discovery + Health Assessment        │
│           ──────────────── per vulnerability ──────────────────  │
│  Step 9   Graph Traversal → impacted files, modules, patches      │
│           SimilarRepoEvidence build → upgrade patterns            │
│           RepositoryContext construction (unified pre-LLM object) │
│  Step 10  Reasoning Engine (Groq → Gemini → Heuristic fallback)  │
│  Step 11  Validation + Multi-feature Candidate Ranking            │
│  Step 12  RSIS 5-Dimension Score Computation                      │
│  Step 13  Intelligence Summary + Projected RSIS                   │
└─────────────────────────────────────────────────────────────────┘
      │
      ▼
  AnalysisResult
  ├── repositoryProfile   (architecture, stack, deployment signals)
  ├── knowledgeGraph      (630+ nodes, 641+ edges for typical repo)
  ├── remediations[]      (ranked candidates with reasoning chains)
  ├── rsis                (5-dimension score with grade A–F)
  └── intelligenceSummary (projected score, graph stats, stack desc)
```

---

## Repository Knowledge Graph (RKG)

The RKG is the central data structure. It is built in two phases:

**Phase 1 — Structural layer:**
```
[Repository] ──CONTAINS──▶ [File] ──CONTAINS──▶ [Module]
                              │
                         DEPENDS_ON
                              │
                              ▼
                        [Dependency] ──IMPORTS──▶ [Package]
```

**Phase 2 — Security enrichment layer (threat intelligence integration):**
```
[Package] ──AFFECTS──▶ [Threat/CVE]
                              ├──HAS_CVSS──▶  [CVSSNode]
                              ├──IN_KEV──▶    [KEVNode]
                              ├──FIXED_BY──▶  [PatchNode]
                              └──REPLACED_BY──▶ [AlternativeNode]
```

The graph enables relationship-aware reasoning: the LLM is told exactly which files import a vulnerable package, which modules are at risk, and which versions are confirmed safe — derived from graph traversal, not hallucination.

---

## RSIS — Repository Security Intelligence Score

$$RSIS = w_1 \cdot S_{security} + w_2 \cdot S_{retrieval} + w_3 \cdot S_{validation} + w_4 \cdot S_{maintainability} + w_5 \cdot S_{compatibility}$$

| Dimension | Default Weight | Measures |
|---|---|---|
| **Security** | 0.30 | CVSS severity, KEV exploitation, vulnerability density |
| **Retrieval** | 0.20 | Code evidence quality (BM25 + pgvector RRF fusion score) |
| **Validation** | 0.20 | Registry confirmation + OSV re-scan of proposed versions |
| **Maintainability** | 0.15 | Dependency age, push recency, open issue burden |
| **Compatibility** | 0.15 | SemVer upgrade safety (patch/minor/major delta) |

Weights are configurable via `.env` and grounded in NIST SP 800-161 and ISO/IEC 25010.

---

## Candidate Ranking — 6-Feature Utility Score

Each remediation candidate is scored by the `CandidateRanker` using a weighted multi-criteria model:

| Feature | Weight | Signal |
|---|---|---|
| Compatibility | 0.20 | SemVer diff (patch=1.0, minor=0.85, major=0.40) |
| Security Gain | 0.30 | CVSS reduction + KEV resolution bonus (0.2) |
| Dependency Impact | 0.12 | Inverse decay of transitive dependency chain length |
| Validation | 0.18 | Registry existence + OSV re-scan outcome |
| Pattern Alignment | 0.10 | Healthy similar-repo adoption signals |
| Evidence Strength | 0.10 | OSV + NVD + GHSA + CISA KEV + similar repo corroboration |

---

## Project Structure

```
.
├── packages/
│   ├── core/                          # Intelligence engine
│   │   ├── prisma/
│   │   │   └── schema.prisma          # Database schema (pgvector support)
│   │   └── src/
│   │       ├── analyzer.ts            # 13-step pipeline orchestrator
│   │       ├── cli.ts                 # Interactive terminal interface
│   │       ├── scanner.ts             # Multi-source vulnerability scanner
│   │       ├── types.ts               # All shared TypeScript interfaces
│   │       ├── intelligence/
│   │       │   ├── repo-understander.ts   # Repository profile generation
│   │       │   ├── knowledge-graph.ts     # RKG builder + traversal engine
│   │       │   ├── reasoner.ts            # LLM reasoning (Groq→Gemini→fallback)
│   │       │   ├── chunker.ts             # Semantic code chunking
│   │       │   ├── embedder.ts            # Embedding (Gemini/TF-IDF)
│   │       │   ├── retriever.ts           # Hybrid BM25 + pgvector retrieval
│   │       │   ├── similar-repos.ts       # Similar repo discovery + evidence
│   │       │   ├── candidate-ranker.ts    # 6-feature ML utility ranker
│   │       │   ├── validator.ts           # Registry + OSV validation
│   │       │   └── rsis-scorer.ts         # 5-dimension RSIS computation
│   │       ├── vulndb/
│   │       │   ├── osv-client.ts          # OSV vulnerability database
│   │       │   ├── nvd-client.ts          # NIST NVD (CVSS data)
│   │       │   ├── github-advisory-client.ts  # GitHub Security Advisories
│   │       │   └── cisa-kev-client.ts     # CISA Known Exploited Vulnerabilities
│   │       ├── benchmark/             # Cross-project evaluation suite
│   │       └── evaluation/            # Retrieval quality metrics (MRR, nDCG)
│   └── api/
│       └── src/
│           └── server.ts              # REST API (Express)
├── docker-compose.yml                 # PostgreSQL + pgvector container
└── .env.example                       # Environment variable template
```

---

## Technology Stack

| Layer | Technology |
|---|---|
| **Runtime** | Node.js 22, TypeScript 5 |
| **LLM Reasoning** | Groq LLaMA 3.3-70B Versatile |
| **Embeddings** | Google Gemini `text-embedding-004` (768-dim) / Local TF-IDF fallback |
| **Vector Database** | PostgreSQL + pgvector (HNSW index, cosine distance `<=>`) |
| **Hybrid Retrieval** | BM25 + Dense ANN with Reciprocal Rank Fusion (RRF) |
| **ORM** | Prisma |
| **Package Manager** | pnpm (workspace monorepo) |
| **Vulnerability Sources** | OSV, NIST NVD, GitHub Advisory API, CISA KEV |
| **CLI** | chalk, ora |
| **API** | Express.js |

---

## Prerequisites

- **Node.js** ≥ 22
- **pnpm** ≥ 9 → `npm install -g pnpm`
- **Docker Desktop** (for PostgreSQL + pgvector)
- **API Keys** (see Configuration section)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/xrishabhjx/VulnDetect.git
cd VulnDetect

# 2. Install all dependencies (monorepo)
pnpm install

# 3. Start PostgreSQL with pgvector
docker-compose up -d

# 4. Push database schema
pnpm --filter @vulnshield/core db:push

# 5. Enable pgvector extension (run once)
docker exec -it vulnshield-db psql -U vulnshield -d vulnshield -c "CREATE EXTENSION IF NOT EXISTS vector;"

# 6. Build all packages
pnpm build
```

---

## Configuration

Copy `.env.example` to `.env` and fill in the values:

```env
# Required — GitHub Personal Access Token
# Scope needed: public_repo (read repository contents)
# Get from: https://github.com/settings/tokens
GITHUB_TOKEN=github_pat_...

# Required for AI reasoning — Groq API Key
# Get from: https://console.groq.com/keys
# Note: Key must start with gsk_ (not Agsk_)
GROQ_API_KEY=gsk_...

# Optional — Gemini API Key (used for neural embeddings + reasoning fallback)
# Get from: https://aistudio.google.com/app/apikey
GEMINI_API_KEY=AIza...

# Optional — NIST NVD API Key (increases rate limit from 5→50 req/30s)
# Get from: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=...

# Database (matches docker-compose.yml defaults)
DATABASE_URL=postgresql://vulnshield:vulnshield123@localhost:5433/vulnshield
```

> **Note:** Without `GEMINI_API_KEY`, the system uses a local TF-IDF fallback for embeddings. All reasoning, scanning, and graph features remain fully functional.

---

## Usage

### Interactive CLI (Recommended)

```bash
cd packages/core
pnpm scan
```

```
══════════════════════════════════════════════════════════════
  🛡️  VulnShield — Repository Security Intelligence Platform
══════════════════════════════════════════════════════════════

  1  Scan a repository                    ← check for vulnerabilities
  2  Run full AI-powered analysis         ← remediation + knowledge graph + RSIS
  3  Run benchmark suite                  ← RSIS before/after across 8 repos
  4  Start API server                     ← REST endpoints at localhost:3001
  5  Run test suite                       ← 40 unit tests
  0  Exit
```

Select **option 2** and enter any public GitHub repository (e.g. `OWASP/NodeGoat`, `juice-shop/juice-shop`).

### REST API

```bash
# Start the API server (option 4 in CLI, or directly:)
cd packages/api && pnpm dev

# Run full analysis
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"repoUrl": "OWASP/NodeGoat"}'

# Quick scan only
curl -X POST http://localhost:3001/api/scan \
  -H "Content-Type: application/json" \
  -d '{"repoUrl": "OWASP/NodeGoat"}'
```

---

## Sample Output

### Repository Profile (Step 2 output)
```
  Repository      juice-shop/juice-shop
  Language        TypeScript
  Framework       express
  Architecture    microservices
  Type            api
  Database        postgresql
  ORM             sequelize
  Auth            jwt
  Deployment      docker
  CI/CD           github-actions
  Testing         cypress
```

### Knowledge Graph (Step 5/7 output)
```
  Nodes:  630  (Files: 197  Modules: 0  Packages: 172  Threats: 83)
  Edges:  641  (dependency chains, import relationships, threat intel edges)
  ⚠️  3 CISA KEV nodes — actively exploited CVEs in this graph
```

### RSIS Score
```
  Overall          ████████████░░░░░░░░░░░░ 49.8/100   Grade: D
  →  CRITICAL RISK — immediate action required

  Security         ░░░░░░░░░░░░   0.0   (3 CRITICAL, 14 HIGH CVEs)
  Retrieval        ██░░░░░░░░░░   3.1   (TF-IDF mode, no Gemini key)
  Validation       ████████████ 100.0   (all candidates registry-confirmed)
  Maintainability  ███████████░  94.5   (dependencies are recent)
  Compatibility    ████████████ 100.0   (all upgrades within same major)

  Projected after remediation: 65.0/100 (+15 points)
```

### AI Remediation Recommendation
```
  [1] sequelize  •  CVE: GHSA-v8fg-2rw7-q452  •  Ecosystem: npm
  Action: UPGRADE → v6.37.5   Risk: LOW
  Confidence: ████████░░ 87%  (evidence-derived)

  Chain of Reasoning:
    1. Observed: SQL Injection via Oracle DB dialect in sequelize@6.37.3
       Deduced: Any route using raw queries with Oracle dialect is exploitable
    2. Observed: Graph traversal — 12 files import sequelize (models/, routes/)
       Deduced: Attack surface spans entire data access layer
    3. Observed: Similar repo helmetjs/helmet uses sequelize@6.37.5 (active)
       Deduced: Patch is stable and production-proven

  Evidence References:
    • models/sequelize.js:1 — Primary ORM initialisation file
    • routes/dataErasure.js:3 — Direct raw query usage
```

---

## Benchmark Suite

Evaluates RSIS before and after remediation across 8 intentionally vulnerable repositories:

```bash
pnpm scan
# Select option 3 → choose number of repos (1–8)
```

Output is saved as `benchmark-results.md` and `benchmark-results.json`.

**Curated benchmark repos include:** OWASP/NodeGoat, juice-shop/juice-shop, OWASP/WebGoat, WebGoat/WebGoat-Legacy, OWASP/DVWA, and more.

---

## Evaluation Metrics

The system is evaluated across three axes:

| Metric | Description | Target |
|---|---|---|
| **Retrieval Precision@5** | Top-5 code chunk relevance | ≥ 0.70 |
| **MRR (Mean Reciprocal Rank)** | Position of first relevant chunk | ≥ 0.60 |
| **Top-1 Recommendation Accuracy** | Correct fix in rank-1 position | ≥ 0.65 |
| **Validation Pass Rate** | Proposed versions pass OSV re-scan | ≥ 0.80 |
| **RSIS Improvement** | Score delta after applying top recommendations | ≥ +10 pts |

---

## Research Contributions

1. **RepositoryProfile** — A structured, LLM-free architectural fingerprint of any GitHub repository derived from file tree, manifest, and README signals.

2. **Repository Knowledge Graph (RKG)** — A two-phase graph (structural + security enrichment) that enables relationship-aware vulnerability reasoning rather than flat CVE listing.

3. **RepositoryContext** — A unified pre-LLM context object that aggregates all pipeline stage outputs, ensuring the reasoning engine receives complete, structured intelligence.

4. **RSIS** — A 5-dimensional, literature-grounded security score that provides a quantitative, reproducible measure of repository security posture.

5. **Provider Fallback Chain** — Groq → Gemini → evidence-based heuristic ensures the pipeline never silently produces empty output regardless of API availability.

---

## Author

**Rishabh Jain**  

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
