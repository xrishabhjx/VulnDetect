# AI-Powered Repository Security Intelligence Platform
## Setup & Usage Guide

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Initial Setup](#2-initial-setup)
3. [Environment Configuration](#3-environment-configuration)
4. [Database Bootstrap](#4-database-bootstrap)
5. [Running the Project](#5-running-the-project)
6. [What to Expect - Screen-by-Screen](#6-what-to-expect--screen-by-screen)
7. [API Reference](#7-api-reference)
8. [Configurable Weight System](#8-configurable-weight-system)
9. [Running Tests](#9-running-tests)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| **Node.js** | >= 20 | Runtime |
| **pnpm** | >= 9 | Package manager |
| **Docker Desktop** | Any | PostgreSQL + pgvector |
| **Git** | Any | Repository access |

Install pnpm if missing:

```bash
npm install -g pnpm
```

---

## 2. Initial Setup

```bash
cd VulnDetect
pnpm install
pnpm build
```

Expected output:

```
packages/core build: Done
packages/api build: Done
```

---

## 3. Environment Configuration

```bash
cp .env.example .env
```

Open `.env` and fill in:

```ini
# REQUIRED - GitHub Personal Access Token
# https://github.com/settings/tokens -> Generate new token (classic)
# Scopes: repo (read:public_repo is enough for public repos)
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# REQUIRED FOR AI FEATURES - Google Gemini API Key
# https://aistudio.google.com/apikey
GEMINI_API_KEY=AIzaXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# REQUIRED FOR DATABASE - leave as-is if using docker-compose.yml
DATABASE_URL=postgresql://vulnshield:vulnshield123@localhost:5433/vulnshield

# OPTIONAL - NIST NVD API Key (increases rate limit from 5 to 50 req/30s)
# https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

> Minimum to get started: only GITHUB_TOKEN is needed for Mode A (basic scan).
> GEMINI_API_KEY is needed for Mode B (full AI analysis).

---

## 4. Database Bootstrap

```bash
# Start PostgreSQL + pgvector container
docker-compose up -d
```

Expected:

```
Container vulnshield-db  Started
```

Push the Prisma schema (creates all tables):

```bash
cd packages/core
pnpm db:push
cd ../..
```

Expected:

```
Your database is now in sync with your Prisma schema.
Generated Prisma Client
```

> Only needed once. Docker volume persists data between restarts.

---

## 5. Running the Project

---

### Mode A - CLI Quick Scan (no AI key needed)

Scans any public GitHub repo for vulnerable dependencies using OSV.

```bash
cd packages/core

# Basic scan
pnpm scan scan https://github.com/juice-shop/juice-shop

# Short form works too
pnpm scan scan OWASP/NodeGoat

# With NVD enrichment (needs NVD_API_KEY, slower but richer CVSS data)
pnpm scan scan juice-shop/juice-shop --use-nvd

# Skip dev dependencies
pnpm scan scan OWASP/NodeGoat --skip-dev

# Skip saving to database
pnpm scan scan snyk-labs/nodejs-goof --no-persist
```

---

### Mode B - Full Intelligence Analysis (Gemini key required)

Runs the complete 9-step pipeline:
Scan -> Metadata -> Embedding -> Knowledge Graph -> KEV Enrichment ->
RKG Enrichment -> Similar Repos -> Reasoning -> Validation -> RSIS

Start the API server first (Mode C), then call:

```bash
# Full analysis with all features
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{ "repoUrl": "juice-shop/juice-shop" }'

# Quick mode - no AI (useful without Gemini key)
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "repoUrl": "OWASP/NodeGoat",
    "skipEmbedding": true,
    "skipReasoning": true,
    "skipSimilarRepos": true
  }'
```

---

### Mode C - REST API Server

```bash
cd packages/api
pnpm dev
```

Expected output:

```
VulnShield Intelligence API running on http://localhost:3001
Endpoints:
   GET  /api/health
   POST /api/scan            { repoUrl: "owner/repo" }
   GET  /api/scan/:id
   GET  /api/scans
   POST /api/analyze         { repoUrl: "owner/repo" }
   GET  /api/analyze/:id
   GET  /api/analyze/:id/rsis
   GET  /api/similar/:id
   POST /api/evaluate        { scanId: "..." }
   GET  /api/evaluate/:id
```

Server watches for file changes - no restart needed during development.

---

### Mode D - Benchmark Suite

Runs the pipeline across 8 known-vulnerable public repositories.
Computes RSIS before and after simulated remediation for each.

```bash
cd packages/core

# All 8 repos
pnpm benchmark

# First 3 only (faster for demos)
pnpm benchmark --repos 3

# Custom output file name
pnpm benchmark --repos 5 --out my-results.json

# With NVD enrichment
pnpm benchmark --use-nvd --repos 3
```

> Needs GITHUB_TOKEN. Does NOT need GEMINI_API_KEY.

Repos benchmarked:
1. OWASP Juice Shop (npm)
2. OWASP NodeGoat (npm)
3. OWASP WebGoat (maven)
4. OWASP PyGoat (pypi)
5. DVNA - Damn Vulnerable Node App (npm)
6. nicowillis/VulnerableApp (npm)
7. OWASP RailsGoat (npm frontend deps)
8. thesp0nge/codebreaker (npm)

---

## 6. What to Expect - Screen-by-Screen

---

### CLI Scan (Mode A)

```
Scanning juice-shop/juice-shop...
Scan complete!

===============================================
  VulnShield - Scan Report
===============================================

Repository:  juice-shop/juice-shop
Scanned at:  2026-08-05T18:30:00.000Z
Total deps:  142
Total vulns: 31

Severity Breakdown:
  CRITICAL    4
  HIGH        14
  MEDIUM      9
  LOW         4

Vulnerable Dependencies (23/142):

  express@4.17.1 (npm, package.json)
     HIGH       CVE-2022-24999 (7.5)
       Prototype pollution in qs before 6.10.3
       Fix: upgrade to 4.17.3

  lodash@4.17.20 (npm, package.json)
     HIGH       CVE-2021-23337 (7.2)
       Command injection via template
       Fix: upgrade to 4.17.21

===============================================
```

---

### Full Intelligence Analysis - Server Logs (Mode B)

When you POST to /api/analyze, the API terminal prints each step live:

```
[Analyzer] Step 1/9: Dependency scanning (OSV)...
[Analyzer]   -> 142 dependencies scanned, 31 vulnerabilities found

[Analyzer] Step 2/9: Repository metadata extraction...
[Analyzer]   -> Language: JavaScript, Stars: 9841

[Analyzer] Step 3/9: Semantic chunking & hybrid embedding...
[Analyzer]   -> 847 chunks indexed

[Analyzer] Step 4/9: Constructing Repository Knowledge Graph...
[Analyzer]   -> Knowledge Graph built: 1243 nodes, 2891 edges

[Analyzer] Step 5/9: CISA KEV threat intel enrichment...
[Analyzer]   -> 3 KEV CVEs flagged
[Analyzer]   -> Enriching Knowledge Graph with threat intelligence...
[Analyzer]   -> Graph enriched: 1289 nodes, 2943 edges (+52 threat intel edges)

[Analyzer] Step 6/9: Discovering similar repositories & health signals...
[Analyzer]   -> 5 similar repos found (health scores: 82, 75, 71, 68, 55)

[Analyzer] Step 7/9: Evidence-grounded remediation reasoning (10 vulns)...
[Analyzer]   -> Reasoning complete for CVE-2022-24999
[Analyzer]   -> Reasoning complete for CVE-2021-23337

[Analyzer] Step 8/9: Candidate reranking (utility scoring)...
[Analyzer]   -> Ranked 10 remediation reports

[Analyzer] Step 9/9: Computing RSIS score...
[Analyzer]   -> RSIS: 42.3 (Grade: D)
```

Response JSON (key fields):

```json
{
  "scanId": "scan_abc123",
  "rsis": {
    "totalScore": 42.3,
    "grade": "D",
    "securityScore": 28.1,
    "retrievalScore": 15.4,
    "validationScore": 18.0,
    "maintainabilityScore": 10.2,
    "compatibilityScore": 9.6,
    "rationale": {
      "formula": "RSIS = w1·Security + w2·Retrieval + w3·Validation + w4·Maintainability + w5·Compatibility",
      "citations": ["NIST SP 800-161 Rev.1", "CVSS v3.1 Specification", "ISO/IEC 25010"]
    }
  },
  "remediations": [
    {
      "cveId": "CVE-2022-24999",
      "packageName": "express",
      "candidates": [
        {
          "rank": 1,
          "action": "upgrade",
          "proposedVersion": "4.17.3",
          "confidence": 0.847,
          "rankingFeatures": {
            "compatibilityScore": 1.0,
            "securityGainScore": 0.75,
            "evidenceStrengthScore": 0.60,
            "utilityScore": 0.847
          },
          "chainOfReasoning": [
            {
              "stepNumber": 1,
              "observation": "express@4.17.1 imported in src/routes/api.ts:L15",
              "deduction": "Upgrading to 4.17.3 is a patch — backward compatible"
            }
          ],
          "evidence": [
            {
              "filePath": "src/routes/api.ts",
              "startLine": 15,
              "codeSnippet": "import express from 'express'",
              "relevance": "Direct import of vulnerable package"
            }
          ]
        }
      ]
    }
  ]
}
```

---

### Benchmark Output (Mode D)

```
============================================================
  RSIS Benchmark Suite - 8 repositories
============================================================

[1/8] OWASP Juice Shop (juice-shop/juice-shop)
   v RSIS: 42.1 -> 71.4 (+29.3)  Grade: D -> C  Vulns: 31  Fixable: 74%  KEV: 3  Scan: 4821ms

[2/8] OWASP NodeGoat (OWASP/NodeGoat)
   v RSIS: 38.5 -> 68.9 (+30.4)  Grade: D -> C  Vulns: 18  Fixable: 83%  KEV: 1  Scan: 3102ms

[3/8] OWASP WebGoat (WebGoat/WebGoat)
   v RSIS: 51.2 -> 79.3 (+28.1)  Grade: F -> C  Vulns: 24  Fixable: 71%  KEV: 0  Scan: 5544ms

...

------------------------------------------------------------
  BENCHMARK SUMMARY
------------------------------------------------------------
  Repos:             7/8 successful
  Mean RSIS Before:  44.2
  Mean RSIS After:   73.6
  Mean Delta:        +29.4
------------------------------------------------------------

Benchmark report saved to: benchmark-results.md
Benchmark JSON saved to:   benchmark-results.json
```

Output files written to packages/core/:
- benchmark-results.md  - Markdown with grade tables and ASCII score bars
- benchmark-results.json - Machine-readable JSON

---

## 7. API Reference

Server: http://localhost:3001

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| GET | /api/health | - | Liveness check |
| POST | /api/scan | { repoUrl, useNVD?, skipDev? } | Basic OSV scan |
| GET | /api/scan/:id | - | Fetch scan by ID |
| GET | /api/scans | - | Last 50 scans |
| POST | /api/analyze | { repoUrl, useNVD?, skipDev?, skipEmbedding?, skipSimilarRepos?, skipReasoning?, maxRemediations? } | Full pipeline |
| GET | /api/analyze/:id | - | Full analysis result |
| GET | /api/analyze/:id/rsis | - | RSIS score breakdown |
| GET | /api/similar/:id | - | Similar repositories |
| POST | /api/evaluate | { scanId } | Run ML evaluation metrics |
| GET | /api/evaluate/:id | - | Fetch evaluation results |

### /api/analyze options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| repoUrl | string | required | owner/repo or full URL |
| useNVD | boolean | false | Enrich with NVD CVSS data |
| skipDev | boolean | false | Exclude devDependencies |
| skipEmbedding | boolean | false | Skip vector indexing |
| skipSimilarRepos | boolean | false | Skip repo discovery |
| skipReasoning | boolean | false | Skip AI reasoning |
| maxRemediations | number | 10 | Max CVEs to reason over |

---

## 8. Configurable Weight System

Both RSIS and Evidence Strength weights are loaded from .env - not hardcoded.

### RSIS 5-Dimension Weights

```ini
# Based on: NIST SP 800-161, CVSS v3.1, ISO/IEC 25010
# Must sum to 1.0 (auto-normalised if not)
RSIS_WEIGHT_SECURITY=0.30        # CVSS severity & KEV penalty
RSIS_WEIGHT_RETRIEVAL=0.20       # Hybrid BM25+Dense retrieval quality
RSIS_WEIGHT_VALIDATION=0.20      # Registry + OSV re-scan outcome
RSIS_WEIGHT_MAINTAINABILITY=0.15 # ISO/IEC 25010 maintainability
RSIS_WEIGHT_COMPATIBILITY=0.15   # SemVer upgrade breakage risk
```

### Evidence Strength Source Weights

```ini
# Must sum to 1.0 (auto-normalised if not)
EVIDENCE_WEIGHT_OSV=0.20          # OSV community database
EVIDENCE_WEIGHT_NVD=0.20          # NIST NVD
EVIDENCE_WEIGHT_GITHUB=0.25       # GitHub Security Advisories
EVIDENCE_WEIGHT_KEV=0.20          # CISA Known Exploited Vulnerabilities
EVIDENCE_WEIGHT_SIMILAR_REPO=0.15 # Peer repository adoption signal
```

> If asked "why GitHub at 25%?" the answer is:
> "These are configurable default values. The framework supports any weighting
> scheme - tune them via ablation experiments or your organisation's trust model."

---

## 9. Running Tests

```bash
# From project root
pnpm test

# From core package (faster)
cd packages/core && pnpm test
```

Expected:

```
v tests/parsers.test.ts    (9 tests)
v tests/intelligence.test.ts (31 tests)

Test Files  2 passed (2)
     Tests  40 passed (40)
  Duration  ~1.5s
```

Coverage:
- Manifest parsers (npm, maven, pypi)
- RSISScorer - 5-dimension scoring, literature rationale, severity ordering
- CandidateRanker - evidence strength, ranking features, rejected vs validated
- RepoKnowledgeGraphBuilder - structural build + enrichment (CVSSNode, KEVNode, PatchNode)
- Hybrid retrieval metrics (P@K, Recall@K, MRR, nDCG, Top-1/3 Accuracy, BSR)
- Benchmark simulation (before/after RSIS, unfixable vuln preservation)
- Configurable evidence weights

---

## 10. Troubleshooting

### GITHUB_TOKEN not set warning
Add it to .env. Without it, GitHub API limits to 60 requests/hour.
Large repo scans will fail mid-way.

### Database connection refused
```bash
docker-compose up -d    # start container
docker ps               # verify vulnshield-db is Running
```
Default port is 5433 (not 5432) to avoid conflicts with local Postgres.

### AI features silently skipped
If GEMINI_API_KEY is missing, embedding and reasoning steps auto-skip.
The scan still runs and RSIS is still computed in heuristic mode.

### Build errors
```bash
pnpm install    # re-link workspace packages
pnpm build      # should show zero TypeScript errors
```

### Benchmark repos failing
Check GITHUB_TOKEN is valid. Some repos may have been renamed on GitHub.
Edit packages/core/src/benchmark/benchmark-repos.ts to update or remove them.

### Slow analysis on large repos
Pass these to /api/analyze:
- skipDev: true        - skip dev-only dependencies
- skipEmbedding: true  - skip chunk indexing (speeds up 60-70%)
- skipSimilarRepos: true - skip GitHub search
- maxRemediations: 3   - limit CVEs sent to reasoning engine

---

## Quick Reference

```bash
# One-time setup
pnpm install && pnpm build
cp .env.example .env
docker-compose up -d
cd packages/core && pnpm db:push && cd ../..

# Mode A - CLI scan
cd packages/core
pnpm scan scan juice-shop/juice-shop

# Mode C - Start API server (separate terminal)
cd packages/api && pnpm dev

# Mode B - Full analysis (API must be running)
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{ "repoUrl": "OWASP/NodeGoat" }'

# Mode D - Benchmark
cd packages/core && pnpm benchmark --repos 5

# Tests
pnpm test
```
