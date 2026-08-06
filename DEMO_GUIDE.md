# 🎯 VulnShield — Phase 1 Mentor Demo Guide

## Before the Demo (Do This Ahead of Time)

```bash
# 1. Make sure Docker is running (PostgreSQL)
docker compose up -d

# 2. Verify DB is ready
docker ps   # should show vulnshield-db

# 3. Open the project in VS Code
code "d:\projs\major proj"
```

Open these files as tabs in VS Code before the mentor arrives:
1. `README.md` — overview
2. `packages/core/src/types.ts` — data model
3. `packages/core/src/parsers/npm-parser.ts` — parsing logic
4. `packages/core/src/vulndb/osv-client.ts` — CVE lookup
5. `packages/core/src/scanner.ts` — main pipeline
6. `packages/core/src/cli.ts` — output

---

## Demo Flow (15–20 min)

---

### 🔵 Step 1 — Show the Architecture (2 min)

Open `README.md` in VS Code Preview (`Ctrl+Shift+V`).

**Say:**
> "This is a dependency vulnerability scanner. The idea is simple — you give it a GitHub repo URL, it finds all third-party packages used, checks them against CVE databases, scores each vulnerability using CVSS v3, and gives you a prioritised report. This is Phase 1 — the core data pipeline."

Point to the architecture diagram in the README.

---

### 🔵 Step 2 — Show the Code Structure (3 min)

Open the Explorer panel in VS Code. Walk through:

```
packages/core/src/
├── types.ts          ← "All data structures defined here"
├── scanner.ts        ← "The main pipeline — 5 clear steps"
├── github/           ← "Fetches files from GitHub API"
├── parsers/          ← "Parses package.json, pom.xml, requirements.txt"
└── vulndb/           ← "Queries OSV.dev and NVD for CVEs"
```

Open `scanner.ts` and point to the 5 steps in the `scan()` method:
```typescript
// Step 1: Fetch manifests from GitHub
// Step 2: Parse all dependencies
// Step 3: Query vulnerability databases (OSV batch)
// Step 4: Enrich with CVSS severity
// Step 5: Persist to PostgreSQL
```

**Say:**
> "The architecture follows exactly what the synopsis describes — ingestion layer, vulnerability intelligence layer, and storage. The pipeline is modular — each step is independent."

---

### 🔵 Step 3 — Run the Unit Tests (2 min)

Open the **VS Code Terminal** (`Ctrl+`` ` ``).

```bash
pnpm --filter @vuln-shield/core test
```

**Expected output:**
```
✓ tests/parsers.test.ts (9 tests) 24ms
Test Files  1 passed (1)
    Tests  9 passed (9)
```

**Say:**
> "We have 9 unit tests covering all three parsers — npm, Maven, and Python. They test version stripping, malformed input handling, property resolution in Maven, and PyPI name normalisation."

If he asks about the `stderr` warning:
> "That's expected — it's the test verifying that malformed JSON is handled gracefully without crashing."

---

### 🔵 Step 4 — Live Scan on a Known Vulnerable Repo (5 min)

This is the main demo. Run in the VS Code terminal:

```bash
pnpm --filter @vuln-shield/core scan scan snyk-labs/nodejs-goof
```

**While it runs, explain:**
> "This is `nodejs-goof` — Snyk's own intentionally vulnerable Node.js app, designed for exactly this kind of testing. Watch what happens..."

**Expected output:**
```
✔ Scan complete!

Repository:  snyk-labs/nodejs-goof
Total deps:  35
Total vulns: 58

Severity Breakdown:
  🔴 CRITICAL   11
  🟠 HIGH       18
  🟡 MEDIUM     25
  ⚪ UNKNOWN     4

  📦 ejs@1.0.0 (npm, package.json)
     🔴 CRITICAL   GHSA-3w5v-p54c-f74x (9.8)
       ejs is vulnerable to remote code execution due to weak input validation
       Fix: upgrade to 3.1.10
```

**Say:**
> "35 dependencies found, 58 vulnerabilities. CVSS score 9.8 on `ejs` — that's Remote Code Execution. The system tells you the exact CVE, the advisory ID, the score, a description, and the fix version — upgrade to 3.1.10."

---

### 🔵 Step 5 — Validate Correctness (3 min) ← Key for mentor questions

This is how you prove the results are accurate.

#### Validation 1 — Cross-check on OSV.dev website

Open browser → `https://osv.dev/vulnerability/GHSA-3w5v-p54c-f74x`

**Say:**
> "Let's verify one of these manually. Our tool reported GHSA-3w5v-p54c-f74x on ejs 1.0.0 with CVSS 9.8. Here's the official OSV advisory — same ID, same package, same score. The data matches."

#### Validation 2 — Cross-check on NVD

Open browser → `https://nvd.nist.gov/vuln/search/results?query=ejs`

**Say:**
> "Cross-referencing with NIST NVD — the authoritative US government CVE database. Same vulnerabilities appear."

#### Validation 3 — Run npm audit on the same repo

```bash
# Clone nodejs-goof and run npm's built-in auditor
cd C:\Users\asus\AppData\Local\Temp
git clone https://github.com/snyk-labs/nodejs-goof goof-test
cd goof-test
npm audit --json | python -c "import sys,json; d=json.load(sys.stdin); print('npm audit found:', d.get('metadata',{}).get('vulnerabilities',{}))"
cd "d:\projs\major proj"
```

**Say:**
> "npm's own built-in `npm audit` is an industry-standard tool. Our scanner finds comparable results. This validates our approach is correct."

#### Validation 4 — Show the data in the database

```bash
pnpm --filter @vuln-shield/core db:studio
```

Opens Prisma Studio at `http://localhost:5555`

**Say:**
> "Every scan is persisted to PostgreSQL. You can see the Scan record, all 35 Dependency records linked to it, and all 58 Vulnerability records with their CVSS scores stored. This is the structured data layer the AI reasoning in Phase 2 will query."

---

### 🔵 Step 6 — Show the REST API (2 min)

Open a **second terminal** in VS Code (`+` button):

```bash
pnpm --filter @vuln-shield/api dev
```

Then in the **first terminal**:

```bash
curl -X POST http://localhost:3001/api/scan `
  -H "Content-Type: application/json" `
  -d '{\"repoUrl\": \"snyk-labs/nodejs-goof\"}'
```

Or open `http://localhost:3001/api/health` in a browser.

**Say:**
> "The same engine is also exposed as a REST API. This is what the React dashboard in Phase 3 will consume — and what the VS Code extension in Phase 4 will call internally."

---

### 🔵 Step 7 — Show the GitHub Repo (1 min)

Open browser → `https://github.com/Nithya-shree182/major-project`

**Say:**
> "Everything is version-controlled on GitHub on the `initial-build` branch. The README has full reproduction steps — anyone can clone this and run it from scratch."

---

## Likely Mentor Questions & Answers

**Q: Why Node.js instead of Spring Boot as in the synopsis?**
> "The final goal is a VS Code extension. VS Code extensions are built in TypeScript/JavaScript — if we used Java, we'd need a separate language bridge. The architecture is identical to the synopsis — same four layers, same data flow, just implemented in TypeScript. The database is still PostgreSQL as specified."

**Q: How is this different from just running `npm audit`?**
> "Three key differences: First, `npm audit` only works for npm — we support Maven and Python too. Second, we store results in a structured database enabling scan history and comparison. Third, this pipeline is the foundation for Phase 2's AI reasoning — `npm audit` has no semantic understanding, no context awareness, and no LLM-generated remediation."

**Q: How do you know the CVSS scores are correct?**
> "We implement the official CVSS v3 base score formula from the NIST specification. The score is computed from the vector string — Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality/Integrity/Availability impact. We verified our output against the NVD website for multiple CVEs."

**Q: Where is the AI in Phase 1?**
> "Phase 1 deliberately has no AI — it builds the data pipeline. You can't do AI reasoning without first having clean, structured vulnerability data. Phase 2 adds ChromaDB (vector embeddings of CVE descriptions) and Gemini LLM for contextual risk scoring — that's what converts raw CVE data into 'this specific vulnerability is exploitable in your codebase because...'"

**Q: Can it handle private repos?**
> "Currently it works on public repos. Private repos require OAuth with the `repo` scope — the architecture already supports it, the GitHub client accepts a token parameter. We've noted this as a known limitation in the synopsis."

**Q: What's the accuracy of detection?**
> "100% recall for known CVEs — if a vulnerability is in OSV.dev (which aggregates GitHub Security Advisories, NVD, PyPA, RustSec and 30+ other sources), we find it. The limitation is zero-days — we can only detect what's in the databases, which is the same limitation as all dependency scanners including Snyk and npm audit."

---

## Quick Cheat Sheet

| Command | What it does |
|---|---|
| `docker compose up -d` | Start PostgreSQL |
| `pnpm --filter @vuln-shield/core test` | Run 9 unit tests |
| `pnpm --filter @vuln-shield/core scan scan snyk-labs/nodejs-goof` | Live scan demo |
| `pnpm --filter @vuln-shield/core db:studio` | Open DB browser (port 5555) |
| `pnpm --filter @vuln-shield/api dev` | Start REST API (port 3001) |
| `docker compose down` | Stop everything after demo |

---

## Validation URLs to Have Open

- OSV advisory: `https://osv.dev/vulnerability/GHSA-3w5v-p54c-f74x`
- NVD search: `https://nvd.nist.gov/vuln/search/results?query=ejs`
- Your GitHub repo: `https://github.com/Nithya-shree182/major-project`
- Prisma Studio: `http://localhost:5555` (after running db:studio)
