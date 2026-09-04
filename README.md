# VulnDetect

VulnDetect scans public GitHub repositories for dependency vulnerabilities and can run a fuller repository-security analysis with a knowledge graph, remediation candidates, and an RSIS score. It is a TypeScript pnpm workspace with a Next.js dashboard, Express API, PostgreSQL/pgvector database, and a CLI.

## Quick start

Prerequisites: Node.js 20 or newer (Node 22 recommended), pnpm, and Docker Desktop.

```powershell
git clone <repository-url>
cd VulnDetect
corepack enable
pnpm install

Copy-Item .env.example .env
# Prisma loads its environment from this package when its CLI is run.
Copy-Item .env packages\core\.env

docker compose up -d
pnpm --filter @vuln-shield/core db:push
pnpm dev
```

Open the dashboard at http://localhost:3000. The API runs at http://localhost:3005; check it with http://localhost:3005/api/health.

On macOS or Linux, use `cp .env.example .env` and `cp .env packages/core/.env` in place of the `Copy-Item` commands.

## Configuration

Start from `.env.example`. Never commit `.env` or `packages/core/.env`; replace any keys that were previously shared or exposed.

| Variable | Purpose | Required |
| --- | --- | --- |
| `DATABASE_URL` | PostgreSQL connection string; defaults match `docker-compose.yml`. | Yes |
| `GITHUB_TOKEN` | Raises GitHub API limits and is recommended for repository analysis. | Recommended |
| `NVD_API_KEY` | Enables richer NVD enrichment and higher NVD API limits. | Optional |
| `GROQ_API_KEY` | Primary LLM provider for remediation reasoning. | Optional |
| `GEMINI_API_KEY` | Fallback LLM provider and optional embeddings provider. | Optional |
| `GROQ_MODEL` | Groq reasoning model. | Optional |
| `GEMINI_MODEL` | Gemini reasoning model; default: `gemini-flash-latest`. | Optional |
| `GEMINI_EMBED_MODEL` | Gemini embeddings model. | Optional |
| `PORT` | API port; default: `3005`. | Optional |
| `WEB_ORIGIN` | Comma-separated dashboard origins allowed by API CORS. | Optional |

The application uses evidence-based heuristic fallbacks if an AI provider is unavailable. An HTTP 429 from a provider does not invalidate a scan; restart after changing keys or model settings.

## Running the app

`pnpm dev` starts PostgreSQL (via Docker Compose), the API, and the dashboard. To run them separately:

```powershell
pnpm --filter @vuln-shield/api dev
pnpm --filter @vuln-shield/web dev
```

Submit a public GitHub repository URL or `owner/repository` in the dashboard. Use a quick scan for dependency findings or full analysis for repository profiling, retrieval, graph construction, remediation ranking, and RSIS scoring.

Full analysis is synchronous and may take several minutes for a large repository or slow external provider. Dashboard progress is estimated; the API does not yet stream pipeline status.

## API and CLI

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scan` | Dependency vulnerability scan |
| `POST` | `/api/analyze` | Full repository-security analysis |
| `GET` | `/api/scans` | Recent scan records |
| `GET` | `/api/scan/:scanId` | Scan and its findings |
| `GET` | `/api/analysis/:scanId` | Saved full-analysis output |
| `GET` | `/api/rsis/:scanId` | RSIS score |
| `GET` | `/api/similar/:scanId` | Similar-repository evidence |

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:3005/api/scan `
  -ContentType 'application/json' `
  -Body '{"repoUrl":"OWASP/NodeGoat"}'
```

Start the interactive CLI with:

```powershell
pnpm --filter @vuln-shield/core scan
```

## Development checks

```powershell
pnpm --filter @vuln-shield/core test
pnpm --filter @vuln-shield/core build
pnpm --filter @vuln-shield/api build
pnpm --filter @vuln-shield/web build
```

Some integration tests call external vulnerability services, so they need network access and can be affected by provider rate limits. Unit and type checks do not require API keys.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| Prisma reports `DATABASE_URL` is missing | Ensure root `.env` exists, then copy it to `packages/core/.env` before running `db:push`. |
| API cannot connect to PostgreSQL | Run `docker compose up -d`, confirm the container is healthy, and check `DATABASE_URL`. |
| Dashboard cannot reach API | Confirm the API is on port `3005` and `packages/web/.env.local` uses `NEXT_PUBLIC_API_URL=http://localhost:3005`; restart Next.js afterward. |
| Gemini reports an unavailable model | Set `GEMINI_MODEL=gemini-flash-latest`, then restart the API. Availability varies by account and region. |
| Groq or Gemini returns 429 | Wait for quota reset or configure another provider; heuristic remediation remains available. |

## Project layout

```text
packages/core  Scanner, analyzer, Prisma schema, CLI, intelligence pipeline
packages/api   Express REST API
packages/web   Next.js dashboard
scripts        Local development launcher
```

For dashboard-specific notes, see [packages/web/README.md](packages/web/README.md). The visual design reference is [DESIGN_SYSTEM.md](DESIGN_SYSTEM.md).
