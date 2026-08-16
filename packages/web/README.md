# VulnShield Web Dashboard

The Next.js dashboard for VulnShield. It submits quick scans and full analyses to the Express API, and renders findings, RSIS scores, remediation candidates, similar repositories, and the knowledge graph.

## Run locally

From the repository root, configure the API URL once:

```powershell
Copy-Item packages\web\.env.local.example packages\web\.env.local
```

`packages/web/.env.local` should contain:

```env
NEXT_PUBLIC_API_URL=http://localhost:3005
```

Start the API and dashboard together from the root with `pnpm dev`, or start only this package after the API is running:

```powershell
pnpm --filter @vuln-shield/web dev
```

The dashboard is served on http://localhost:3000.

## Checks

```powershell
pnpm --filter @vuln-shield/web build
```

Restart Next.js whenever `NEXT_PUBLIC_API_URL` changes because `NEXT_PUBLIC_` values are included in the client bundle.

## Current behavior and limitations

- Full analysis is a synchronous API request and can take several minutes.
- The progress UI is an estimate; the API does not stream pipeline status yet.
- The force-directed knowledge graph loads only in the browser to avoid server-rendering errors.
- API keys and database setup belong in the root project setup; see the [root README](../../README.md).
