# ─── VulnShield API Dockerfile ─────────────────────────────────────────────
# Build from repo root:  docker build -f packages/api/Dockerfile -t vulnshield-api .
# Run:                   docker run --rm -p 3001:3001 --env-file .env vulnshield-api

# 1. Dependencies — installs from the pnpm lockfile only (reproducible).
FROM node:20-alpine AS deps
WORKDIR /repo
RUN corepack enable
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./
COPY packages/api/package.json   packages/api/
COPY packages/core/package.json packages/core/
COPY packages/web/package.json   packages/web/
RUN pnpm install --frozen-lockfile --filter @vuln-shield/api... --filter @vuln-shield/core

# 2. Build — produces dist/ for core and dist/ for api.
FROM node:20-alpine AS build
WORKDIR /repo
RUN corepack enable
COPY --from=deps /repo /repo
COPY tsconfig.base.json ./
COPY packages/api   packages/api
COPY packages/core  packages/core
RUN pnpm --filter @vuln-shield/core build
RUN pnpm --filter @vuln-shield/api  build

# 3. Prune — keeps only the api's runtime deps + the built core.
FROM node:20-alpine AS prune
WORKDIR /repo
RUN corepack enable
COPY --from=build /repo /repo
RUN pnpm deploy --filter @vuln-shield/api --prod /out

# 4. Runtime — minimal image, non-root user, healthcheck.
FROM node:20-alpine AS runtime
WORKDIR /app
RUN addgroup -S app && adduser -S app -G app
COPY --from=prune --chown=app:app /out /app
COPY --chown=app:app packages/api/dist /app/dist
USER app
ENV NODE_ENV=production
ENV PORT=3001
EXPOSE 3001
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3001/api/health || exit 1
CMD ["node", "dist/server.js"]
