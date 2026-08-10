# ─── VulnShield Web Dockerfile ─────────────────────────────────────────────
# Build from repo root:  docker build -f packages/web/Dockerfile -t vulnshield-web \
#                          --build-arg NEXT_PUBLIC_API_URL=http://api:3001 .
# Run:                   docker run --rm -p 3000:3000 vulnshield-web

# 1. Dependencies.
FROM node:20-alpine AS deps
WORKDIR /repo
RUN corepack enable
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./
COPY packages/api/package.json   packages/api/
COPY packages/core/package.json packages/core/
COPY packages/web/package.json   packages/web/
RUN pnpm install --frozen-lockfile --filter @vuln-shield/web...

# 2. Build — NEXT_PUBLIC_* must be inlined at build time.
FROM node:20-alpine AS build
WORKDIR /repo
ARG NEXT_PUBLIC_API_URL=http://localhost:3001
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
RUN corepack enable
COPY --from=deps /repo /repo
COPY tsconfig.base.json ./
COPY packages/web packages/web
RUN pnpm --filter @vuln-shield/web build

# 3. Runtime — Next.js standalone output.
FROM node:20-alpine AS runtime
WORKDIR /app
RUN addgroup -S app && adduser -S app -G app
ENV NODE_ENV=production
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
COPY --from=build --chown=app:app /repo/packages/web/public      ./public
COPY --from=build --chown=app:app /repo/packages/web/.next/standalone ./
COPY --from=build --chown=app:app /repo/packages/web/.next/static     ./.next/static
USER app
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/ || exit 1
CMD ["node", "server.js"]
