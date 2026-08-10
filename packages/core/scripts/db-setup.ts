#!/usr/bin/env tsx
/**
 * db-setup — bring the database from zero to ready in one command.
 *
 * Steps:
 *   1. Load env from the repo root .env (same resolution as core/src/db.ts).
 *   2. `prisma db push` to apply the schema.
 *      The `extensions = [vector]` directive in schema.prisma tells Prisma
 *      to `CREATE EXTENSION IF NOT EXISTS vector` automatically.
 *   3. Apply prisma/enable_vector.sql to build the HNSW index used by
 *      hybrid BM25 + dense retrieval.
 *
 * Usage:
 *   pnpm --filter @vuln-shield/core db:setup
 *
 * Requires:
 *   - `psql` on PATH (or set PSQL_BIN to its absolute path).
 *   - DATABASE_URL in the environment (loaded from .env if not set).
 */

import { spawn } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const repoRoot   = path.resolve(__dirname, "../../../");
const sqlFile    = path.resolve(__dirname, "../prisma/enable_vector.sql");

// Load env from the same locations as the rest of the core package.
dotenv.config({ path: path.join(repoRoot, ".env") });
dotenv.config({ path: path.join(repoRoot, "packages/core/.env") });

const RED   = "\x1b[31m";
const GREEN = "\x1b[32m";
const CYAN  = "\x1b[36m";
const RESET = "\x1b[0m";

function log(step: string, msg: string) {
  console.log(`${CYAN}[db-setup]${RESET} ${step}  ${msg}`);
}

function fail(msg: string): never {
  console.error(`${RED}[db-setup] ✘${RESET} ${msg}`);
  process.exit(1);
}

function run(cmd: string, args: string[], opts: { input?: string } = {}): Promise<number> {
  return new Promise((resolve, reject) => {
    log("$", `${cmd} ${args.join(" ")}`);
    const child = spawn(cmd, args, {
      stdio: ["pipe", "inherit", "inherit"],
      shell: process.platform === "win32", // .cmd / .bat shims on Windows
    });

    child.on("error", reject);
    child.on("exit", (code) => resolve(code ?? 1));

    if (opts.input !== undefined) {
      child.stdin?.on("error", () => {
        // psql may close stdin early if it doesn't need input; ignore.
      });
      child.stdin?.write(opts.input);
      child.stdin?.end();
    }
  });
}

async function step1_validate(): Promise<void> {
  const url = process.env.DATABASE_URL;
  if (!url) {
    fail("DATABASE_URL is not set. Copy .env.example to .env at the repo root first.");
  }
  if (!existsSync(sqlFile)) {
    fail(`SQL file not found at ${sqlFile}`);
  }
  log("✓", `DATABASE_URL present, SQL file found at ${path.relative(repoRoot, sqlFile)}`);
}

async function step2_prismaPush(): Promise<void> {
  log(
    "→",
    "Running `prisma db push` (this also installs the `vector` extension)..."
  );
  // --accept-data-loss is required when the live schema has columns the
  // local schema no longer declares (e.g. an older `securityScore` field).
  // The id is preserved on `Scan`, so historical rows survive.
  const code = await run(
    "pnpm",
    ["exec", "prisma", "db", "push", "--accept-data-loss"],
    { input: "" }
  );
  if (code !== 0) fail(`prisma db push exited with code ${code}`);
  log("✓", "Prisma schema applied + Prisma Client regenerated");
}

async function step3_enableVector(): Promise<void> {
  const sql = readFileSync(sqlFile, "utf8");
  const psql = process.env.PSQL_BIN || "psql";
  const url = process.env.DATABASE_URL!;

  log("→", `Applying ${path.relative(repoRoot, sqlFile)} via ${psql}...`);
  const code = await run(psql, [url, "-v", "ON_ERROR_STOP=1", "-f", sqlFile], {
    input: sql,
  });
  if (code !== 0) {
    fail(
      `psql exited with code ${code}.\n` +
        `  - Is Postgres reachable at $DATABASE_URL?\n` +
        `  - Is the pgvector image running? (docker compose up -d postgres)\n` +
        `  - If psql is not on PATH, set PSQL_BIN=/path/to/psql`
    );
  }
  log("✓", "HNSW index ready — hybrid BM25 + dense retrieval is enabled");
}

async function main() {
  console.log(`${GREEN}┌── VulnShield database setup ─────────────────────────${RESET}`);
  await step1_validate();
  await step2_prismaPush();
  await step3_enableVector();
  console.log(`${GREEN}└── ✅ Database is ready. Run \`pnpm dev:api\` next. ───${RESET}\n`);
}

main().catch((err) => {
  console.error("[db-setup] Unexpected error:", err);
  process.exit(1);
});
