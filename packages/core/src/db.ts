import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Load environment variables. The repo root .env lives at:
//   <repo>/.env           (for monorepo dev)
//   packages/core/.env    (package-local override, optional)
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const repoRoot   = path.resolve(__dirname, "../../../");

dotenv.config({ path: path.join(repoRoot, ".env") });
dotenv.config({ path: path.join(repoRoot, "packages/core/.env") });

let prisma: PrismaClient | null = null;

/**
 * Get the Prisma client singleton.
 * Lazy-initializes on first call.
 */
export function getDB(): PrismaClient {
  if (!prisma) {
    prisma = new PrismaClient();
  }
  return prisma;
}

/**
 * Disconnect the Prisma client (call on shutdown).
 */
export async function disconnectDB(): Promise<void> {
  if (prisma) {
    await prisma.$disconnect();
    prisma = null;
  }
}
