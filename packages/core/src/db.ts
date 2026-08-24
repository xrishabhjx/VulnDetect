import path from "node:path";
import { fileURLToPath } from "node:url";
import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables from the true workspace root and prefer the latest values.
dotenv.config({ path: path.resolve(__dirname, "../../../.env"), override: true });

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
