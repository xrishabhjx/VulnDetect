import { PrismaClient } from "@prisma/client";
import dotenv from "dotenv";

// Load environment variables
dotenv.config({ path: "../../.env" });
dotenv.config({ path: ".env" });

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
