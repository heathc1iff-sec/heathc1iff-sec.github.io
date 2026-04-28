import { rm } from "node:fs/promises";
import path from "node:path";

const cacheDir = path.resolve("node_modules/.astro");

try {
  await rm(cacheDir, { recursive: true, force: true });
  console.log(`[clean-astro-cache] Removed ${cacheDir}`);
} catch (error) {
  console.error(`[clean-astro-cache] Failed to remove ${cacheDir}`);
  throw error;
}
