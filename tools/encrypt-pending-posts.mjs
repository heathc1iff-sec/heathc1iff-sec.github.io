import fs from "node:fs/promises";
import path from "node:path";
import yaml from "js-yaml";
import { encryptPostFile } from "./post-encrypt.mjs";

const FRONTMATTER_PATTERN = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;
const BLOG_DIR = path.resolve(process.cwd(), "src/content/blog");

async function getMarkdownFiles(dir) {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const files = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...(await getMarkdownFiles(fullPath)));
      continue;
    }

    if (entry.isFile() && (entry.name.endsWith(".md") || entry.name.endsWith(".mdx"))) {
      files.push(fullPath);
    }
  }

  return files;
}

function needsEncryption(content) {
  const match = content.match(FRONTMATTER_PATTERN);
  if (!match) {
    return false;
  }

  const meta = yaml.load(match[1]) ?? {};
  if (typeof meta !== "object" || Array.isArray(meta)) {
    return false;
  }

  return (
    meta.encryption === true &&
    typeof meta.password === "string" &&
    meta.password.length > 0
  );
}

async function main() {
  const markdownFiles = await getMarkdownFiles(BLOG_DIR);
  const pendingFiles = [];

  for (const filePath of markdownFiles) {
    const content = await fs.readFile(filePath, "utf8");
    if (needsEncryption(content)) {
      pendingFiles.push(filePath);
    }
  }

  if (pendingFiles.length === 0) {
    console.log("[encrypt-pending] No plaintext encrypted posts found.");
    return;
  }

  for (const filePath of pendingFiles) {
    const relativePath = path.relative(process.cwd(), filePath).replace(/\\/g, "/");
    await encryptPostFile(relativePath);
    console.log(`[encrypt-pending] Encrypted ${relativePath}`);
  }
}

main().catch((error) => {
  console.error(`[encrypt-pending] ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});
