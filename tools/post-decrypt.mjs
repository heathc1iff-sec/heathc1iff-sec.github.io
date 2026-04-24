import fs from "node:fs/promises";
import path from "node:path";
import { createDecipheriv, createHash, pbkdf2Sync } from "node:crypto";
import { pathToFileURL } from "node:url";
import yaml from "js-yaml";

const FRONTMATTER_PATTERN = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

function usage() {
  console.error("Usage: npm run decrypt:post -- <markdown-file> <password>");
}

function parseMarkdownFile(content) {
  const match = content.match(FRONTMATTER_PATTERN);
  if (!match) {
    throw new Error("Invalid markdown file: missing frontmatter block.");
  }

  return {
    frontmatterRaw: match[1],
    body: match[2],
  };
}

function requireString(meta, key) {
  const value = meta[key];
  if (typeof value !== "string" || !value) {
    throw new Error(`Missing required encrypted field: ${key}`);
  }
  return value;
}

async function main() {
  const targetFile = process.argv[2];
  const password = process.argv[3];

  if (!targetFile || !password) {
    usage();
    process.exit(1);
  }

  const decryptedFile = await decryptPostFile(targetFile, password);
  console.log(`[decrypt-post] Decrypted ${decryptedFile}`);
}

export async function decryptPostFile(targetFile, password) {
  const resolvedPath = path.resolve(process.cwd(), targetFile);
  const source = await fs.readFile(resolvedPath, "utf8");
  const { frontmatterRaw } = parseMarkdownFile(source);

  const metaRaw = yaml.load(frontmatterRaw) ?? {};
  if (typeof metaRaw !== "object" || Array.isArray(metaRaw)) {
    throw new Error("Frontmatter must be a YAML object.");
  }

  const meta = { ...metaRaw };

  const passwordHash = requireString(meta, "passwordHash");
  if (createHash("sha256").update(password).digest("hex") !== passwordHash) {
    throw new Error("Password does not match this encrypted post.");
  }

  const iterationsRaw = meta.encryptionIterations;
  if (
    typeof iterationsRaw !== "number" ||
    !Number.isInteger(iterationsRaw) ||
    iterationsRaw <= 0
  ) {
    throw new Error("Invalid encryptionIterations value.");
  }

  const salt = Buffer.from(requireString(meta, "encryptionSalt"), "base64");
  const iv = Buffer.from(requireString(meta, "encryptionIv"), "base64");
  const tag = Buffer.from(requireString(meta, "encryptionTag"), "base64");
  const cipherText = Buffer.from(requireString(meta, "encryptionContent"), "base64");

  const key = pbkdf2Sync(password, salt, iterationsRaw, 32, "sha256");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);

  const markdown = Buffer.concat([decipher.update(cipherText), decipher.final()]).toString("utf8");

  delete meta.passwordHash;
  delete meta.encryptionSalt;
  delete meta.encryptionIv;
  delete meta.encryptionTag;
  delete meta.encryptionContent;
  delete meta.encryptionIterations;
  delete meta.encryptedWordCount;
  delete meta.encryptedReadTime;

  meta.encryption = true;
  meta.password = password;

  const serializedFrontmatter = yaml
    .dump(meta, {
      lineWidth: -1,
      noRefs: true,
    })
    .trimEnd();

  const output = `---\n${serializedFrontmatter}\n---\n\n${markdown.endsWith("\n") ? markdown : `${markdown}\n`}`;
  await fs.writeFile(resolvedPath, output, "utf8");

  return path.relative(process.cwd(), resolvedPath);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`[decrypt-post] ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
