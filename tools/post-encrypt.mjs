import fs from "node:fs/promises";
import path from "node:path";
import { createCipheriv, createHash, pbkdf2Sync, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import yaml from "js-yaml";

const ITERATIONS = 210000;
const FRONTMATTER_PATTERN = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

function usage() {
  console.error(
    "Usage: npm run encrypt:post -- <markdown-file> [password] (or set POST_ENCRYPTION_PASSWORD)",
  );
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

function stripMarkdown(markdown) {
  return markdown
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`[^`\n]+`/g, " ")
    .replace(/!\[[^\]]*\]\([^)]*\)/g, " ")
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/<[^>]+>/g, " ")
    .replace(/[#>*_~\-]/g, " ")
    .replace(/\s+/g, "")
    .trim();
}

export async function encryptPostFile(targetFile, passwordFromArg) {
  if (!targetFile) {
    throw new Error("Missing target markdown file path.");
  }

  const resolvedPath = path.resolve(process.cwd(), targetFile);
  const source = await fs.readFile(resolvedPath, "utf8");
  const { frontmatterRaw, body } = parseMarkdownFile(source);

  const metaRaw = yaml.load(frontmatterRaw) ?? {};
  if (typeof metaRaw !== "object" || Array.isArray(metaRaw)) {
    throw new Error("Frontmatter must be a YAML object.");
  }

  const meta = { ...metaRaw };
  const password =
    typeof passwordFromArg === "string" && passwordFromArg.length > 0
      ? passwordFromArg
      : typeof meta.password === "string"
        ? meta.password
        : typeof process.env.POST_ENCRYPTION_PASSWORD === "string"
          ? process.env.POST_ENCRYPTION_PASSWORD
          : "";

  if (!password) {
    throw new Error(
      "Missing password. Pass it as CLI arg, set frontmatter password, or use POST_ENCRYPTION_PASSWORD.",
    );
  }

  if (!body.trim()) {
    throw new Error("Post body is empty. Nothing to encrypt.");
  }

  meta.encryption = true;

  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = pbkdf2Sync(password, salt, ITERATIONS, 32, "sha256");

  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encryptedBody = Buffer.concat([cipher.update(body, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const plainText = stripMarkdown(body);
  const charCount = plainText.length;
  const estimatedReadTime = Math.max(1, Math.ceil(charCount / 500));

  meta.passwordHash = createHash("sha256").update(password).digest("hex");
  meta.encryptionSalt = salt.toString("base64");
  meta.encryptionIv = iv.toString("base64");
  meta.encryptionTag = authTag.toString("base64");
  meta.encryptionContent = encryptedBody.toString("base64");
  meta.encryptionIterations = ITERATIONS;
  meta.encryptedWordCount = String(charCount);
  meta.encryptedReadTime = String(estimatedReadTime);

  delete meta.password;

  const serializedFrontmatter = yaml
    .dump(meta, {
      lineWidth: -1,
      noRefs: true,
    })
    .trimEnd();

  const output = `---\n${serializedFrontmatter}\n---\n\n<!-- Encrypted article body. Use decrypt script before editing. -->\n`;
  await fs.writeFile(resolvedPath, output, "utf8");

  return path.relative(process.cwd(), resolvedPath);
}

async function main() {
  const targetFile = process.argv[2];
  const passwordFromArg = process.argv[3];

  if (!targetFile) {
    usage();
    process.exit(1);
  }

  const encryptedFile = await encryptPostFile(targetFile, passwordFromArg);
  console.log(`[encrypt-post] Encrypted ${encryptedFile}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`[encrypt-post] ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
