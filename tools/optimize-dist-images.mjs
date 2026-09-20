import fs from "node:fs";
import path from "node:path";
import sharp from "sharp";

const distDir = path.resolve("dist");
const MIN_BYTES = 150 * 1024;
const IMAGE_EXT = new Set([".png", ".jpg", ".jpeg"]);
const SKIP_DIR_NAMES = new Set(["pagefind", "_astro", "cursor", "fonts", "og"]);

function listFiles(dir, files = []) {
  if (!fs.existsSync(dir)) return files;

  for (const name of fs.readdirSync(dir)) {
    const fullPath = path.join(dir, name);
    const stat = fs.statSync(fullPath);

    if (stat.isDirectory()) {
      if (SKIP_DIR_NAMES.has(name) || name.endsWith("_files")) continue;
      listFiles(fullPath, files);
      continue;
    }

    files.push(fullPath);
  }

  return files;
}

function toPosixUrl(filePath) {
  return `/${path.relative(distDir, filePath).split(path.sep).join("/")}`;
}

async function convertLargeImages(files) {
  const rewritten = new Map();

  for (const file of files) {
    const ext = path.extname(file).toLowerCase();
    if (!IMAGE_EXT.has(ext)) continue;
    if (fs.statSync(file).size < MIN_BYTES) continue;

    const webpPath = `${file.slice(0, -ext.length)}.webp`;
    const sourceMtime = fs.statSync(file).mtimeMs;
    const webpExists = fs.existsSync(webpPath);
    const webpFresh = webpExists && fs.statSync(webpPath).mtimeMs >= sourceMtime;

    if (!webpFresh) {
      await sharp(file).webp({ quality: 72 }).toFile(webpPath);
    }

    rewritten.set(toPosixUrl(file), toPosixUrl(webpPath));
  }

  return rewritten;
}

function removeJunk(files) {
  let removed = 0;

  for (const file of files) {
    const rel = path.relative(distDir, file).split(path.sep).join("/");
    const isYuqueDump =
      rel.includes("_files/") ||
      (rel.includes("fengmian/") && rel.toLowerCase().endsWith(".html"));
    const isUnusedCursorCss =
      rel.startsWith("cursor/") && rel.toLowerCase().endsWith(".css");

    if (!isYuqueDump && !isUnusedCursorCss) continue;

    fs.rmSync(file, { force: true });
    removed += 1;
  }

  const fengmianDir = path.join(distDir, "image", "fengmian");
  if (fs.existsSync(fengmianDir)) {
    for (const name of fs.readdirSync(fengmianDir)) {
      const fullPath = path.join(fengmianDir, name);
      if (name.endsWith("_files") && fs.statSync(fullPath).isDirectory()) {
        fs.rmSync(fullPath, { recursive: true, force: true });
        removed += 1;
      }
    }
  }

  return removed;
}

function rewriteHtml(files, rewritten) {
  if (rewritten.size === 0) return 0;

  const replacements = [];
  for (const [from, to] of rewritten) {
    replacements.push([from, to]);
    const encodedFrom = encodeURI(from);
    const encodedTo = encodeURI(to);
    if (encodedFrom !== from) replacements.push([encodedFrom, encodedTo]);
  }

  replacements.sort((a, b) => b[0].length - a[0].length);

  let changed = 0;
  for (const file of files) {
    if (!file.endsWith(".html")) continue;

    const original = fs.readFileSync(file, "utf8");
    let next = original;
    for (const [from, to] of replacements) {
      next = next.split(from).join(to);
    }

    if (next !== original) {
      fs.writeFileSync(file, next);
      changed += 1;
    }
  }

  return changed;
}

const files = listFiles(distDir);
if (files.length === 0) {
  console.log("[optimize-dist-images] dist/ not found, skip");
  process.exit(0);
}

const rewritten = await convertLargeImages(files);
const removed = removeJunk(files);
const htmlChanged = rewriteHtml(listFiles(distDir), rewritten);

console.log(
  `[optimize-dist-images] webp=${rewritten.size} html=${htmlChanged} removed=${removed}`,
);
