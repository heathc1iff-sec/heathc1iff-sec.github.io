import fs from "node:fs";
import path from "node:path";

const SOURCE_DIR = path.resolve("src/content/blog");
const SITEMAP_PATH = path.resolve("dist/sitemap-0.xml");
const SITE_BASE = "https://heathc1iff-sec.github.io";

const FRONTMATTER_PATTERN = /^---\s*\r?\n([\s\S]*?)\r?\n---\s*(?:\r?\n|$)/;
const DIRECT_POST_URL_PATTERN =
  /^\/blog\/(?!$|\d+\/|archives\/|categories\/|search\/|tags\/|tag\/|category\/).+\/$/;

function walkMarkdownFiles(dirPath) {
  const entries = fs.readdirSync(dirPath, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      return walkMarkdownFiles(fullPath);
    }
    return entry.isFile() && entry.name.endsWith(".md") ? [fullPath] : [];
  });
}

function isDraftPost(filePath) {
  const content = fs.readFileSync(filePath, "utf8");
  const match = content.match(FRONTMATTER_PATTERN);
  if (!match) return false;

  return /^draft:\s*true\s*$/im.test(match[1]);
}

function getExpectedPublishedPostCount() {
  const markdownFiles = walkMarkdownFiles(SOURCE_DIR);
  return markdownFiles.filter((filePath) => !isDraftPost(filePath)).length;
}

function getGeneratedPostUrls() {
  if (!fs.existsSync(SITEMAP_PATH)) {
    throw new Error(`Missing sitemap: ${SITEMAP_PATH}`);
  }

  const sitemap = fs.readFileSync(SITEMAP_PATH, "utf8");
  const urls = [...sitemap.matchAll(/<loc>(.*?)<\/loc>/g)].map((match) =>
    match[1].trim(),
  );

  return urls.filter((url) => {
    const pathname = url.startsWith(SITE_BASE) ? url.slice(SITE_BASE.length) : url;
    return DIRECT_POST_URL_PATTERN.test(pathname);
  });
}

function main() {
  const expectedCount = getExpectedPublishedPostCount();
  const generatedPostUrls = getGeneratedPostUrls();
  const actualCount = generatedPostUrls.length;

  console.log(
    `[verify-blog-build] expected published posts: ${expectedCount}, generated post pages: ${actualCount}`,
  );

  if (actualCount !== expectedCount) {
    console.error("[verify-blog-build] Blog build is incomplete.");
    console.error("[verify-blog-build] Sample generated pages:");
    generatedPostUrls.slice(-10).forEach((url) => console.error(`  - ${url}`));
    process.exit(1);
  }
}

main();
