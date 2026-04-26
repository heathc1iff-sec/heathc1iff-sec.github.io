import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const BLOG_ROOT_URL = new URL("./blog/", import.meta.url);
const BLOG_ROOT_PATH = fileURLToPath(BLOG_ROOT_URL);

function toPosixPath(filePath: string): string {
  return filePath.split(path.sep).join("/");
}

function slugSegment(segment: string): string {
  return segment
    .normalize("NFKC")
    .toLowerCase()
    .replace(/[.'"`’“”‘’()[\]{}<>《》〈〉「」『』【】（）]/gu, "")
    .replace(/[^\p{Letter}\p{Number}]+/gu, "-")
    .replace(/^-+|-+$/g, "");
}

function getLegacyEntry(filePath: string) {
  const relativePath = path.relative(BLOG_ROOT_PATH, filePath);
  const withoutFileExt = relativePath.replace(
    new RegExp(`${path.extname(relativePath)}$`),
    "",
  );
  const slug = withoutFileExt
    .split(path.sep)
    .map((segment) => slugSegment(segment))
    .join("/")
    .replace(/\/index$/, "");

  return {
    id: toPosixPath(relativePath),
    slug,
  };
}

async function walkMarkdownFiles(dirPath: string): Promise<string[]> {
  const entries = await fs.readdir(dirPath, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map(async (entry) => {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        return walkMarkdownFiles(fullPath);
      }
      return entry.isFile() && entry.name.endsWith(".md") ? [fullPath] : [];
    }),
  );

  return nested.flat();
}

export const blogLoader = {
  name: "heathcliff-blog-loader",
  async load(context: any) {
    const { config, entryTypes, generateDigest, logger, parseData, store } =
      context;
    const markdownEntryType = entryTypes.get(".md");
    if (!markdownEntryType) {
      throw new Error("Missing Astro markdown entry type for blog content.");
    }

    const renderMarkdownEntry = markdownEntryType.getRenderFunction
      ? await markdownEntryType.getRenderFunction(config)
      : null;
    const markdownFiles = (await walkMarkdownFiles(BLOG_ROOT_PATH)).sort((a, b) =>
      a.localeCompare(b),
    );
    const untouchedEntries = new Set(store.keys());

    for (const fullPath of markdownFiles) {
      const fileUrl = pathToFileURL(fullPath);
      const contents = await fs.readFile(fullPath, "utf8");
      const { body, data, slug } = await markdownEntryType.getEntryInfo({
        contents,
        fileUrl,
      });
      const legacyEntry = getLegacyEntry(fullPath);
      const id = typeof slug === "string" && slug.trim() ? slug.trim() : legacyEntry.slug;
      const digest = generateDigest(contents);
      const rendered = renderMarkdownEntry
        ? await renderMarkdownEntry({
            id,
            data,
            body,
            filePath: fullPath,
            digest,
          })
        : undefined;

      untouchedEntries.delete(id);
      store.set({
        id,
        data: await parseData({ id, data, filePath: fullPath }),
        body,
        filePath: toPosixPath(path.relative(fileURLToPath(config.root), fullPath)),
        digest,
        rendered,
        assetImports: rendered?.metadata?.imagePaths,
        legacyId: legacyEntry.id,
      });
    }

    untouchedEntries.forEach((id) => store.delete(id));
    logger.info(`Loaded ${markdownFiles.length} blog markdown files.`);
  },
};
