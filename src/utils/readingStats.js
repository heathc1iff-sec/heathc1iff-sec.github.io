import { remark } from "remark";

const FRONTMATTER_PATTERN = /^---\s*\r?\n[\s\S]*?\r?\n---\s*\r?\n?/;
const HTML_COMMENT_PATTERN = /<!--[\s\S]*?-->/g;
const REFERENCE_LINK_PATTERN = /^[\t ]*\[[^\]]+]:\s+\S+(?:\s+["(].*)?$/gm;
const AUTO_LINK_PATTERN = /<https?:\/\/[^>\s]+>/g;
const FALLBACK_FENCED_CODE_PATTERN = /(?:^|\n)(```|~~~)[^\n]*\n[\s\S]*?\n\1(?=\n|$)/g;
const FALLBACK_INLINE_CODE_PATTERN = /`[^`\n]+`/g;
const FALLBACK_IMAGE_PATTERN = /!\[[^\]]*]\([^)]*\)/g;
const FALLBACK_LINK_PATTERN = /\[([^\]]+)\]\([^)]+\)/g;
const FALLBACK_HTML_TAG_PATTERN = /<\/?[A-Za-z][^>]*>/g;

const TEXT_VALUE_NODE_TYPES = new Set(["text", "inlineMath", "math"]);
const IGNORED_NODE_TYPES = new Set([
  "code",
  "definition",
  "footnoteDefinition",
  "footnoteReference",
  "html",
  "image",
  "imageReference",
  "inlineCode",
  "toml",
  "yaml",
]);
const BLOCK_SEPARATOR_NODE_TYPES = new Set([
  "break",
  "blockquote",
  "heading",
  "listItem",
  "paragraph",
  "table",
  "tableCell",
  "tableRow",
]);
const CJK_CHAR_PATTERN =
  /[\p{Script=Han}\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}]/gu;
const LATIN_WORD_PATTERN = /\b[\p{L}][\p{L}\p{N}'-]*\b/gu;

const WORDS_PER_MINUTE = 200;
const CJK_CHARS_PER_MINUTE = 300;

function normalizeWhitespace(text) {
  return String(text ?? "")
    .replace(/\r?\n/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function prepareMarkdown(markdown) {
  return String(markdown ?? "")
    .replace(FRONTMATTER_PATTERN, " ")
    .replace(HTML_COMMENT_PATTERN, " ")
    .replace(REFERENCE_LINK_PATTERN, " ")
    .replace(AUTO_LINK_PATTERN, " ");
}

function collectVisibleText(node, parts) {
  if (!node || typeof node !== "object") return;

  if (Array.isArray(node)) {
    for (const child of node) {
      collectVisibleText(child, parts);
    }
    return;
  }

  const nodeType = typeof node.type === "string" ? node.type : "";
  if (IGNORED_NODE_TYPES.has(nodeType)) {
    return;
  }

  if (
    TEXT_VALUE_NODE_TYPES.has(nodeType) &&
    typeof node.value === "string" &&
    node.value.trim()
  ) {
    parts.push(node.value);
    parts.push(" ");
    return;
  }

  if (Array.isArray(node.children)) {
    for (const child of node.children) {
      collectVisibleText(child, parts);
    }
  }

  if (BLOCK_SEPARATOR_NODE_TYPES.has(nodeType)) {
    parts.push(" ");
  }
}

function fallbackVisibleText(markdown) {
  return normalizeWhitespace(
    markdown
      .replace(FALLBACK_FENCED_CODE_PATTERN, " ")
      .replace(FALLBACK_INLINE_CODE_PATTERN, " ")
      .replace(FALLBACK_IMAGE_PATTERN, " ")
      .replace(FALLBACK_LINK_PATTERN, " $1 ")
      .replace(FALLBACK_HTML_TAG_PATTERN, " "),
  );
}

/**
 * Extract human-visible text from markdown so reading stats track rendered
 * content instead of code blocks, image URLs or other noisy syntax.
 *
 * @param {string | undefined | null} markdown
 * @returns {string}
 */
export function stripMarkdownForReadingStats(markdown) {
  const prepared = prepareMarkdown(markdown);

  try {
    const tree = remark().parse(prepared);
    const parts = [];
    collectVisibleText(tree, parts);
    const visibleText = normalizeWhitespace(parts.join(" "));

    return visibleText || fallbackVisibleText(prepared);
  } catch {
    return fallbackVisibleText(prepared);
  }
}

/**
 * Estimate human-facing reading stats from markdown content.
 *
 * @param {string | undefined | null} markdown
 * @returns {{
 *   plainText: string;
 *   latinWordCount: number;
 *   cjkCount: number;
 *   totalCharCount: number;
 *   readingTime: number;
 * }}
 */
export function calculateReadingStats(markdown) {
  const plainText = stripMarkdownForReadingStats(markdown);
  const cjkCount = plainText.match(CJK_CHAR_PATTERN)?.length ?? 0;
  const nonCjkText = plainText.replace(CJK_CHAR_PATTERN, " ");
  const latinWordCount = nonCjkText.match(LATIN_WORD_PATTERN)?.length ?? 0;
  const totalCharCount = latinWordCount + cjkCount;

  if (totalCharCount === 0) {
    return {
      plainText,
      latinWordCount,
      cjkCount,
      totalCharCount: 0,
      readingTime: 0,
    };
  }

  const readingTime = Math.max(
    1,
    Math.ceil(
      latinWordCount / WORDS_PER_MINUTE + cjkCount / CJK_CHARS_PER_MINUTE,
    ),
  );

  return {
    plainText,
    latinWordCount,
    cjkCount,
    totalCharCount,
    readingTime,
  };
}
