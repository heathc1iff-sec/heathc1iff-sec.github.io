import type { CollectionEntry, RenderResult } from "astro:content";
import { getCollection } from "astro:content";
import { calculateReadingStats } from "./readingStats.js";

export type BlogPostEntry = CollectionEntry<"blog"> & {
  slug: string;
  body?: string;
  render: () => Promise<RenderResult>;
};

type PostStats = {
  readingTime: string;
  totalCharCount: string;
};

type PostWithStats = BlogPostEntry & {
  remarkPluginFrontmatter: PostStats;
};

let allPostsCache: Promise<BlogPostEntry[]> | null = null;
const postStatsCache = new Map<string, PostStats>();

export function getPostSlug(post: CollectionEntry<"blog">): string {
  return (post as BlogPostEntry).slug || post.id;
}

function shouldUseContentCache(): boolean {
  return import.meta.env.PROD;
}

function getPostCacheKey(post: BlogPostEntry): string {
  return post.id || getPostSlug(post);
}

function resolveFallbackStats(post: BlogPostEntry): PostStats {
  return {
    readingTime: post.data.encryptedReadTime ?? "0",
    totalCharCount: post.data.encryptedWordCount ?? "0",
  };
}

function computeStatsFromBody(body: string): PostStats {
  const { readingTime, totalCharCount } = calculateReadingStats(body);

  return {
    readingTime: String(readingTime),
    totalCharCount: String(totalCharCount),
  };
}

function resolvePostStats(post: BlogPostEntry): PostStats {
  if (!shouldUseContentCache()) {
    return post.data.encryption
      ? resolveFallbackStats(post)
      : computeStatsFromBody(post.body ?? "");
  }

  const cacheKey = getPostCacheKey(post);
  const cached = postStatsCache.get(cacheKey);
  if (cached) return cached;

  const fallback = resolveFallbackStats(post);

  // Encrypted posts already carry precomputed values.
  if (post.data.encryption) {
    postStatsCache.set(cacheKey, fallback);
    return fallback;
  }

  const stats = computeStatsFromBody(post.body ?? "");
  postStatsCache.set(cacheKey, stats);
  return stats;
}

/**
 * Get all blog posts and filter drafts in production builds.
 */
export async function getAllPosts(): Promise<BlogPostEntry[]> {
  if (!shouldUseContentCache()) {
    return [...(await getCollection("blog"))] as BlogPostEntry[];
  }

  if (!allPostsCache) {
    allPostsCache = (async () => {
      const allBlogPosts = (await getCollection("blog")) as BlogPostEntry[];
      return allBlogPosts.filter((post: BlogPostEntry) => !post.data.draft);
    })();
  }

  const posts = await allPostsCache;
  return [...posts];
}

/**
 * Sort posts by publish date (newest first).
 */
export function sortPostsByDate(posts: BlogPostEntry[]): BlogPostEntry[] {
  return [...posts].sort(
    (a: BlogPostEntry, b: BlogPostEntry) =>
      new Date(b.data.pubDate).getTime() - new Date(a.data.pubDate).getTime(),
  );
}

/**
 * Sort posts by pin status first, then by publish date.
 */
export function sortPostsByPinAndDate(posts: BlogPostEntry[]): BlogPostEntry[] {
  const topPosts = posts.filter(
    (blog: BlogPostEntry) => blog.data.badge === "Pin",
  );
  const otherPosts = posts.filter(
    (blog: BlogPostEntry) => blog.data.badge !== "Pin",
  );

  const sortedTopPosts = sortPostsByDate(topPosts);
  const sortedOtherPosts = sortPostsByDate(otherPosts);

  return [...sortedTopPosts, ...sortedOtherPosts];
}

/**
 * Count tag frequencies across posts.
 */
export function getTagsWithCount(posts: BlogPostEntry[]): Map<string, number> {
  const tagMap = new Map<string, number>();

  posts.forEach((post: BlogPostEntry) => {
    if (!post.data.tags) return;

    post.data.tags.forEach((tag: string) => {
      tagMap.set(tag, (tagMap.get(tag) || 0) + 1);
    });
  });

  return tagMap;
}

/**
 * Group posts by category.
 */
export function getCategoriesWithPosts(
  posts: BlogPostEntry[],
): Map<string, BlogPostEntry[]> {
  const categoryMap = new Map<string, BlogPostEntry[]>();

  posts.forEach((post: BlogPostEntry) => {
    if (!post.data.categories) return;

    post.data.categories.forEach((category: string) => {
      if (!categoryMap.has(category)) {
        categoryMap.set(category, []);
      }
      categoryMap.get(category)?.push(post);
    });
  });

  return categoryMap;
}

/**
 * Group posts by year and month.
 */
export function getPostsByYearAndMonth(
  posts: BlogPostEntry[],
): Map<string, Map<string, BlogPostEntry[]>> {
  const postsByDate = new Map<string, Map<string, BlogPostEntry[]>>();

  posts.forEach((post: BlogPostEntry) => {
    const date = new Date(post.data.pubDate);
    const year = date.getFullYear().toString();
    const month = (date.getMonth() + 1).toString().padStart(2, "0");

    if (!postsByDate.has(year)) {
      postsByDate.set(year, new Map<string, BlogPostEntry[]>());
    }

    const yearMap = postsByDate.get(year);
    if (!yearMap?.has(month)) {
      yearMap?.set(month, []);
    }

    yearMap?.get(month)?.push(post);
  });

  return postsByDate;
}

/**
 * Build visible and hidden page-link buckets for pagination UI.
 */
export function generatePageLinks(totalPages: number): {
  active: string[];
  hidden: string[];
} {
  const pages = {
    active: [] as string[],
    hidden: [] as string[],
  };

  if (totalPages > 3) {
    pages.active.push("1");
    pages.active.push("...");
    pages.active.push(totalPages.toString());
    for (let i = 2; i <= totalPages - 1; i += 1) {
      pages.hidden.push(i.toString());
    }
  } else {
    for (let i = 1; i <= totalPages; i += 1) {
      pages.active.push(i.toString());
    }
  }

  return pages;
}

/**
 * Attach reading statistics to posts.
 */
export function getPostsWithStats(posts: BlogPostEntry[]): PostWithStats[] {
  return posts.map((blog: BlogPostEntry) => {
    const { readingTime, totalCharCount } = resolvePostStats(blog);

    return {
      ...blog,
      remarkPluginFrontmatter: {
        readingTime,
        totalCharCount,
      },
    };
  });
}

/**
 * Derive tag color intensity from frequency.
 */
export function getTagColorClass(count: number, max: number): string {
  const ratio = count / max;
  if (ratio > 0.8) return "tag-high";
  if (ratio > 0.6) return "tag-medium-high";
  if (ratio > 0.4) return "tag-medium";
  if (ratio > 0.2) return "tag-medium-low";
  return "tag-low";
}

/**
 * Derive tag font size from frequency.
 */
export function getTagFontSize(
  count: number,
  max: number,
  min: number,
): number {
  const normalized = (count - min) / (max - min || 1);
  return 0.9 + normalized * 1.1;
}

/**
 * Assign category color class from index.
 */
export function getCategoryColorClass(index: number): string {
  const colorClasses = [
    "category-primary",
    "category-secondary",
    "category-accent",
    "category-info",
    "category-success",
    "category-warning",
    "category-error",
  ];
  return colorClasses[index % colorClasses.length];
}

/**
 * Encode a post slug safely for use in href/src URLs.
 * Each path segment is encoded independently to preserve slash separators.
 */
export function encodeSlugPath(slug: string): string {
  return slug
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
}
