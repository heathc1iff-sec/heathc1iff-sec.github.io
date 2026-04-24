import type { Root } from "mdast";
import type { Plugin } from "unified";
import type { VFile } from "vfile";
import { calculateReadingStats } from "../utils/readingStats.js";

interface AstroVFile extends VFile {
  data: {
    astro: {
      frontmatter: {
        totalCharCount: number;
        readingTime: number;
        [key: string]: any;
      };
    };
  };
}

export const remarkReadingTime: Plugin<[], Root> = () => {
  return (_tree: Root, file: VFile): void => {
    const astroFile = file as AstroVFile;
    const { totalCharCount, readingTime } = calculateReadingStats(
      String(file.value ?? ""),
    );

    astroFile.data.astro.frontmatter.totalCharCount = totalCharCount;
    astroFile.data.astro.frontmatter.readingTime = readingTime;
  };
};
