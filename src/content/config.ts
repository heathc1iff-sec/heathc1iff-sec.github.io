import { defineCollection, z } from "astro:content";
import { blogLoader } from "./blog-loader.js";

const blog = defineCollection({
  type: "content_layer",
  loader: blogLoader,
  _legacy: true,
  schema: z
    .object({
      title: z.string(),
      description: z.string(),
      pubDate: z.coerce.date(),
      updated: z.coerce.date().optional(),
      image: z.string().optional(),
      certificate: z.string().optional(),
      badge: z.string().optional(),
      draft: z.boolean().default(false),
      encryption: z.boolean().default(false),
      password: z.string().min(1).optional(),
      passwordHash: z.string().length(64).optional(),
      encryptionSalt: z.string().optional(),
      encryptionIv: z.string().optional(),
      encryptionTag: z.string().optional(),
      encryptionContent: z.string().optional(),
      encryptionIterations: z.number().int().positive().optional(),
      encryptedWordCount: z.string().optional(),
      encryptedReadTime: z.string().optional(),
      passwordHint: z.string().optional(),
      categories: z
        .array(z.string())
        .refine((items: string[]) => new Set(items).size === items.length, {
          message: "categories must be unique",
        })
        .optional(),
      tags: z
        .array(z.string())
        .refine((items: string[]) => new Set(items).size === items.length, {
          message: "tags must be unique",
        })
        .optional(),
    })
    .superRefine(
      (
        data: {
          encryption: boolean;
          password?: string;
          passwordHash?: string;
          encryptionSalt?: string;
          encryptionIv?: string;
          encryptionTag?: string;
          encryptionContent?: string;
          encryptionIterations?: number;
        },
        ctx: z.RefinementCtx,
      ) => {
        const hasEncryptedPayload = Boolean(
          data.passwordHash &&
            data.encryptionSalt &&
            data.encryptionIv &&
            data.encryptionTag &&
            data.encryptionContent &&
            data.encryptionIterations,
        );

        if (data.encryption && !data.password && !hasEncryptedPayload) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ["encryption"],
            message:
              "encryption=true requires either password or encrypted payload fields",
          });
        }
      },
    ),
});

export const collections = { blog };
