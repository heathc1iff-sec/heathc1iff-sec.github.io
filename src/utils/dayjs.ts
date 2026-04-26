import { DATE_FORMAT, SITE_LANGUAGE } from "@config";
import dayjs from "dayjs";

// Import all supported locales
import "dayjs/locale/en";
import "dayjs/locale/fr";
import "dayjs/locale/zh";
import "dayjs/locale/ja";
import "dayjs/locale/ko";
import "dayjs/locale/es";
import "dayjs/locale/de";
import "dayjs/locale/ru";
import "dayjs/locale/pt";
import "dayjs/locale/it";

// Set the default locale from the site configuration
// @ts-expect-error - TypeScript
dayjs.locale(SITE_LANGUAGE);

export const SITE_TIMEZONE = "Asia/Shanghai";

const formatterCache = new Map<string, Intl.DateTimeFormat>();

const getFormatter = (options: Intl.DateTimeFormatOptions) => {
  const key = JSON.stringify(options);
  const cached = formatterCache.get(key);
  if (cached) return cached;

  const formatter = new Intl.DateTimeFormat(SITE_LANGUAGE, {
    timeZone: SITE_TIMEZONE,
    ...options,
  });
  formatterCache.set(key, formatter);
  return formatter;
};

const getDatePart = (
  date: Date,
  options: Intl.DateTimeFormatOptions,
  type: Intl.DateTimeFormatPartTypes,
) => {
  const part = getFormatter(options)
    .formatToParts(date)
    .find((item) => item.type === type);
  return part?.value ?? "";
};

const toDate = (input: unknown) => {
  if (input instanceof Date) {
    return Number.isNaN(input.getTime()) ? null : input;
  }

  if (typeof input === "string" || typeof input === "number") {
    const parsed = new Date(input);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }

  if (
    typeof input === "object" &&
    input !== null &&
    "toDate" in input &&
    typeof input.toDate === "function"
  ) {
    const parsed = input.toDate();
    return parsed instanceof Date && !Number.isNaN(parsed.getTime())
      ? parsed
      : null;
  }

  return null;
};

export function formatSiteDate(input: unknown, format: string = DATE_FORMAT): string {
  const date = toDate(input);
  if (!date) return "";

  const replacements = new Map<string, string>([
    ["YYYY", getDatePart(date, { year: "numeric" }, "year")],
    ["MMMM", getDatePart(date, { month: "long" }, "month")],
    ["MMM", getDatePart(date, { month: "short" }, "month")],
    ["MM", getDatePart(date, { month: "2-digit" }, "month")],
    ["M", getDatePart(date, { month: "numeric" }, "month")],
    ["DD", getDatePart(date, { day: "2-digit" }, "day")],
    ["D", getDatePart(date, { day: "numeric" }, "day")],
    ["dddd", getDatePart(date, { weekday: "long" }, "weekday")],
    ["ddd", getDatePart(date, { weekday: "short" }, "weekday")],
    [
      "HH",
      getDatePart(
        date,
        { hour: "2-digit", hour12: false, hourCycle: "h23" },
        "hour",
      ),
    ],
    [
      "H",
      getDatePart(
        date,
        { hour: "numeric", hour12: false, hourCycle: "h23" },
        "hour",
      ),
    ],
    ["mm", getDatePart(date, { minute: "2-digit" }, "minute")],
    ["m", getDatePart(date, { minute: "numeric" }, "minute")],
    ["ss", getDatePart(date, { second: "2-digit" }, "second")],
    ["s", getDatePart(date, { second: "numeric" }, "second")],
  ]);

  return format.replace(
    /YYYY|MMMM|MMM|MM|M|DD|D|dddd|ddd|HH|H|mm|m|ss|s/g,
    (token) => replacements.get(token) ?? token,
  );
}

// Export the configured dayjs
export default dayjs;
