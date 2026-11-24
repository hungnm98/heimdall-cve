import type { Severity } from "@/api/types";

export const SEVERITIES: readonly Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  UNKNOWN: 0,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  CRITICAL: "Critical",
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
  UNKNOWN: "Unknown",
};

/**
 * One palette for every severity indicator in the app. Badges pair the colour with
 * the text label so colour is never the only signal.
 */
export const SEVERITY_CLASS: Record<Severity, string> = {
  CRITICAL:
    "bg-red-100 text-red-900 border-red-300 dark:bg-red-950 dark:text-red-200 dark:border-red-800",
  HIGH: "bg-orange-100 text-orange-900 border-orange-300 dark:bg-orange-950 dark:text-orange-200 dark:border-orange-800",
  MEDIUM:
    "bg-amber-100 text-amber-900 border-amber-300 dark:bg-amber-950 dark:text-amber-200 dark:border-amber-800",
  LOW: "bg-sky-100 text-sky-900 border-sky-300 dark:bg-sky-950 dark:text-sky-200 dark:border-sky-800",
  UNKNOWN:
    "bg-zinc-100 text-zinc-800 border-zinc-300 dark:bg-zinc-800 dark:text-zinc-200 dark:border-zinc-600",
};

/** Chart colours (same hues as the badges; checked with a CVD/contrast validator on the light surface). */
export const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "#b91c1c",
  HIGH: "#f97316",
  MEDIUM: "#a16207",
  LOW: "#0284c7",
  UNKNOWN: "#71717a",
};

export function isSeverity(v: unknown): v is Severity {
  return typeof v === "string" && (SEVERITIES as readonly string[]).includes(v);
}

/** Reads a severity → count map, tolerating missing keys. */
export function countOf(map: Record<string, number> | undefined, s: Severity): number {
  return map?.[s] ?? 0;
}
