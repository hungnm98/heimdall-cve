import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/** Splits a comma/newline separated list, trimming blanks. */
export function splitList(s: string): string[] {
  return s
    .split(/[,\n]/)
    .map((v) => v.trim())
    .filter(Boolean);
}

export function pluralize(n: number, one: string, many = `${one}s`) {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`;
}

/** URL of a repo on its forge; html_url wins when the server provides it. */
export function repoUrl(fullName: string, htmlUrl?: string) {
  return htmlUrl || `https://github.com/${fullName}`;
}

export function osvUrl(id: string) {
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}
