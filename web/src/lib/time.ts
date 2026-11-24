const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 365 * 24 * 3600],
  ["month", 30 * 24 * 3600],
  ["week", 7 * 24 * 3600],
  ["day", 24 * 3600],
  ["hour", 3600],
  ["minute", 60],
  ["second", 1],
];

export function relativeTime(iso: string, now = Date.now()): string {
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const diff = (t - now) / 1000;
  const abs = Math.abs(diff);
  if (abs < 45) return "just now";
  for (const [unit, secs] of UNITS) {
    if (abs >= secs) return rtf.format(Math.round(diff / secs), unit);
  }
  return "just now";
}

export function absoluteTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const local = d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "medium" });
  return `${local} (${d.toISOString().replace(".000Z", "Z")})`;
}

export function formatDuration(startIso?: string | null, endIso?: string | null, now = Date.now()): string {
  if (!startIso) return "—";
  const start = Date.parse(startIso);
  const end = endIso ? Date.parse(endIso) : now;
  let s = Math.max(0, Math.round((end - start) / 1000));
  if (s < 60) return `${s}s`;
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  return h > 0 ? `${h}h ${m}m` : `${m}m ${s}s`;
}

/** yyyy-mm-dd of a date in UTC. */
export function isoDate(d: Date): string {
  return d.toISOString().slice(0, 10);
}

export function addDays(d: Date, days: number): Date {
  const r = new Date(d);
  r.setUTCDate(r.getUTCDate() + days);
  return r;
}
