export const SCHEDULE_PRESETS = [
  { id: "daily", label: "Daily 02:00 UTC", cron: "0 2 * * *" },
  { id: "every3", label: "Every 3 days", cron: "0 2 */3 * *" },
  { id: "manual", label: "Manual", cron: "" },
] as const;

export type SchedulePresetId = (typeof SCHEDULE_PRESETS)[number]["id"] | "custom";

export function presetFor(cron: string): SchedulePresetId {
  return SCHEDULE_PRESETS.find((p) => p.cron === cron.trim())?.id ?? "custom";
}

export function describeSchedule(cron: string | undefined): string {
  const c = (cron ?? "").trim();
  if (c === "") return "Manual";
  return SCHEDULE_PRESETS.find((p) => p.cron === c)?.label ?? `cron: ${c}`;
}

const FIELD = /^(\*|\d+(-\d+)?)(\/\d+)?(,(\*|\d+(-\d+)?)(\/\d+)?)*$/;

/**
 * Light client-side check (5 fields, digits/ranges/steps/lists). The server owns
 * the real validation; this only catches typos early.
 */
export function cronError(cron: string): string | undefined {
  const parts = cron.trim().split(/\s+/);
  if (parts.length !== 5) return "A cron expression has 5 fields: minute hour day-of-month month day-of-week";
  const bad = parts.find((p) => !FIELD.test(p));
  return bad ? `Invalid field "${bad}"` : undefined;
}
