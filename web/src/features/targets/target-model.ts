import type { Target, TargetInput, TargetKind } from "@/api/types";
import { presetFor, SCHEDULE_PRESETS, type SchedulePresetId } from "@/lib/schedule";
import { splitList } from "@/lib/utils";

export interface TargetFormState {
  kind: TargetKind;
  owner: string;
  url: string;
  base_url: string;
  branch: string;
  branches: string;
  max_branches: string;
  auth: string;
  list_auth: string;
  include: string;
  exclude: string;
  topics: string;
  skip_archived: boolean;
  skip_forks: boolean;
  skip_empty: boolean;
  max_repos: string;
  schedulePreset: SchedulePresetId;
  customCron: string;
  poll: string;
  enabled: boolean;
}

/** Poll choices: a cheap check that rescans only branches whose commit moved. */
export const POLL_PRESETS = [
  { value: "", label: "Off" },
  { value: "@every 15m", label: "Every 15 minutes" },
  { value: "@every 1h", label: "Every hour" },
  { value: "@every 6h", label: "Every 6 hours" },
] as const;

export const EMPTY_TARGET: TargetFormState = {
  kind: "org",
  owner: "",
  url: "",
  base_url: "",
  branch: "",
  branches: "",
  max_branches: "",
  auth: "",
  list_auth: "",
  include: "",
  exclude: "",
  topics: "",
  skip_archived: true,
  skip_forks: true,
  skip_empty: true,
  max_repos: "",
  schedulePreset: "daily",
  customCron: "",
  poll: "",
  enabled: true,
};

/** Field names as the API reports them in problem `fields`. */
export const TARGET_FIELDS = [
  "kind",
  "owner",
  "url",
  "base_url",
  "branch",
  "branches",
  "max_branches",
  "poll",
  "auth",
  "list_auth",
  "schedule",
  "repos",
  "filter",
  "filter.include",
  "filter.exclude",
  "filter.topics",
  "filter.max_repos",
  "enabled",
] as const;

export function scheduleOf(s: TargetFormState): string {
  if (s.schedulePreset === "custom") return s.customCron.trim();
  return SCHEDULE_PRESETS.find((p) => p.id === s.schedulePreset)?.cron ?? "";
}

export function toTargetInput(s: TargetFormState, needsListAuth: boolean): TargetInput {
  const input: TargetInput = {
    kind: s.kind,
    provider: "github",
    auth: s.auth,
    branch: s.branch.trim(),
    schedule: scheduleOf(s),
    enabled: s.enabled,
  };
  const branches = splitList(s.branches);
  if (branches.length) input.branches = branches;
  if (/^\d+$/.test(s.max_branches.trim())) input.max_branches = Number(s.max_branches.trim());
  if (s.poll) input.poll = s.poll;
  if (s.base_url.trim()) input.base_url = s.base_url.trim();
  if (s.kind === "repo") {
    input.url = s.url.trim();
  } else {
    input.owner = s.owner.trim();
    if (needsListAuth && s.list_auth) input.list_auth = s.list_auth;
    const max = s.max_repos.trim() === "" ? undefined : Number(s.max_repos);
    input.filter = {
      include: splitList(s.include),
      exclude: splitList(s.exclude),
      topics: splitList(s.topics),
      skip_archived: s.skip_archived,
      skip_forks: s.skip_forks,
      skip_empty: s.skip_empty,
      ...(max !== undefined && Number.isFinite(max) ? { max_repos: max } : {}),
    };
  }
  return input;
}

export function fromTarget(t: Target): TargetFormState {
  const preset = presetFor(t.schedule ?? "");
  return {
    kind: t.kind,
    owner: t.owner ?? "",
    url: t.url ?? "",
    base_url: t.base_url ?? "",
    branch: t.branch ?? "",
    branches: (t.branches ?? []).join(", "),
    max_branches: t.max_branches ? String(t.max_branches) : "",
    auth: t.auth,
    list_auth: t.list_auth ?? "",
    include: (t.filter?.include ?? []).join(", "),
    exclude: (t.filter?.exclude ?? []).join(", "),
    topics: (t.filter?.topics ?? []).join(", "),
    skip_archived: t.filter?.skip_archived ?? true,
    skip_forks: t.filter?.skip_forks ?? true,
    skip_empty: t.filter?.skip_empty ?? true,
    max_repos: t.filter?.max_repos !== undefined ? String(t.filter.max_repos) : "",
    schedulePreset: preset,
    customCron: preset === "custom" ? (t.schedule ?? "") : "",
    poll: t.poll ?? "",
    enabled: t.enabled ?? true,
  };
}

/** The writable part of a Target (PATCH replaces all writable fields). */
export function targetInputOf(t: Target): TargetInput {
  const { kind, provider, base_url, owner, url, branch, branches, max_branches, poll, auth, list_auth, repos, filter, schedule, enabled } = t;
  return { kind, provider, base_url, owner, url, branch, branches, max_branches, poll, auth, list_auth, repos, filter, schedule, enabled };
}
