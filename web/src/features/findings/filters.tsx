import { getRouteApi } from "@tanstack/react-router";
import { Search, X } from "lucide-react";
import * as React from "react";
import type { FindingKind, FindingsQuery, FindingStatus, Severity } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Input, NativeSelect } from "@/components/ui/input";
import { isSeverity, SEVERITIES, SEVERITY_LABEL } from "@/lib/severity";

export interface FindingSearch {
  repo?: string;
  kind?: FindingKind;
  status?: FindingStatus;
  min_severity?: Severity;
  kev?: boolean;
  /** yyyy-mm-dd (UTC) */
  new_since?: string;
  q?: string;
}

export const KINDS: FindingKind[] = ["dependency", "runtime", "code", "secret", "config"];
export const STATUSES: FindingStatus[] = ["open", "fixed", "suppressed"];

const str = (v: unknown) =>
  typeof v === "string" && v.trim() !== "" ? v.trim() : typeof v === "number" ? String(v) : undefined;

/** Validates URL search params; anything unknown is dropped rather than sent to the API. */
export function parseFindingSearch(s: Record<string, unknown>): FindingSearch {
  const kind = KINDS.find((k) => k === s.kind);
  const status = STATUSES.find((k) => k === s.status);
  const minSev = isSeverity(s.min_severity) ? s.min_severity : undefined;
  const kev = s.kev === true || s.kev === "true" ? true : s.kev === false || s.kev === "false" ? false : undefined;
  const since = str(s.new_since);
  return {
    repo: str(s.repo),
    kind,
    status,
    min_severity: minSev,
    kev,
    new_since: since && /^\d{4}-\d{2}-\d{2}$/.test(since) ? since : undefined,
    q: str(s.q),
  };
}

/** URL search → API query. */
export function toFindingsQuery(s: FindingSearch): FindingsQuery {
  const q: FindingsQuery = {};
  if (s.repo) q.repo = s.repo;
  if (s.kind) q.kind = s.kind;
  if (s.status) q.status = s.status;
  if (s.min_severity) q.min_severity = s.min_severity;
  if (s.kev !== undefined) q.kev = s.kev;
  if (s.new_since) q.new_since = `${s.new_since}T00:00:00Z`;
  if (s.q) q.q = s.q;
  return q;
}

export function hasFilters(s: FindingSearch) {
  return Object.values(s).some((v) => v !== undefined);
}

const route = getRouteApi("/findings");

/** Free-text input that commits to the URL on Enter, blur or after a pause. */
function DebouncedInput({
  value,
  onCommit,
  ...props
}: { value: string; onCommit: (v: string) => void } & Omit<React.InputHTMLAttributes<HTMLInputElement>, "value" | "onChange">) {
  const [local, setLocal] = React.useState(value);
  const committed = React.useRef(value);
  React.useEffect(() => {
    setLocal(value);
    committed.current = value;
  }, [value]);
  const commit = React.useCallback(
    (v: string) => {
      if (v.trim() === committed.current) return;
      committed.current = v.trim();
      onCommit(v.trim());
    },
    [onCommit],
  );
  React.useEffect(() => {
    if (local === value) return;
    const t = setTimeout(() => commit(local), 400);
    return () => clearTimeout(t);
  }, [local, value, commit]);
  return (
    <Input
      {...props}
      value={local}
      onChange={(e) => setLocal(e.target.value)}
      onBlur={() => commit(local)}
      onKeyDown={(e) => {
        if (e.key === "Enter") commit(local);
      }}
    />
  );
}

export function FindingsFilters() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const set = React.useCallback(
    (patch: Partial<FindingSearch>) =>
      void navigate({ search: (prev) => ({ ...prev, ...patch }), replace: true }),
    [navigate],
  );
  const onQ = React.useCallback((v: string) => set({ q: v || undefined }), [set]);
  const onRepo = React.useCallback((v: string) => set({ repo: v || undefined }), [set]);

  return (
    <form
      role="search"
      aria-label="Filter findings"
      className="mb-4 grid grid-cols-1 gap-3 rounded-lg border bg-card p-3 sm:grid-cols-2 lg:grid-cols-4"
      onSubmit={(e) => e.preventDefault()}
    >
      <div className="relative sm:col-span-2">
        <label htmlFor="f-q" className="sr-only">
          Search package or advisory id
        </label>
        <Search aria-hidden className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
        <DebouncedInput
          id="f-q"
          type="search"
          placeholder="Package name or CVE / GHSA / GO id"
          className="pl-8"
          value={search.q ?? ""}
          onCommit={onQ}
        />
      </div>
      <div>
        <label htmlFor="f-repo" className="sr-only">
          Repository
        </label>
        <DebouncedInput id="f-repo" placeholder="Repository (owner/name)" value={search.repo ?? ""} onCommit={onRepo} />
      </div>
      <div>
        <label htmlFor="f-sev" className="sr-only">
          Minimum severity
        </label>
        <NativeSelect
          id="f-sev"
          value={search.min_severity ?? ""}
          onChange={(e) => set({ min_severity: (e.target.value || undefined) as Severity | undefined })}
        >
          <option value="">Any severity</option>
          {SEVERITIES.filter((s) => s !== "UNKNOWN").map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
              {s === "CRITICAL" ? "" : " and above"}
            </option>
          ))}
        </NativeSelect>
      </div>
      <div>
        <label htmlFor="f-status" className="sr-only">
          Status
        </label>
        <NativeSelect
          id="f-status"
          value={search.status ?? ""}
          onChange={(e) => set({ status: (e.target.value || undefined) as FindingStatus | undefined })}
        >
          <option value="">Any status</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s[0]!.toUpperCase() + s.slice(1)}
            </option>
          ))}
        </NativeSelect>
      </div>
      <div>
        <label htmlFor="f-kind" className="sr-only">
          Kind
        </label>
        <NativeSelect
          id="f-kind"
          value={search.kind ?? ""}
          onChange={(e) => set({ kind: (e.target.value || undefined) as FindingKind | undefined })}
        >
          <option value="">Any kind</option>
          {KINDS.map((k) => (
            <option key={k} value={k}>
              {k[0]!.toUpperCase() + k.slice(1)}
            </option>
          ))}
        </NativeSelect>
      </div>
      <div>
        <label htmlFor="f-kev" className="sr-only">
          Known exploited (KEV)
        </label>
        <NativeSelect
          id="f-kev"
          value={search.kev === undefined ? "" : String(search.kev)}
          onChange={(e) => set({ kev: e.target.value === "" ? undefined : e.target.value === "true" })}
        >
          <option value="">KEV: any</option>
          <option value="true">Known exploited only</option>
          <option value="false">Not in KEV</option>
        </NativeSelect>
      </div>
      <div className="flex items-center gap-2">
        <label htmlFor="f-since" className="shrink-0 text-sm text-muted-foreground">
          New since
        </label>
        <Input
          id="f-since"
          type="date"
          value={search.new_since ?? ""}
          onChange={(e) => set({ new_since: e.target.value || undefined })}
        />
      </div>
      {hasFilters(search) ? (
        <div className="flex items-center sm:col-span-2 lg:col-span-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => void navigate({ search: {}, replace: true })}
          >
            <X aria-hidden /> Clear filters
          </Button>
        </div>
      ) : null}
    </form>
  );
}
