import { useQuery } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { ArrowLeft, ChevronLeft, Eye, Lock, Save } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { splitFieldErrors } from "@/api/problem";
import { authProfilesQuery, targetQuery, usePreviewTarget, useSaveTarget } from "@/api/queries";
import type { Repo, Target, TargetInput } from "@/api/types";
import { OriginBadge } from "@/components/badges";
import { EmptyState, ErrorState, Field, InlineError, PageHeader } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox, Input, NativeSelect } from "@/components/ui/input";
import { Skeleton, Switch } from "@/components/ui/misc";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";
import { useScan } from "@/features/jobs/use-scan";
import { cronError, SCHEDULE_PRESETS, type SchedulePresetId } from "@/lib/schedule";
import { EMPTY_TARGET, fromTarget, POLL_PRESETS, TARGET_FIELDS, type TargetFormState, toTargetInput } from "./target-model";

type Errors = Partial<Record<string, string>>;

function clientErrors(s: TargetFormState, needsListAuth: boolean): Errors {
  const e: Errors = {};
  if (s.kind === "repo") {
    if (!s.url.trim()) e.url = "Enter the repository URL.";
  } else if (!s.owner.trim()) {
    e.owner = `Enter the ${s.kind === "org" ? "organization" : "user"} login.`;
  }
  if (!s.auth) e.auth = "Choose the auth profile used to read code.";
  if (needsListAuth && !s.list_auth) e.list_auth = "SSH cannot list repositories: choose a token or app profile for listing.";
  if (s.schedulePreset === "custom") {
    const err = cronError(s.customCron);
    if (err) e.schedule = err;
  }
  if (s.max_repos.trim() !== "" && !/^\d+$/.test(s.max_repos.trim())) e["filter.max_repos"] = "Enter a whole number.";
  if (s.max_branches.trim() !== "" && !/^\d+$/.test(s.max_branches.trim())) e.max_branches = "Enter a whole number.";
  return e;
}

function PreviewTable({ repos }: { repos: Repo[] }) {
  if (repos.length === 0)
    return (
      <EmptyState
        title="No repositories match"
        description="The target would scan nothing. Go back and relax the filters or check the owner and auth profile."
      />
    );
  return (
    <Table>
      <caption className="sr-only">Repositories this target would scan</caption>
      <THead>
        <tr>
          <TH>Repository</TH>
          <TH>Branch</TH>
          <TH className="hidden sm:table-cell">Topics</TH>
        </tr>
      </THead>
      <TBody>
        {repos.map((r) => (
          <TR key={r.full_name}>
            <TD className="font-medium">
              {r.full_name}
              {r.private ? <Lock aria-label="private" className="ml-1 inline size-3 text-muted-foreground" /> : null}
              {r.archived ? <Badge variant="outline" className="ml-2">archived</Badge> : null}
              {r.fork ? <Badge variant="outline" className="ml-2">fork</Badge> : null}
            </TD>
            <TD>
              <code className="text-xs">{r.ref || r.default_branch}</code>
            </TD>
            <TD className="hidden text-xs text-muted-foreground sm:table-cell">{r.topics?.join(", ") || "—"}</TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

export function TargetForm({ target }: { target?: Target }) {
  const navigate = useNavigate();
  const profiles = useQuery(authProfilesQuery());
  const [s, setS] = React.useState<TargetFormState>(() => (target ? fromTarget(target) : EMPTY_TARGET));
  const [errors, setErrors] = React.useState<Errors>({});
  const [other, setOther] = React.useState<Record<string, string>>({});
  const [step, setStep] = React.useState<"edit" | "preview">("edit");
  const [previewed, setPreviewed] = React.useState<{ input: TargetInput; repos: Repo[] } | null>(null);
  const preview = usePreviewTarget();
  const save = useSaveTarget();
  const scan = useScan();
  const readOnly = target?.origin === "config";

  const items = React.useMemo(() => profiles.data?.items ?? [], [profiles.data]);
  const authProfile = items.find((p) => p.name === s.auth);
  const needsListAuth = s.kind !== "repo" && authProfile?.type === "ssh";
  const listProfiles = items.filter((p) => p.type !== "ssh");

  React.useEffect(() => {
    // Default to the first profile once they load.
    if (!target && !s.auth && items.length) setS((p) => ({ ...p, auth: items[0]!.name }));
  }, [items, s.auth, target]);

  const set = <K extends keyof TargetFormState>(k: K, v: TargetFormState[K]) => setS((p) => ({ ...p, [k]: v }));

  const applyProblem = (err: unknown) => {
    const { fields, other } = splitFieldErrors(err, TARGET_FIELDS);
    setErrors(fields);
    setOther(other);
    setStep("edit");
  };

  const onPreview = (e: React.FormEvent) => {
    e.preventDefault();
    const errs = clientErrors(s, needsListAuth);
    setErrors(errs);
    setOther({});
    if (Object.keys(errs).length) {
      document.getElementById(`t-${Object.keys(errs)[0]!.replace(".", "-")}`)?.focus();
      return;
    }
    const input = toTargetInput(s, needsListAuth);
    preview.mutate(input, {
      onSuccess: (data) => {
        setPreviewed({ input, repos: data.items });
        setStep("preview");
      },
      onError: applyProblem,
    });
  };

  const onSave = () => {
    if (!previewed) return;
    save.mutate(
      { id: target?.id, body: previewed.input },
      {
        onSuccess: (saved) => {
          toast.success(target ? `Saved ${saved.label}` : `Added ${saved.label}`, {
            action: { label: "Scan now", onClick: () => scan.mutate({ target_id: saved.id }, `Scan of ${saved.label}`) },
          });
          void navigate({ to: "/targets" });
        },
        onError: applyProblem,
      },
    );
  };

  if (step === "preview" && previewed) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Step 2 of 2 · Preview</CardTitle>
          <CardDescription>
            {previewed.repos.length === 1 ? "1 repository" : `${previewed.repos.length} repositories`} would be scanned with these settings. Nothing is saved yet.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <PreviewTable repos={previewed.repos} />
          <InlineError error={save.error && Object.keys(splitFieldErrors(save.error, TARGET_FIELDS).fields).length === 0 ? save.error : null} />
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-between">
            <Button variant="outline" onClick={() => setStep("edit")}>
              <ArrowLeft aria-hidden /> Back
            </Button>
            <Button onClick={onSave} disabled={save.isPending}>
              <Save aria-hidden /> {save.isPending ? "Saving…" : target ? "Save changes" : "Save target"}
            </Button>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <form onSubmit={onPreview} noValidate>
      <fieldset disabled={readOnly} className="grid gap-4">
        <Card>
          <CardHeader>
            <CardTitle>{readOnly ? "Target" : "Step 1 of 2 · What to scan"}</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <Field id="t-kind" label="Kind" error={errors.kind}>
              <NativeSelect value={s.kind} onChange={(e) => set("kind", e.target.value as TargetFormState["kind"])}>
                <option value="org">Organization</option>
                <option value="user">User</option>
                <option value="repo">Single repository (URL)</option>
              </NativeSelect>
            </Field>
            {s.kind === "repo" ? (
              <Field id="t-url" label="Repository URL" error={errors.url} hint="https://github.com/owner/name, git@github.com:owner/name.git or ssh://…">
                <Input value={s.url} onChange={(e) => set("url", e.target.value)} placeholder="https://github.com/acme/api" autoComplete="off" />
              </Field>
            ) : (
              <Field id="t-owner" label={s.kind === "org" ? "Organization" : "User"} error={errors.owner}>
                <Input value={s.owner} onChange={(e) => set("owner", e.target.value)} placeholder={s.kind === "org" ? "acme" : "octocat"} autoComplete="off" />
              </Field>
            )}
            <Field id="t-auth" label="Auth profile" error={errors.auth} hint={profiles.isError ? "Could not load auth profiles." : "Used to read code."}>
              <NativeSelect value={s.auth} onChange={(e) => set("auth", e.target.value)}>
                <option value="">Select a profile…</option>
                {items.map((p) => (
                  <option key={p.name} value={p.name}>
                    {p.name} ({p.type})
                  </option>
                ))}
              </NativeSelect>
            </Field>
            {needsListAuth ? (
              <Field id="t-list_auth" label="Listing auth profile" error={errors.list_auth} hint="SSH keys cannot call the GitHub API, so listing repositories needs a token or app profile.">
                <NativeSelect value={s.list_auth} onChange={(e) => set("list_auth", e.target.value)}>
                  <option value="">Select a profile…</option>
                  {listProfiles.map((p) => (
                    <option key={p.name} value={p.name}>
                      {p.name} ({p.type})
                    </option>
                  ))}
                </NativeSelect>
              </Field>
            ) : null}
            <Field id="t-branch" label="Branch" error={errors.branch} hint="Leave empty to use each repository's default branch.">
              <Input value={s.branch} onChange={(e) => set("branch", e.target.value)} placeholder="default branch" />
            </Field>
            <Field
              id="t-branches"
              label="Extra branches"
              error={errors.branches}
              hint="Also scanned, comma-separated; globs like release/* are allowed. Missing branches are skipped."
            >
              <Input value={s.branches} onChange={(e) => set("branches", e.target.value)} placeholder="release/*, develop" autoComplete="off" />
            </Field>
            {s.branches.trim() ? (
              <Field id="t-max_branches" label="Max extra branches per repository" error={errors.max_branches} hint="Empty = 10.">
                <Input inputMode="numeric" value={s.max_branches} onChange={(e) => set("max_branches", e.target.value)} />
              </Field>
            ) : null}
            <Field id="t-base_url" label="GitHub Enterprise API URL" error={errors.base_url} hint="Only for GitHub Enterprise Server.">
              <Input value={s.base_url} onChange={(e) => set("base_url", e.target.value)} placeholder="https://github.example.com/api/v3" />
            </Field>
          </CardContent>
        </Card>

        {s.kind !== "repo" ? (
          <Card>
            <CardHeader>
              <CardTitle>Filters</CardTitle>
              <CardDescription>Comma-separated; globs like <code>api-*</code> are allowed.</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <Field id="t-filter-include" label="Include" error={errors["filter.include"]}>
                <Input value={s.include} onChange={(e) => set("include", e.target.value)} placeholder="all repositories" />
              </Field>
              <Field id="t-filter-exclude" label="Exclude" error={errors["filter.exclude"]}>
                <Input value={s.exclude} onChange={(e) => set("exclude", e.target.value)} placeholder="sandbox-*" />
              </Field>
              <Field id="t-filter-topics" label="Topics (any of)" error={errors["filter.topics"]}>
                <Input value={s.topics} onChange={(e) => set("topics", e.target.value)} placeholder="production" />
              </Field>
              <Field id="t-filter-max_repos" label="Max repositories" error={errors["filter.max_repos"]} hint="Empty = no limit.">
                <Input inputMode="numeric" value={s.max_repos} onChange={(e) => set("max_repos", e.target.value)} />
              </Field>
              <div className="flex flex-wrap gap-x-6 gap-y-2 sm:col-span-2">
                {(
                  [
                    ["skip_archived", "Skip archived"],
                    ["skip_forks", "Skip forks"],
                    ["skip_empty", "Skip empty"],
                  ] as const
                ).map(([k, label]) => (
                  <label key={k} className="flex items-center gap-2 text-sm">
                    <Checkbox checked={s[k]} onChange={(e) => set(k, e.target.checked)} />
                    {label}
                  </label>
                ))}
              </div>
            </CardContent>
          </Card>
        ) : null}

        <Card>
          <CardHeader>
            <CardTitle>Schedule</CardTitle>
          </CardHeader>
          <CardContent className="grid gap-4 sm:grid-cols-2">
            <Field id="t-schedule-preset" label="Run" error={s.schedulePreset !== "custom" ? errors.schedule : undefined}>
              <NativeSelect value={s.schedulePreset} onChange={(e) => set("schedulePreset", e.target.value as SchedulePresetId)}>
                {SCHEDULE_PRESETS.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
                <option value="custom">Custom cron…</option>
              </NativeSelect>
            </Field>
            {s.schedulePreset === "custom" ? (
              <Field id="t-schedule" label="Cron expression (UTC)" error={errors.schedule} hint="minute hour day-of-month month day-of-week, e.g. 30 3 * * 1-5">
                <Input value={s.customCron} onChange={(e) => set("customCron", e.target.value)} placeholder="30 3 * * 1-5" className="font-mono" />
              </Field>
            ) : null}
            <Field
              id="t-poll"
              label="Check for new commits"
              error={errors.poll}
              hint="Rescans only branches whose commit moved since their last scan; unchanged repositories cost one request each."
            >
              <NativeSelect value={s.poll} onChange={(e) => set("poll", e.target.value)}>
                {POLL_PRESETS.map((p) => (
                  <option key={p.value} value={p.value}>
                    {p.label}
                  </option>
                ))}
                {s.poll && !POLL_PRESETS.some((p) => p.value === s.poll) ? <option value={s.poll}>{s.poll}</option> : null}
              </NativeSelect>
            </Field>
            <div className="flex items-center gap-3 sm:col-span-2">
              <Switch id="t-enabled" checked={s.enabled} onCheckedChange={(v) => set("enabled", v)} />
              <label htmlFor="t-enabled" className="text-sm">
                Enabled {s.enabled ? "" : "(the scheduler and “Scan all” skip this target)"}
              </label>
            </div>
          </CardContent>
        </Card>

        {Object.keys(other).length ? (
          <div role="alert" className="rounded-md bg-destructive/10 p-3 text-sm text-destructive">
            <ul className="list-inside list-disc">
              {Object.entries(other).map(([k, v]) => (
                <li key={k}>
                  <code>{k}</code>: {v}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        <InlineError error={preview.error && Object.keys(splitFieldErrors(preview.error, TARGET_FIELDS).fields).length === 0 && Object.keys(other).length === 0 ? preview.error : null} />
        {readOnly ? null : (
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <Button variant="outline" asChild>
              <Link to="/targets">Cancel</Link>
            </Button>
            <Button type="submit" disabled={preview.isPending}>
              <Eye aria-hidden /> {preview.isPending ? "Listing repositories…" : "Preview repositories"}
            </Button>
          </div>
        )}
      </fieldset>
    </form>
  );
}

export function TargetFormPage() {
  const params = useParams({ strict: false }) as { id?: string };
  const id = params.id !== undefined ? Number(params.id) : undefined;
  const q = useQuery({ ...targetQuery(id ?? 0), enabled: id !== undefined });

  const back = (
    <Link to="/targets" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
      <ChevronLeft aria-hidden className="size-4" /> Targets
    </Link>
  );

  if (id === undefined) {
    return (
      <>
        {back}
        <PageHeader title="Add target" description="Scan an organization, a user's repositories or a single repository." />
        <TargetForm />
      </>
    );
  }
  if (q.isPending) return <Skeleton className="h-96 w-full" />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const t = q.data;
  return (
    <>
      {back}
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2">
            {t.label} <OriginBadge origin={t.origin} />
          </span>
        }
        description={t.origin === "config" ? undefined : "Edit the target, then preview the repositories before saving."}
      />
      {t.origin === "config" ? (
        <p className="mb-4 rounded-md border bg-muted p-3 text-sm">
          This target is defined in the Heimdall config file and is read-only here. Edit the config file and restart the server to change it.
        </p>
      ) : null}
      <TargetForm key={t.id} target={t} />
    </>
  );
}
