/**
 * In-memory state of the mock API. Behaves like the real service layer closely
 * enough for the UI: validation with problem `fields`, idempotent job triggers,
 * jobs that progress over time and stream events, audit entries for writes.
 */
import type {
  AuditEntry,
  AuthProfile,
  AuthProfileInput,
  DashboardSummary,
  Diff,
  Finding,
  FindingSort,
  Job,
  JobEvent,
  JobRequest,
  Meta,
  NotifierStatus,
  Repo,
  RepoDetail,
  RepoRecord,
  ScanRun,
  Severity,
  SourceStatus,
  Target,
  TargetInput,
  UpgradeItem,
} from "@/api/types";
import {
  ACTOR,
  type FindingRow,
  hashId,
  iso,
  makeAudit,
  makeAuthProfiles,
  makeFindings,
  makeJobs,
  makeNotifiers,
  makeRuns,
  makeSources,
  makeTargets,
  repoRecords,
  runtimesFor,
} from "./fixtures";

export class MockProblem extends Error {
  constructor(
    readonly status: number,
    readonly title: string,
    readonly detail?: string,
    readonly fields?: Record<string, string>,
  ) {
    super(detail ?? title);
  }
}

const bad = (fields: Record<string, string>, detail = "Validation failed") =>
  new MockProblem(400, "Bad Request", detail, fields);
const notFound = (what: string) => new MockProblem(404, "Not Found", `${what} not found`);
const conflict = (detail: string) => new MockProblem(409, "Conflict", detail);

export const SEV_RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

export const mockConfig = {
  /** Delay between simulated job steps (ms). */
  stepMs: 450,
  secretsEnabled: true,
};

type Listener = (ev: { type: "progress"; event: JobEvent } | { type: "done"; job: Job }) => void;

class Db {
  targets: Target[] = [];
  profiles: AuthProfile[] = [];
  repos: RepoRecord[] = [];
  findings: FindingRow[] = [];
  runs: ScanRun[] = [];
  jobs: Job[] = [];
  events = new Map<number, JobEvent[]>();
  sources: SourceStatus[] = [];
  notifiers: NotifierStatus[] = [];
  audit: AuditEntry[] = [];
  private listeners = new Map<number, Set<Listener>>();
  private timers: ReturnType<typeof setTimeout>[] = [];
  private seq = { target: 10, profile: 10, job: 100, event: 1000, run: 200, audit: 1000 };

  constructor() {
    this.reset();
  }

  reset() {
    this.timers.forEach(clearTimeout);
    this.timers = [];
    this.listeners.clear();
    this.targets = makeTargets();
    this.profiles = makeAuthProfiles();
    this.repos = repoRecords();
    this.findings = makeFindings();
    this.runs = makeRuns();
    const seeds = makeJobs();
    this.jobs = seeds.map((s) => s.job).sort((a, b) => b.id - a.id);
    this.events = new Map(seeds.map((s) => [s.job.id, s.events]));
    this.sources = makeSources();
    this.notifiers = makeNotifiers();
    this.audit = makeAudit();
    this.seq = { target: 10, profile: 10, job: 100, event: 1000, run: 200, audit: 1000 };
    // Keep the latest run consistent with the current findings.
    // Trend converges on today's open findings: older runs had a few more.
    const current = this.openBySeverity(this.findings);
    const extra: Record<string, number> = { CRITICAL: 0.25, HIGH: 0.6, MEDIUM: 0.4, LOW: 0.1, UNKNOWN: 0 };
    this.runs.forEach((run, i) => {
      if (!run.stats) return;
      const age = this.runs.length - 1 - i;
      run.stats.open_by_severity = Object.fromEntries(
        Object.entries(current).map(([sev, n]) => [sev, n + Math.round(age * (extra[sev] ?? 0) + ((i * 7) % 3) * (age > 0 ? 1 : 0))]),
      );
    });
  }

  /** Starts the fixture jobs that are queued/running (browser only, so tests stay deterministic). */
  startBackground() {
    for (const job of this.jobs) {
      if (job.status === "running") this.simulate(job, 1);
      else if (job.status === "queued") this.later(6 * mockConfig.stepMs * 2, () => this.simulate(job));
    }
  }

  private later(ms: number, fn: () => void) {
    this.timers.push(setTimeout(fn, ms));
  }

  meta(): Meta {
    return {
      version: "v0.3.0-mock",
      secrets_enabled: mockConfig.secretsEnabled,
      jobs_backend: "asynq",
      providers: ["github"],
      auth_types: ["token", "app", "ssh"],
    };
  }

  private log(action: string, object_type: string, object_id: string, details?: Record<string, unknown>) {
    this.audit.unshift({ id: this.seq.audit++, at: iso(Date.now()), actor: ACTOR, action, object_type, object_id, details });
  }

  // ---- derived -------------------------------------------------------------------

  openBySeverity(fs: Finding[]) {
    const m: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 };
    for (const f of fs) if (f.status === "open") m[f.severity] = (m[f.severity] ?? 0) + 1;
    return m;
  }

  repoRecord(r: RepoRecord): RepoRecord {
    return { ...r, open_by_severity: this.openBySeverity(this.findings.filter((f) => f.repo === r.full_name)) };
  }

  profile(p: AuthProfile): AuthProfile {
    return { ...p, used_by: this.targets.filter((t) => t.auth === p.name || t.list_auth === p.name).map((t) => t.id) };
  }

  publicFinding(f: FindingRow): Finding {
    const { suppression: _s, ...rest } = f;
    return rest;
  }

  // ---- targets ---------------------------------------------------------------------

  private validateTarget(input: TargetInput): Record<string, string> {
    const fields: Record<string, string> = {};
    if (!["org", "user", "repo"].includes(input.kind)) fields.kind = "Must be org, user or repo";
    if (input.kind === "org" || input.kind === "user") {
      if (!input.owner?.trim()) fields.owner = "Required for org and user targets";
      else if (!/^[A-Za-z0-9-]{1,39}$/.test(input.owner.trim())) fields.owner = "Not a valid GitHub login";
    }
    if (input.kind === "repo") {
      if (!input.url?.trim()) fields.url = "Required for repo targets";
      else if (!parseRepoUrl(input.url)) fields.url = "Use https://host/owner/name, git@host:owner/name.git or ssh://…";
    }
    const auth = this.profiles.find((p) => p.name === input.auth);
    if (!input.auth) fields.auth = "Choose an auth profile";
    else if (!auth) fields.auth = `Unknown auth profile "${input.auth}"`;
    if (auth?.type === "ssh" && input.kind !== "repo") {
      if (!input.list_auth) fields.list_auth = "SSH cannot list repositories; choose a token or app profile";
      else if (this.profiles.find((p) => p.name === input.list_auth)?.type === "ssh")
        fields.list_auth = "The listing profile must be a token or app profile";
    }
    if (input.schedule && input.schedule.trim().split(/\s+/).length !== 5)
      fields.schedule = "Invalid cron expression: expected 5 fields";
    if (input.filter?.max_repos !== undefined && input.filter.max_repos < 0)
      fields["filter.max_repos"] = "Must be zero or positive";
    return fields;
  }

  private labelOf(input: TargetInput) {
    if (input.kind === "repo") {
      const p = parseRepoUrl(input.url ?? "");
      return `repo:${p ? `${p.owner}/${p.name}` : input.url}`;
    }
    return `${input.kind}:${input.owner?.trim()}`;
  }

  getTarget(id: number) {
    const t = this.targets.find((x) => x.id === id);
    if (!t) throw notFound(`Target ${id}`);
    return t;
  }

  createTarget(input: TargetInput): Target {
    const fields = this.validateTarget(input);
    if (Object.keys(fields).length) throw bad(fields);
    const label = this.labelOf(input);
    if (this.targets.some((t) => t.label === label)) throw conflict(`A target for ${label} already exists`);
    const now = iso(Date.now());
    const parsed = input.kind === "repo" ? parseRepoUrl(input.url ?? "") : null;
    const t: Target = {
      provider: "github",
      ...input,
      owner: parsed?.owner ?? input.owner?.trim(),
      name: parsed?.name,
      enabled: input.enabled ?? true,
      id: this.seq.target++,
      label,
      origin: "ui",
      next_run_at: input.schedule ? iso(Date.now() + 6 * 3600_000) : null,
      created_at: now,
      updated_at: now,
    };
    this.targets.push(t);
    this.log("target.create", "target", String(t.id), { label });
    return t;
  }

  updateTarget(id: number, input: TargetInput): Target {
    const t = this.getTarget(id);
    if (t.origin === "config") throw conflict("This target comes from the config file and is read-only. Edit the config file instead.");
    const fields = this.validateTarget(input);
    if (Object.keys(fields).length) throw bad(fields);
    const parsed = input.kind === "repo" ? parseRepoUrl(input.url ?? "") : null;
    Object.assign(t, input, {
      owner: parsed?.owner ?? input.owner?.trim(),
      name: parsed?.name,
      label: this.labelOf(input),
      enabled: input.enabled ?? true,
      next_run_at: input.schedule && (input.enabled ?? true) ? iso(Date.now() + 6 * 3600_000) : null,
      updated_at: iso(Date.now()),
    });
    this.log("target.update", "target", String(id));
    return t;
  }

  deleteTarget(id: number) {
    const t = this.getTarget(id);
    if (t.origin === "config") throw conflict("This target comes from the config file and is read-only. Remove it from the config file instead.");
    this.targets = this.targets.filter((x) => x.id !== id);
    this.log("target.delete", "target", String(id), { label: t.label });
  }

  previewTarget(input: TargetInput): Repo[] {
    const fields = this.validateTarget(input);
    if (Object.keys(fields).length) throw bad(fields);
    if (input.kind === "repo") {
      const p = parseRepoUrl(input.url ?? "")!;
      return [mkRepo(p.owner, p.name, input.branch)];
    }
    const owner = input.owner!.trim();
    if (owner.toLowerCase() === "unreachable")
      throw new MockProblem(502, "Bad Gateway", "GitHub API: GET /orgs/unreachable/repos: 503 Service Unavailable");
    const known = this.repos.filter((r) => r.owner === owner);
    let repos: Repo[] = known.length
      ? known.map(({ target_id: _t, last_listed_at: _l, last_head_sha: _h, last_scanned_at: _s, open_by_severity: _o, ...r }) => r)
      : ["api-gateway", "billing", "docs", "frontend", "worker", "terraform-modules"].map((n, i) =>
          mkRepo(owner, n, input.branch, i === 2 ? { archived: true } : i === 4 ? { fork: true } : {}),
        );
    const f = input.filter ?? {};
    if (f.skip_archived ?? true) repos = repos.filter((r) => !r.archived);
    if (f.skip_forks ?? true) repos = repos.filter((r) => !r.fork);
    if (f.include?.length) repos = repos.filter((r) => f.include!.some((g) => glob(g, r.full_name) || glob(g, r.name)));
    if (f.exclude?.length) repos = repos.filter((r) => !f.exclude!.some((g) => glob(g, r.full_name) || glob(g, r.name)));
    if (f.topics?.length) repos = repos.filter((r) => r.topics?.some((t) => f.topics!.includes(t)));
    if (f.max_repos) repos = repos.slice(0, f.max_repos);
    if (input.repos?.length) repos = repos.filter((r) => input.repos!.includes(r.name) || input.repos!.includes(r.full_name));
    return repos;
  }

  // ---- auth profiles ------------------------------------------------------------------

  private validateProfile(input: AuthProfileInput, creating: boolean) {
    const fields: Record<string, string> = {};
    if (creating && !/^[a-z0-9][a-z0-9_-]{0,62}$/.test(input.name ?? ""))
      fields.name = "Lowercase letters, digits, - and _ (max 63), starting with a letter or digit";
    if (!["token", "app", "ssh"].includes(input.type)) fields.type = "Must be token, app or ssh";
    if (input.type === "app") {
      if (!input.options?.app_id) fields["options.app_id"] = "Required for GitHub App profiles";
      if (!input.options?.installation_id) fields["options.installation_id"] = "Required for GitHub App profiles";
    }
    if (input.secret !== undefined && input.secret.trim() === "") fields.secret = "Must not be blank; omit it to keep the current secret";
    if (input.type === "app" && input.secret && !input.secret.includes("PRIVATE KEY"))
      fields.secret = "Expected a PEM encoded private key";
    return fields;
  }

  createProfile(input: AuthProfileInput): AuthProfile {
    const fields = this.validateProfile(input, true);
    if (Object.keys(fields).length) throw bad(fields);
    if (this.profiles.some((p) => p.name === input.name)) throw conflict(`Auth profile "${input.name}" already exists`);
    if (input.secret && !mockConfig.secretsEnabled)
      throw new MockProblem(503, "Service Unavailable", "Secrets are disabled: no master key is configured");
    const now = iso(Date.now());
    const p: AuthProfile = {
      id: this.seq.profile++,
      name: input.name,
      type: input.type,
      options: input.options ?? {},
      has_secret: !!input.secret,
      secret_fingerprint: input.secret ? fingerprint(input.secret) : undefined,
      origin: "ui",
      created_at: now,
      updated_at: now,
    };
    this.profiles.push(p);
    this.log("auth_profile.create", "auth_profile", p.name, { secret: input.secret ? "set" : "none" });
    return this.profile(p);
  }

  updateProfile(name: string, input: AuthProfileInput): AuthProfile {
    const p = this.profiles.find((x) => x.name === name);
    if (!p) throw notFound(`Auth profile "${name}"`);
    if (p.origin === "config") throw conflict("This auth profile comes from the config file and is read-only.");
    const fields = this.validateProfile(input, false);
    if (Object.keys(fields).length) throw bad(fields);
    if (input.secret && !mockConfig.secretsEnabled)
      throw new MockProblem(503, "Service Unavailable", "Secrets are disabled: no master key is configured");
    p.type = input.type;
    p.options = input.options ?? {};
    if (input.secret) {
      p.has_secret = true;
      p.secret_fingerprint = fingerprint(input.secret);
      this.log("auth_profile.secret.replace", "auth_profile", name);
    }
    p.updated_at = iso(Date.now());
    this.log("auth_profile.update", "auth_profile", name);
    return this.profile(p);
  }

  deleteProfile(name: string) {
    const p = this.profiles.find((x) => x.name === name);
    if (!p) throw notFound(`Auth profile "${name}"`);
    if (p.origin === "config") throw conflict("This auth profile comes from the config file and is read-only.");
    const used = this.profile(p).used_by ?? [];
    if (used.length)
      throw conflict(`Auth profile "${name}" is used by ${used.length === 1 ? "target" : "targets"} ${used.map((id) => `#${id}`).join(", ")}`);
    this.profiles = this.profiles.filter((x) => x !== p);
    this.log("auth_profile.delete", "auth_profile", name);
  }

  testProfile(name: string) {
    const p = this.profiles.find((x) => x.name === name);
    if (!p) throw notFound(`Auth profile "${name}"`);
    if (!p.has_secret) return { ok: false, message: "No secret is configured for this profile" };
    if (p.type === "ssh") return { ok: true, message: "SSH handshake with github.com succeeded (ED25519 host key verified)" };
    if (p.type === "app") return { ok: true, message: `Authenticated as GitHub App ${String(p.options?.app_id ?? "")} (installation on globex, 4 repositories)` };
    return { ok: true, message: "Authenticated as acme-heimdall-bot (scopes: repo, read:org); 4,812 API calls remaining" };
  }

  // ---- repos & findings ---------------------------------------------------------------------

  getRepo(owner: string, name: string): RepoDetail {
    const r = this.repos.find((x) => x.owner === owner && x.name === name);
    if (!r) throw notFound(`Repository ${owner}/${name}`);
    const findings = this.findings.filter((f) => f.repo === r.full_name);
    const open: Record<string, number> = {};
    for (const f of findings) open[f.severity] = (open[f.severity] ?? 0) + 1;
    return {
      repo: this.repoRecord(r),
      branches: [{ name: r.ref, primary: true, open_by_severity: open }],
      findings: sortFindings(findings).map((f) => this.publicFinding(f)),
      runtimes: runtimesFor(r.full_name),
      upgrade_plan: upgradePlan(findings),
    };
  }

  getFinding(id: string) {
    const f = this.findings.find((x) => x.id === id);
    if (!f) throw notFound(`Finding ${id}`);
    return f;
  }

  suppress(id: string, body: { reason?: string; expires_at?: string }) {
    const f = this.getFinding(id);
    const fields: Record<string, string> = {};
    const reason = (body.reason ?? "").trim();
    if (reason.length < 3) fields.reason = "A reason of at least 3 characters is required";
    if (reason.length > 1000) fields.reason = "At most 1000 characters";
    const exp = Date.parse(body.expires_at ?? "");
    if (Number.isNaN(exp)) fields.expires_at = "Required (RFC 3339 date-time)";
    else if (exp <= Date.now()) fields.expires_at = "Must be in the future";
    else if (exp > Date.now() + 366 * 24 * 3600_000) fields.expires_at = "At most one year ahead";
    if (Object.keys(fields).length) throw bad(fields);
    f.status = "suppressed";
    f.suppression = { reason, expires_at: new Date(exp).toISOString(), actor: ACTOR, created_at: iso(Date.now()) };
    this.log("finding.suppress", "finding", id, { reason, expires_at: f.suppression.expires_at });
  }

  unsuppress(id: string) {
    const f = this.getFinding(id);
    f.status = "open";
    f.suppression = undefined;
    this.log("finding.unsuppress", "finding", id);
  }

  // ---- runs -------------------------------------------------------------------------------------

  getRun(id: number) {
    const r = this.runs.find((x) => x.id === id);
    if (!r) throw notFound(`Run ${id}`);
    return r;
  }

  diff(id: number, against?: number): Diff {
    const to = this.getRun(id);
    const idx = this.runs.indexOf(to);
    const from = against !== undefined ? this.getRun(against) : this.runs[idx - 1];
    if (!from) throw notFound(`No run before #${id} to compare with`);
    const [a, b] = Date.parse(from.started_at) < Date.parse(to.started_at) ? [from, to] : [to, from];
    const aT = Date.parse(a.started_at);
    const bT = Date.parse(b.finished_at ?? b.started_at);
    const pub = (fs: FindingRow[]) => sortFindings(fs).map((f) => this.publicFinding(f));
    const seenAt = (f: FindingRow, t: number) => Date.parse(f.first_seen) <= t && Date.parse(f.last_seen) >= t;
    return {
      from_run: from.id,
      to_run: to.id,
      new: pub(this.findings.filter((f) => Date.parse(f.first_seen) > aT && Date.parse(f.first_seen) <= bT)),
      fixed: pub(this.findings.filter((f) => f.status === "fixed" && Date.parse(f.last_seen) >= aT && Date.parse(f.last_seen) < bT)),
      still_open: pub(this.findings.filter((f) => seenAt(f, aT) && f.status !== "fixed")),
    };
  }

  // ---- jobs -------------------------------------------------------------------------------------

  getJob(id: number) {
    const j = this.jobs.find((x) => x.id === id);
    if (!j) throw notFound(`Job ${id}`);
    return j;
  }

  trigger(req: JobRequest, by = ACTOR): { job: Job; created: boolean } {
    const fields: Record<string, string> = {};
    if (req.repo_url) {
      if (!parseRepoUrl(req.repo_url)) fields.repo_url = "Not a valid repository URL";
      if (!req.auth_profile) fields.auth_profile = "Required with repo_url";
      else if (!this.profiles.some((p) => p.name === req.auth_profile)) fields.auth_profile = "Unknown auth profile";
    }
    if (req.repo && req.target_id === undefined) fields.target_id = "Required with repo";
    if (Object.keys(fields).length) throw bad(fields);
    if (req.target_id !== undefined) {
      const t = this.getTarget(req.target_id);
      if (req.repo && !this.repos.some((r) => r.full_name === req.repo && r.target_id === t.id))
        throw notFound(`Repository ${req.repo} in target ${t.label}`);
    }
    const repo = req.repo ?? (req.repo_url ? req.repo_url : "");
    const existing = this.jobs.find(
      (j) => (j.target_id ?? null) === (req.target_id ?? null) && (j.repo ?? "") === repo && (j.status === "queued" || j.status === "running"),
    );
    if (existing) return { job: existing, created: false };
    const job: Job = {
      id: this.seq.job++,
      target_id: req.target_id ?? null,
      repo,
      branch: req.branch,
      auth_profile: req.auth_profile,
      trigger: "manual",
      status: "queued",
      run_id: null,
      attempts: 0,
      requested_by: by,
      created_at: iso(Date.now()),
      started_at: null,
      finished_at: null,
    };
    this.jobs.unshift(job);
    this.events.set(job.id, []);
    this.log("job.trigger", "job", String(job.id), { ...req });
    this.later(mockConfig.stepMs, () => this.simulate(job));
    return { job, created: true };
  }

  cancel(id: number) {
    const j = this.getJob(id);
    if (j.status !== "queued" && j.status !== "running") throw conflict(`Job ${id} already ${j.status}`);
    this.emit(j, "warn", `Canceled by ${ACTOR}`);
    this.finish(j, "canceled");
    this.log("job.cancel", "job", String(id));
  }

  subscribe(jobId: number, fn: Listener) {
    let set = this.listeners.get(jobId);
    if (!set) this.listeners.set(jobId, (set = new Set()));
    set.add(fn);
    return () => set!.delete(fn);
  }

  private emit(job: Job, level: JobEvent["level"], message: string, repo?: string) {
    const ev: JobEvent = { id: this.seq.event++, job_id: job.id, at: iso(Date.now()), level, message, repo };
    const list = this.events.get(job.id);
    if (list) list.push(ev);
    else this.events.set(job.id, [ev]);
    this.listeners.get(job.id)?.forEach((fn) => fn({ type: "progress", event: ev }));
  }

  private finish(job: Job, status: Job["status"], error?: string) {
    job.status = status;
    job.finished_at = iso(Date.now());
    if (error) job.error = error;
    this.listeners.get(job.id)?.forEach((fn) => fn({ type: "done", job }));
    this.listeners.delete(job.id);
  }

  /** Plays a scripted scan: one event per step, then a new run. */
  private simulate(job: Job, skip = 0) {
    if (job.status === "canceled") return;
    const target = job.target_id != null ? this.targets.find((t) => t.id === job.target_id) : undefined;
    const scopeRepos: { full: string; repo?: RepoRecord }[] = job.repo
      ? [{ full: parseRepoUrl(job.repo) ? `${parseRepoUrl(job.repo)!.owner}/${parseRepoUrl(job.repo)!.name}` : job.repo }]
      : target
        ? this.reposForTarget(target)
        : this.targets.filter((t) => t.enabled).flatMap((t) => this.reposForTarget(t));
    const label = job.repo ? job.repo : (target?.label ?? "all enabled targets");
    const steps: (() => void)[] = [
      () => {
        job.status = "running";
        job.started_at = iso(Date.now());
        job.attempts += 1;
        this.emit(job, "info", `Scanning ${label}`);
      },
      () => this.emit(job, "info", `Listed ${scopeRepos.length} ${scopeRepos.length === 1 ? "repository" : "repositories"}`),
    ];
    scopeRepos.slice(0, 6).forEach(({ full }, i) => {
      steps.push(() => this.emit(job, "info", `Fetching manifests (${i % 2 ? "API, cache hit" : "git mirror"})`, full));
      steps.push(() =>
        i === 3
          ? this.emit(job, "warn", "osv: retrying after 429 Too Many Requests", full)
          : this.emit(job, "info", `Resolved ${12 + ((i * 37) % 180)} packages, ${(i * 3) % 5} findings`, full),
      );
    });
    steps.push(() => {
      const run: ScanRun = {
        id: this.seq.run++,
        started_at: job.started_at ?? iso(Date.now()),
        finished_at: iso(Date.now()),
        status: "succeeded",
        targets: target ? [target.label] : this.targets.filter((t) => t.enabled).map((t) => t.label),
        repos_scanned: scopeRepos.map((r) => r.full),
        repos_failed: [],
        sources: this.runs[this.runs.length - 1]?.sources,
        stats: { open_by_severity: this.openBySeverity(this.findings), new: 0, fixed: 0, repos: scopeRepos.length },
      };
      this.runs.push(run);
      job.run_id = run.id;
      const now = iso(Date.now());
      for (const { full } of scopeRepos) {
        const rec = this.repos.find((r) => r.full_name === full);
        if (rec) rec.last_scanned_at = now;
        else if (target) {
          const [owner, name] = full.split("/") as [string, string];
          this.repos.push({ ...mkRepo(owner, name, target.branch), target_id: target.id, last_listed_at: now, last_scanned_at: now, open_by_severity: {} });
        }
      }
      this.emit(job, "info", `Run #${run.id} finished: ${scopeRepos.length} scanned, 0 failed`);
      this.finish(job, "succeeded");
    });
    // A fixture job that is already running skips its start step(s).
    steps.slice(skip > 0 ? 1 : 0).forEach((step, i) =>
      this.later((i + 1) * mockConfig.stepMs, () => {
        if (job.status !== "canceled") step();
      }),
    );
  }

  private reposForTarget(t: Target): { full: string; repo?: RepoRecord }[] {
    const known = this.repos.filter((r) => r.target_id === t.id);
    if (known.length) return known.map((r) => ({ full: r.full_name, repo: r }));
    try {
      return this.previewTarget(t).map((r) => ({ full: r.full_name }));
    } catch {
      return [];
    }
  }

  // ---- dashboard -----------------------------------------------------------------------------------

  dashboard(trendRuns = 30): DashboardSummary {
    const open = this.findings.filter((f) => f.status === "open");
    const eol = this.repos.flatMap((r) =>
      runtimesFor(r.full_name)
        .filter((rt) => rt.status === "eol" || rt.status === "eol-soon")
        .map((rt) => ({ ...rt, repo: r.full_name })),
    );
    const unhealthy = this.sources.filter((s) => !s.healthy).map((s) => ({ name: s.name, healthy: false, error: s.error }));
    return {
      open_by_severity: this.openBySeverity(this.findings),
      open_kev: open.filter((f) => f.in_kev).length,
      open_malicious: open.filter((f) => f.malicious).length,
      repos: this.repos.length,
      trend: this.runs.slice(-trendRuns),
      top_findings: [...open].sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0)).slice(0, 10).map((f) => this.publicFinding(f)),
      eol_runtimes: eol,
      unhealthy_sources: unhealthy,
      active_jobs: this.jobs.filter((j) => j.status === "queued" || j.status === "running"),
      last_run: this.runs[this.runs.length - 1],
    };
  }

  testNotifier(name: string) {
    const n = this.notifiers.find((x) => x.name === name);
    if (!n) throw notFound(`Notifier "${name}"`);
    this.log("notifier.test", "notifier", name);
    if (n.type === "webhook") throw new MockProblem(502, "Bad Gateway", "POST https://events.pagerduty.example/v2/enqueue: 400 Invalid routing key");
  }
}

// ---- helpers ------------------------------------------------------------------------------------

export function sortFindings<T extends Finding>(fs: T[]): T[] {
  return [...fs].sort(
    (a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.repo.localeCompare(b.repo) || a.id.localeCompare(b.id),
  );
}

const cmp = (a: string | number, b: string | number) => (a < b ? -1 : a > b ? 1 : 0);

/** GET /findings?sort=&order= as the server orders it (see store.FindingSort). */
export function sortFindingsBy<T extends Finding>(fs: T[], sort: FindingSort, order: "asc" | "desc"): T[] {
  if (sort === "severity") return order === "desc" ? sortFindings(fs) : sortFindings(fs).reverse(); // asc: exact reverse
  const key: Record<Exclude<FindingSort, "severity">, (f: T) => string | number> = {
    priority: (f) => f.priority ?? 0,
    name: (f) => (f.package?.name || f.runtime?.name || f.advisory_id || "").toLowerCase(),
    first_seen: (f) => Date.parse(f.first_seen),
    repo: (f) => f.repo,
  };
  const get = key[sort];
  const dir = order === "asc" ? 1 : -1;
  return [...fs].sort((a, b) => dir * (cmp(get(a), get(b)) || cmp(a.id, b.id)));
}

function upgradePlan(fs: FindingRow[]): UpgradeItem[] {
  const by = new Map<string, UpgradeItem>();
  for (const f of fs) {
    if (f.status !== "open" || f.kind !== "dependency" || !f.package) continue;
    const key = `${f.manifest_path}|${f.package.name}`;
    const cur = by.get(key);
    if (!cur) {
      by.set(key, {
        package: f.package,
        manifest: f.manifest_path,
        direct: f.direct ?? false,
        recommended: f.recommended_version,
        bump: f.bump ?? "",
        severity: f.severity,
        advisories: [f.advisory_id ?? f.id],
        advice: f.advice,
      });
    } else {
      cur.advisories.push(f.advisory_id ?? f.id);
      if (SEV_RANK[f.severity] > SEV_RANK[cur.severity]) cur.severity = f.severity;
    }
  }
  return [...by.values()].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || a.package.name.localeCompare(b.package.name));
}

export function parseRepoUrl(url: string): { host: string; owner: string; name: string } | null {
  const u = url.trim();
  let m = /^https?:\/\/([^/]+)\/([^/]+)\/([^/]+?)(?:\.git)?\/?$/.exec(u);
  if (!m) m = /^git@([^:]+):([^/]+)\/([^/]+?)(?:\.git)?$/.exec(u);
  if (!m) m = /^ssh:\/\/(?:[^@]+@)?([^/]+)\/([^/]+)\/([^/]+?)(?:\.git)?$/.exec(u);
  if (!m) return null;
  return { host: m[1]!, owner: m[2]!, name: m[3]! };
}

function mkRepo(owner: string, name: string, branch?: string, extra: Partial<Repo> = {}): Repo {
  return {
    provider: "github",
    host: "github.com",
    owner,
    name,
    full_name: `${owner}/${name}`,
    html_url: `https://github.com/${owner}/${name}`,
    default_branch: "main",
    ref: branch || "main",
    private: true,
    archived: false,
    fork: false,
    topics: [],
    ...extra,
  };
}

function glob(pattern: string, s: string) {
  const re = new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
  return re.test(s);
}

function fingerprint(secret: string) {
  const h = hashId(secret);
  return `${h.slice(0, 8)}…${secret.trim().slice(-4)}`;
}

export const db = new Db();
