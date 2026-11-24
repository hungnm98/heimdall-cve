import { http, HttpResponse, type JsonBodyType } from "msw";
import type { AuthProfileInput, FindingSort, FindingStatus, JobRequest, JobStatus, RepoRecord, Severity, TargetInput } from "@/api/types";
import { db, MockProblem, mockConfig, SEV_RANK, sortFindingsBy } from "./db";

/** Matches /api/v1 under any origin or path prefix. */
const p = (path: string) => `*/api/v1${path}`;

export const latency = { ms: 0 };
const wait = () => (latency.ms ? new Promise((r) => setTimeout(r, latency.ms * (0.5 + Math.random()))) : Promise.resolve());

function problem(e: unknown) {
  if (e instanceof MockProblem) {
    return HttpResponse.json(
      { type: "about:blank", title: e.title, status: e.status, detail: e.detail, fields: e.fields },
      { status: e.status, headers: { "Content-Type": "application/problem+json" } },
    );
  }
  throw e;
}

/** Mirrors the server's CSRF guard so the UI can't forget the headers. */
function csrf(request: Request) {
  if (request.headers.get("X-Heimdall-Request") !== "1" || !(request.headers.get("Content-Type") ?? "").startsWith("application/json")) {
    throw new MockProblem(403, "Forbidden", "Writes require Content-Type: application/json and X-Heimdall-Request: 1");
  }
}

async function handle<T extends JsonBodyType | undefined>(
  fn: () => T | Promise<T>,
  status = 200,
): Promise<Response> {
  await wait();
  try {
    const out = await fn();
    if (status === 204 || status === 202) return new HttpResponse(null, { status });
    return HttpResponse.json(out as JsonBodyType, { status });
  } catch (e) {
    return problem(e);
  }
}

async function bodyOf<T>(request: Request): Promise<T> {
  try {
    return (await request.json()) as T;
  } catch {
    throw new MockProblem(400, "Bad Request", "Request body must be JSON");
  }
}

/** Offset pagination; `order` (e.g. "priority:desc") is bound into the cursor like the server's keyset cursors. */
function page<T>(items: T[], url: URL, order = "") {
  const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") ?? 50) || 50));
  const cursor = url.searchParams.get("cursor");
  const prefix = order ? `o:${order}:` : "o:";
  let offset = 0;
  if (cursor) {
    let raw = "";
    try {
      raw = atob(cursor);
    } catch {
      // handled below
    }
    if (!raw.startsWith(prefix) || (!order && raw.slice(2).includes(":")))
      throw new MockProblem(400, "Bad Request", "Invalid cursor", { cursor: "cursor does not match this sort order: restart from the first page" });
    const decoded = Number(raw.slice(prefix.length));
    if (!Number.isFinite(decoded) || decoded < 0) throw new MockProblem(400, "Bad Request", "Invalid cursor", { cursor: "Invalid cursor" });
    offset = decoded;
  }
  const slice = items.slice(offset, offset + limit);
  const next = offset + limit < items.length ? btoa(`${prefix}${offset + limit}`) : undefined;
  return { items: slice, next_cursor: next };
}

const FINDING_SORTS: readonly FindingSort[] = ["severity", "priority", "name", "first_seen", "repo"];

/** Validates sort/order like the API (400 on unknown values) and applies the defaults. */
function sortParams<K extends string>(sp: URLSearchParams, keys: readonly K[], fallback: K, firstAsc: readonly K[]) {
  const s = sp.get("sort");
  const o = sp.get("order");
  const fields: Record<string, string> = {};
  if (s && !keys.includes(s as K)) fields.sort = `must be ${keys.join(", ")}`;
  if (o && o !== "asc" && o !== "desc") fields.order = "must be asc or desc";
  if (Object.keys(fields).length) throw new MockProblem(400, "Bad Request", "Invalid sort", fields);
  const sort = (s as K | null) ?? fallback;
  const order: "asc" | "desc" = (o as "asc" | "desc" | null) ?? (firstAsc.includes(sort) ? "asc" : "desc");
  return { sort, order };
}

const intParam = (v: string | readonly string[] | undefined) => Number(Array.isArray(v) ? v[0] : v);

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export const handlers = [
  http.get(p("/meta"), () => handle(() => db.meta())),

  http.get(p("/dashboard"), ({ request }) =>
    handle(() => db.dashboard(Number(new URL(request.url).searchParams.get("trend_runs") ?? 30))),
  ),

  // ---- targets
  http.get(p("/targets"), () => handle(() => ({ items: db.targets }))),
  http.post(p("/targets/preview"), async ({ request }) =>
    handle(async () => {
      csrf(request);
      const body = await bodyOf<TargetInput>(request);
      await new Promise((r) => setTimeout(r, latency.ms ? 500 : 0));
      return { items: db.previewTarget(body) };
    }),
  ),
  http.post(p("/targets"), async ({ request }) =>
    handle(async () => {
      csrf(request);
      return db.createTarget(await bodyOf<TargetInput>(request));
    }, 201),
  ),
  http.get(p("/targets/:id"), ({ params }) => handle(() => db.getTarget(intParam(params.id)))),
  http.patch(p("/targets/:id"), async ({ request, params }) =>
    handle(async () => {
      csrf(request);
      return db.updateTarget(intParam(params.id), await bodyOf<TargetInput>(request));
    }),
  ),
  http.delete(p("/targets/:id"), ({ request, params }) =>
    handle(() => {
      csrf(request);
      db.deleteTarget(intParam(params.id));
      return undefined;
    }, 204),
  ),

  // ---- auth profiles
  http.get(p("/auth-profiles"), () => handle(() => ({ items: db.profiles.map((x) => db.profile(x)) }))),
  http.post(p("/auth-profiles"), async ({ request }) =>
    handle(async () => {
      csrf(request);
      return db.createProfile(await bodyOf<AuthProfileInput>(request));
    }, 201),
  ),
  http.patch(p("/auth-profiles/:name"), async ({ request, params }) =>
    handle(async () => {
      csrf(request);
      return db.updateProfile(String(params.name), await bodyOf<AuthProfileInput>(request));
    }),
  ),
  http.delete(p("/auth-profiles/:name"), ({ request, params }) =>
    handle(() => {
      csrf(request);
      db.deleteProfile(String(params.name));
      return undefined;
    }, 204),
  ),
  http.post(p("/auth-profiles/:name/test"), ({ request, params }) =>
    handle(() => {
      csrf(request);
      return db.testProfile(String(params.name));
    }),
  ),

  // ---- repos
  http.get(p("/repos"), ({ request }) =>
    handle(() => {
      const url = new URL(request.url);
      const q = (url.searchParams.get("q") ?? "").toLowerCase();
      const target = url.searchParams.get("target_id");
      const { sort, order } = sortParams(url.searchParams, ["name", "last_scanned"] as const, "name", ["name"]);
      const dir = order === "asc" ? 1 : -1;
      const scanned = (r: RepoRecord) => (r.last_scanned_at ? Date.parse(r.last_scanned_at) : -Infinity);
      const items = db.repos
        .filter((r) => (!q || r.full_name.toLowerCase().includes(q)) && (!target || r.target_id === Number(target)))
        .sort(
          (a, b) =>
            dir * ((sort === "last_scanned" ? scanned(a) - scanned(b) : 0) || (a.full_name < b.full_name ? -1 : a.full_name > b.full_name ? 1 : 0)),
        )
        .map((r) => db.repoRecord(r));
      return page(items, url, `${sort}:${order}`);
    }),
  ),
  http.get(p("/repos/:owner/:name"), ({ params }) => handle(() => db.getRepo(String(params.owner), String(params.name)))),

  // ---- findings
  http.get(p("/findings"), ({ request }) =>
    handle(() => {
      const url = new URL(request.url);
      const sp = url.searchParams;
      const fields: Record<string, string> = {};
      const minSev = sp.get("min_severity");
      if (minSev && !SEVERITIES.includes(minSev)) fields.min_severity = "Unknown severity";
      const newSince = sp.get("new_since");
      if (newSince && Number.isNaN(Date.parse(newSince))) fields.new_since = "Must be an RFC 3339 date-time";
      if (Object.keys(fields).length) throw new MockProblem(400, "Bad Request", "Invalid filter", fields);
      const { sort, order } = sortParams(sp, FINDING_SORTS, "severity", ["name", "repo"]);
      const repo = sp.get("repo");
      const kind = sp.get("kind");
      const status = sp.get("status") as FindingStatus | null;
      const kev = sp.get("kev");
      const q = (sp.get("q") ?? "").trim().toLowerCase();
      const items = sortFindingsBy(
        db.findings.filter(
          (f) =>
            (!repo || f.repo === repo) &&
            (!kind || f.kind === kind) &&
            (!status || f.status === status) &&
            (!minSev || SEV_RANK[f.severity] >= SEV_RANK[minSev as Severity]) &&
            (kev === null || f.in_kev === (kev === "true")) &&
            (!newSince || Date.parse(f.first_seen) >= Date.parse(newSince)) &&
            (!q ||
              (f.package?.name.toLowerCase().includes(q) ?? false) ||
              f.advisory_id?.toLowerCase() === q ||
              (f.aliases ?? []).some((a) => a.toLowerCase() === q)),
        ),
        sort,
        order,
      ).map((f) => db.publicFinding(f));
      return page(items, url, `${sort}:${order}`);
    }),
  ),
  http.get(p("/findings/:id"), ({ params }) => handle(() => db.getFinding(String(params.id)))),
  http.put(p("/findings/:id/suppression"), async ({ request, params }) =>
    handle(async () => {
      csrf(request);
      db.suppress(String(params.id), await bodyOf<{ reason?: string; expires_at?: string }>(request));
      return undefined;
    }, 204),
  ),
  http.delete(p("/findings/:id/suppression"), ({ request, params }) =>
    handle(() => {
      csrf(request);
      db.unsuppress(String(params.id));
      return undefined;
    }, 204),
  ),

  // ---- runs
  http.get(p("/runs"), ({ request }) => handle(() => page([...db.runs].reverse(), new URL(request.url)))),
  http.get(p("/runs/:id"), ({ params }) => handle(() => db.getRun(intParam(params.id)))),
  http.get(p("/runs/:id/diff"), ({ request, params }) =>
    handle(() => {
      const against = new URL(request.url).searchParams.get("against");
      return db.diff(intParam(params.id), against ? Number(against) : undefined);
    }),
  ),

  // ---- jobs
  http.get(p("/jobs"), ({ request }) =>
    handle(() => {
      const url = new URL(request.url);
      const status = url.searchParams.get("status") as JobStatus | null;
      const target = url.searchParams.get("target_id");
      const items = db.jobs.filter((j) => (!status || j.status === status) && (!target || j.target_id === Number(target)));
      return page(items, url);
    }),
  ),
  http.post(p("/jobs"), async ({ request }) => {
    await wait();
    try {
      csrf(request);
      const { job, created } = db.trigger(await bodyOf<JobRequest>(request));
      return HttpResponse.json(job, { status: created ? 201 : 200 });
    } catch (e) {
      return problem(e);
    }
  }),
  http.get(p("/jobs/:id"), ({ params }) => handle(() => db.getJob(intParam(params.id)))),
  http.post(p("/jobs/:id/cancel"), ({ request, params }) =>
    handle(() => {
      csrf(request);
      db.cancel(intParam(params.id));
      return undefined;
    }, 202),
  ),
  http.get(p("/jobs/:id/events"), ({ request, params }) => {
    const id = intParam(params.id);
    let job;
    try {
      job = db.getJob(id);
    } catch (e) {
      return problem(e);
    }
    const url = new URL(request.url);
    if (!(request.headers.get("Accept") ?? "").includes("text/event-stream")) {
      const after = Number(url.searchParams.get("after_id") ?? 0);
      const limit = Number(url.searchParams.get("limit") ?? 50);
      return HttpResponse.json({ items: (db.events.get(id) ?? []).filter((e) => e.id > after).slice(0, limit) });
    }
    const lastId = Number(request.headers.get("Last-Event-ID") ?? 0);
    const enc = new TextEncoder();
    let unsubscribe = () => {};
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        const write = (s: string) => {
          try {
            controller.enqueue(enc.encode(s));
          } catch {
            unsubscribe();
          }
        };
        const done = (j: typeof job) => {
          write(`event: done\ndata: ${JSON.stringify(j)}\n\n`);
          unsubscribe();
          try {
            controller.close();
          } catch {
            // already closed
          }
        };
        write("retry: 1000\n\n");
        for (const ev of db.events.get(id) ?? []) {
          if (ev.id > lastId) write(`id: ${ev.id}\nevent: progress\ndata: ${JSON.stringify(ev)}\n\n`);
        }
        if (job.status !== "queued" && job.status !== "running") {
          done(job);
          return;
        }
        unsubscribe = db.subscribe(id, (msg) => {
          if (msg.type === "progress") write(`id: ${msg.event.id}\nevent: progress\ndata: ${JSON.stringify(msg.event)}\n\n`);
          else done(msg.job);
        });
      },
      cancel() {
        unsubscribe();
      },
    });
    return new HttpResponse(stream, {
      headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" },
    });
  }),

  // ---- system
  http.get(p("/sources"), () => handle(() => ({ items: db.sources }))),
  http.get(p("/notifiers"), () => handle(() => ({ items: db.notifiers }))),
  http.post(p("/notifiers/:name/test"), ({ request, params }) =>
    handle(() => {
      csrf(request);
      db.testNotifier(String(params.name));
      return undefined;
    }, 204),
  ),
  http.get(p("/audit"), ({ request }) => handle(() => page(db.audit, new URL(request.url)))),
];

export { db, mockConfig };
