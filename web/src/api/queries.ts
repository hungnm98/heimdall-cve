import {
  infiniteQueryOptions,
  queryOptions,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { api, unwrap } from "./client";
import type {
  AuthProfileInput,
  FindingsQuery,
  JobStatus,
  SuppressInput,
  TargetInput,
} from "./types";

export const PAGE_SIZE = 50;

/** Statuses of a job that has not finished yet. */
export const ACTIVE_JOB_STATUSES: readonly JobStatus[] = ["queued", "running"];

export const keys = {
  meta: ["meta"] as const,
  dashboard: ["dashboard"] as const,
  targets: ["targets"] as const,
  target: (id: number) => ["targets", id] as const,
  authProfiles: ["auth-profiles"] as const,
  repos: ["repos"] as const,
  repoList: (q: { q?: string; target_id?: number }) => ["repos", "list", q] as const,
  repo: (owner: string, name: string, branch = "") => ["repos", "detail", owner, name, branch] as const,
  findings: ["findings"] as const,
  findingList: (q: FindingsQuery) => ["findings", "list", q] as const,
  finding: (id: string) => ["findings", "detail", id] as const,
  runs: ["runs"] as const,
  run: (id: number) => ["runs", "detail", id] as const,
  diff: (id: number, against?: number) => ["runs", "diff", id, against ?? null] as const,
  jobs: ["jobs"] as const,
  jobList: (q: { status?: JobStatus; target_id?: number }) => ["jobs", "list", q] as const,
  activeJobs: ["jobs", "active"] as const,
  job: (id: number) => ["jobs", "detail", id] as const,
  sources: ["sources"] as const,
  notifiers: ["notifiers"] as const,
  audit: ["audit"] as const,
};

const nextCursor = (last: { next_cursor?: string }) => last.next_cursor || undefined;

export const metaQuery = () =>
  queryOptions({
    queryKey: keys.meta,
    queryFn: () => unwrap(api.GET("/meta")),
    staleTime: 5 * 60_000,
  });

export const dashboardQuery = () =>
  queryOptions({
    queryKey: keys.dashboard,
    queryFn: () => unwrap(api.GET("/dashboard", { params: { query: { trend_runs: 30 } } })),
  });

export const targetsQuery = () =>
  queryOptions({ queryKey: keys.targets, queryFn: () => unwrap(api.GET("/targets")) });

export const targetQuery = (id: number) =>
  queryOptions({
    queryKey: keys.target(id),
    queryFn: () => unwrap(api.GET("/targets/{id}", { params: { path: { id } } })),
  });

export const authProfilesQuery = () =>
  queryOptions({ queryKey: keys.authProfiles, queryFn: () => unwrap(api.GET("/auth-profiles")) });

export const reposQuery = (q: { q?: string; target_id?: number }) =>
  infiniteQueryOptions({
    queryKey: keys.repoList(q),
    queryFn: ({ pageParam }) =>
      unwrap(api.GET("/repos", { params: { query: { ...q, cursor: pageParam, limit: PAGE_SIZE } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
  });

export const repoQuery = (owner: string, name: string, branch = "") =>
  queryOptions({
    queryKey: keys.repo(owner, name, branch),
    queryFn: () =>
      unwrap(api.GET("/repos/{owner}/{name}", { params: { path: { owner, name }, query: branch ? { branch } : {} } })),
  });

export const findingsQuery = (q: FindingsQuery) =>
  infiniteQueryOptions({
    queryKey: keys.findingList(q),
    queryFn: ({ pageParam }) =>
      unwrap(api.GET("/findings", { params: { query: { ...q, cursor: pageParam, limit: PAGE_SIZE } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
  });

export const findingQuery = (id: string) =>
  queryOptions({
    queryKey: keys.finding(id),
    queryFn: () => unwrap(api.GET("/findings/{id}", { params: { path: { id } } })),
  });

export const runsQuery = () =>
  infiniteQueryOptions({
    queryKey: keys.runs,
    queryFn: ({ pageParam }) =>
      unwrap(api.GET("/runs", { params: { query: { cursor: pageParam, limit: PAGE_SIZE } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
  });

export const runQuery = (id: number) =>
  queryOptions({
    queryKey: keys.run(id),
    queryFn: () => unwrap(api.GET("/runs/{id}", { params: { path: { id } } })),
  });

export const diffQuery = (id: number, against?: number) =>
  queryOptions({
    queryKey: keys.diff(id, against),
    queryFn: () =>
      unwrap(api.GET("/runs/{id}/diff", { params: { path: { id }, query: against ? { against } : {} } })),
  });

export const jobsQuery = (q: { status?: JobStatus; target_id?: number }) =>
  infiniteQueryOptions({
    queryKey: keys.jobList(q),
    queryFn: ({ pageParam }) =>
      unwrap(api.GET("/jobs", { params: { query: { ...q, cursor: pageParam, limit: PAGE_SIZE } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
  });

/** Queued + running jobs, for the top bar. Polls while the tab is visible. */
export const activeJobsQuery = () =>
  queryOptions({
    queryKey: keys.activeJobs,
    queryFn: async () => {
      const [running, queued] = await Promise.all(
        ACTIVE_JOB_STATUSES.map((status) =>
          unwrap(api.GET("/jobs", { params: { query: { status, limit: 100 } } })),
        ),
      );
      return [...(running?.items ?? []), ...(queued?.items ?? [])];
    },
    refetchInterval: 5_000,
  });

export const jobQuery = (id: number) =>
  queryOptions({
    queryKey: keys.job(id),
    queryFn: () => unwrap(api.GET("/jobs/{id}", { params: { path: { id } } })),
  });

export const sourcesQuery = () =>
  queryOptions({ queryKey: keys.sources, queryFn: () => unwrap(api.GET("/sources")) });

export const notifiersQuery = () =>
  queryOptions({ queryKey: keys.notifiers, queryFn: () => unwrap(api.GET("/notifiers")) });

export const auditQuery = () =>
  infiniteQueryOptions({
    queryKey: keys.audit,
    queryFn: ({ pageParam }) =>
      unwrap(api.GET("/audit", { params: { query: { cursor: pageParam, limit: PAGE_SIZE } } })),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: nextCursor,
  });

// ---- mutations -------------------------------------------------------------

export function useCancelJob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => unwrap(api.POST("/jobs/{id}/cancel", { params: { path: { id } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.jobs }),
  });
}

export function usePreviewTarget() {
  return useMutation({
    mutationFn: (body: TargetInput) => unwrap(api.POST("/targets/preview", { body })),
  });
}

export function useSaveTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id?: number; body: TargetInput }) =>
      id === undefined
        ? unwrap(api.POST("/targets", { body }))
        : unwrap(api.PATCH("/targets/{id}", { params: { path: { id } }, body })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.targets });
      void qc.invalidateQueries({ queryKey: keys.authProfiles });
    },
  });
}

export function useDeleteTarget() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => unwrap(api.DELETE("/targets/{id}", { params: { path: { id } } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.targets });
      void qc.invalidateQueries({ queryKey: keys.authProfiles });
    },
  });
}

export function useSaveAuthProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, body }: { name?: string; body: AuthProfileInput }) =>
      name === undefined
        ? unwrap(api.POST("/auth-profiles", { body }))
        : unwrap(api.PATCH("/auth-profiles/{name}", { params: { path: { name } }, body })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.authProfiles }),
  });
}

export function useDeleteAuthProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      unwrap(api.DELETE("/auth-profiles/{name}", { params: { path: { name } } })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: keys.authProfiles }),
  });
}

export function useTestAuthProfile() {
  return useMutation({
    mutationFn: (name: string) =>
      unwrap(api.POST("/auth-profiles/{name}/test", { params: { path: { name } } })),
  });
}

export function useSuppressFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: SuppressInput }) =>
      unwrap(api.PUT("/findings/{id}/suppression", { params: { path: { id } }, body })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.findings });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
      void qc.invalidateQueries({ queryKey: keys.repos });
    },
  });
}

export function useUnsuppressFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      unwrap(api.DELETE("/findings/{id}/suppression", { params: { path: { id } } })),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: keys.findings });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
      void qc.invalidateQueries({ queryKey: keys.repos });
    },
  });
}

export function useTestNotifier() {
  return useMutation({
    mutationFn: (name: string) =>
      unwrap(api.POST("/notifiers/{name}/test", { params: { path: { name } } })),
  });
}
