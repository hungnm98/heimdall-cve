import { useInfiniteQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { jobsQuery, runsQuery } from "@/api/queries";
import type { JobStatus, ScanRun } from "@/api/types";
import { RunStatusBadge, SeverityCounts } from "@/components/badges";
import { EmptyState, ErrorState, LoadMore, PageHeader, RelativeTime, TableSkeleton } from "@/components/common";
import { NativeSelect } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";
import { JobsTable } from "@/features/jobs/jobs-table";
import { formatDuration } from "@/lib/time";

const route = getRouteApi("/scans");

function RunsTable({ runs }: { runs: ScanRun[] }) {
  return (
    <Table>
      <caption className="sr-only">Scan runs</caption>
      <THead>
        <tr>
          <TH>Run</TH>
          <TH>Started</TH>
          <TH>Status</TH>
          <TH className="hidden sm:table-cell">Duration</TH>
          <TH className="hidden md:table-cell">Repos</TH>
          <TH>Open</TH>
          <TH className="hidden md:table-cell">New / fixed</TH>
        </tr>
      </THead>
      <TBody>
        {runs.map((r) => (
          <TR key={r.id}>
            <TD>
              <Link to="/runs/$id" params={{ id: String(r.id) }} className="font-medium hover:underline">
                #{r.id}
              </Link>
            </TD>
            <TD>
              <RelativeTime value={r.started_at} />
            </TD>
            <TD>
              <RunStatusBadge status={r.status} />
            </TD>
            <TD className="hidden whitespace-nowrap sm:table-cell">{formatDuration(r.started_at, r.finished_at)}</TD>
            <TD className="hidden md:table-cell">
              {r.repos_scanned?.length ?? 0}
              {r.repos_failed?.length ? <span className="text-destructive"> ({r.repos_failed.length} failed)</span> : null}
            </TD>
            <TD>{r.stats ? <SeverityCounts counts={r.stats.open_by_severity} /> : <span className="text-xs text-muted-foreground">—</span>}</TD>
            <TD className="hidden whitespace-nowrap md:table-cell">
              {r.stats ? (
                <>
                  <span className="text-orange-700 dark:text-orange-300">+{r.stats.new ?? 0}</span> /{" "}
                  <span className="text-emerald-700 dark:text-emerald-300">−{r.stats.fixed ?? 0}</span>
                </>
              ) : (
                "—"
              )}
            </TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

function RunsTab() {
  const q = useInfiniteQuery(runsQuery());
  const runs = q.data?.pages.flatMap((p) => p.items) ?? [];
  if (q.isPending) return <TableSkeleton />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  if (runs.length === 0) return <EmptyState title="No scans yet" description="Use “Scan all” in the top bar to run the first scan." />;
  return (
    <>
      <RunsTable runs={runs} />
      <LoadMore shown={runs.length} hasNextPage={q.hasNextPage} isFetchingNextPage={q.isFetchingNextPage} fetchNextPage={q.fetchNextPage} />
    </>
  );
}

const STATUSES: JobStatus[] = ["queued", "running", "succeeded", "failed", "canceled"];

function JobsTab({ status }: { status?: JobStatus }) {
  const navigate = route.useNavigate();
  const q = useInfiniteQuery({
    ...jobsQuery({ status }),
    // Keep the list live while anything is in flight.
    refetchInterval: (query) =>
      query.state.data?.pages.some((p) => p.items.some((j) => j.status === "queued" || j.status === "running")) ? 3000 : false,
  });
  const jobs = q.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <>
      <div className="mb-3 flex items-center gap-2">
        <label htmlFor="job-status" className="text-sm text-muted-foreground">
          Status
        </label>
        <NativeSelect
          id="job-status"
          className="w-auto"
          value={status ?? ""}
          onChange={(e) => void navigate({ search: (p) => ({ ...p, status: (e.target.value || undefined) as JobStatus | undefined }), replace: true })}
        >
          <option value="">All</option>
          {STATUSES.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </NativeSelect>
      </div>
      {q.isPending ? (
        <TableSkeleton />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : jobs.length === 0 ? (
        <EmptyState title={status ? `No ${status} jobs` : "No jobs yet"} description="Jobs appear when a scan is triggered manually, by schedule or via the API." />
      ) : (
        <>
          <JobsTable jobs={jobs} />
          <LoadMore shown={jobs.length} hasNextPage={q.hasNextPage} isFetchingNextPage={q.isFetchingNextPage} fetchNextPage={q.fetchNextPage} />
        </>
      )}
    </>
  );
}

export function ScansPage() {
  const { tab = "runs", status } = route.useSearch();
  const navigate = route.useNavigate();
  return (
    <>
      <PageHeader title="Scans & jobs" description="Scan history, and the jobs that produce it." />
      <Tabs value={tab} onValueChange={(v) => void navigate({ search: { tab: v as "runs" | "jobs" }, replace: true })}>
        <TabsList>
          <TabsTrigger value="runs">Runs</TabsTrigger>
          <TabsTrigger value="jobs">Jobs</TabsTrigger>
        </TabsList>
        <TabsContent value="runs">
          <RunsTab />
        </TabsContent>
        <TabsContent value="jobs">
          <JobsTab status={status} />
        </TabsContent>
      </Tabs>
    </>
  );
}
