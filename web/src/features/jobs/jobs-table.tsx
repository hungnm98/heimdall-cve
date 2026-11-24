import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { targetsQuery } from "@/api/queries";
import type { Job, Target } from "@/api/types";
import { JobStatusBadge } from "@/components/badges";
import { RelativeTime } from "@/components/common";
import { SortableTH, SortedTH, useClientSort } from "@/components/ui/sortable-header";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";
import { formatDuration } from "@/lib/time";

/** Human label of a job's scope; the Job schema only carries ids. */
export function jobScope(job: Job, targets: Target[] | undefined): string {
  const target = job.target_id != null ? targets?.find((t) => t.id === job.target_id) : undefined;
  const t = job.target_id != null ? (target?.label ?? `target #${job.target_id}`) : null;
  const branch = job.branch ? `@${job.branch}` : "";
  if (job.repo) return `${job.repo}${branch}${t && !job.repo.includes("://") && !job.repo.startsWith("git@") ? ` (${t})` : ""}`;
  return t ? `${t}${branch}` : "All enabled targets";
}

export function useJobScope() {
  const targets = useQuery(targetsQuery());
  return (job: Job) => jobScope(job, targets.data?.items);
}

const JOB_SORT = {
  id: (j: Job) => j.id,
  status: (j: Job) => j.status,
  created: (j: Job) => Date.parse(j.created_at),
};

/**
 * Jobs, newest first. `sortable` lets the user sort a complete in-memory list
 * (e.g. the dashboard's active jobs); a paginated list keeps the server order.
 */
export function JobsTable({ jobs, compact = false, sortable = false }: { jobs: Job[]; compact?: boolean; sortable?: boolean }) {
  const scope = useJobScope();
  const { sorted, sort, setSort } = useClientSort(jobs, JOB_SORT);
  return (
    <Table>
      <caption className="sr-only">Jobs</caption>
      <THead>
        <tr>
          {sortable ? (
            <SortableTH sortKey="id" first="desc" sort={sort} onSort={setSort}>
              Job
            </SortableTH>
          ) : (
            <TH>Job</TH>
          )}
          <TH>Scope</TH>
          {sortable ? (
            <SortableTH sortKey="status" sort={sort} onSort={setSort}>
              Status
            </SortableTH>
          ) : (
            <TH>Status</TH>
          )}
          {compact ? null : <TH className="hidden md:table-cell">Trigger</TH>}
          {sortable ? (
            <SortableTH sortKey="created" first="desc" sort={sort} onSort={setSort}>
              Created
            </SortableTH>
          ) : (
            <SortedTH order="desc" title="Newest first">
              Created
            </SortedTH>
          )}
          {compact ? null : <TH className="hidden sm:table-cell">Duration</TH>}
          {compact ? null : <TH className="hidden lg:table-cell">Requested by</TH>}
        </tr>
      </THead>
      <TBody>
        {(sortable ? sorted : jobs).map((j) => (
          <TR key={j.id}>
            <TD>
              <Link to="/jobs/$id" params={{ id: String(j.id) }} className="font-medium hover:underline">
                #{j.id}
              </Link>
            </TD>
            <TD className="max-w-xs">
              <span className="line-clamp-2 break-all">{scope(j)}</span>
              {j.error ? <span className="line-clamp-1 text-xs text-destructive">{j.error}</span> : null}
            </TD>
            <TD>
              <JobStatusBadge status={j.status} />
            </TD>
            {compact ? null : <TD className="hidden md:table-cell">{j.trigger}</TD>}
            <TD>
              <RelativeTime value={j.created_at} />
            </TD>
            {compact ? null : (
              <TD className="hidden whitespace-nowrap sm:table-cell">{j.started_at ? formatDuration(j.started_at, j.finished_at) : "—"}</TD>
            )}
            {compact ? null : <TD className="hidden text-muted-foreground lg:table-cell">{j.requested_by ?? "—"}</TD>}
          </TR>
        ))}
      </TBody>
    </Table>
  );
}
