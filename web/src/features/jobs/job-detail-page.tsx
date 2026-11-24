import { useQuery, useQueryClient } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { ChevronLeft, CircleStop, RotateCw, Wifi, WifiOff } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { errorMessage } from "@/api/problem";
import { jobQuery, keys, useCancelJob } from "@/api/queries";
import type { Job, JobEvent, JobRequest } from "@/api/types";
import { JobStatusBadge } from "@/components/badges";
import { ErrorState, KV, PageHeader, RelativeTime } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/misc";
import { formatDuration } from "@/lib/time";
import { cn } from "@/lib/utils";
import { useJobScope } from "./jobs-table";
import { type StreamState, useJobEvents } from "./use-job-events";
import { useScan } from "./use-scan";

const route = getRouteApi("/jobs/$id");

const isActive = (j: Job) => j.status === "queued" || j.status === "running";

const LEVEL_CLASS: Record<JobEvent["level"], string> = {
  info: "text-muted-foreground",
  warn: "text-amber-700 dark:text-amber-300",
  error: "text-red-700 dark:text-red-300",
};

function StreamBadge({ state, onReconnect }: { state: StreamState; onReconnect: () => void }) {
  switch (state) {
    case "open":
      return (
        <Badge variant="success">
          <Wifi aria-hidden /> live
        </Badge>
      );
    case "connecting":
      return <Badge variant="secondary">connecting…</Badge>;
    case "reconnecting":
      return (
        <Badge variant="warning">
          <WifiOff aria-hidden /> reconnecting…
        </Badge>
      );
    case "done":
      return <Badge variant="outline">finished</Badge>;
    case "error":
      return (
        <span className="inline-flex items-center gap-2">
          <Badge variant="danger">
            <WifiOff aria-hidden /> disconnected
          </Badge>
          <Button size="sm" variant="outline" onClick={onReconnect}>
            Reconnect
          </Button>
        </span>
      );
  }
}

function LiveLog({ job }: { job: Job }) {
  const qc = useQueryClient();
  const onDone = React.useCallback(
    (final: Job) => {
      qc.setQueryData(keys.job(final.id), final);
      void qc.invalidateQueries({ queryKey: keys.jobs });
      void qc.invalidateQueries({ queryKey: keys.runs });
      void qc.invalidateQueries({ queryKey: keys.dashboard });
      void qc.invalidateQueries({ queryKey: keys.repos });
    },
    [qc],
  );
  const { events, state, reconnect } = useJobEvents(job.id, onDone);
  const [follow, setFollow] = React.useState(true);
  const boxRef = React.useRef<HTMLDivElement>(null);

  React.useLayoutEffect(() => {
    const el = boxRef.current;
    if (follow && el) el.scrollTop = el.scrollHeight;
  }, [events, follow]);

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
        <CardTitle>Log</CardTitle>
        <div className="flex flex-wrap items-center gap-3">
          <StreamBadge state={state} onReconnect={reconnect} />
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={follow} onChange={(e) => setFollow(e.target.checked)} /> Auto-scroll
          </label>
        </div>
      </CardHeader>
      <CardContent>
        <div
          ref={boxRef}
          role="log"
          aria-label={`Log of job ${job.id}`}
          tabIndex={0}
          onScroll={(e) => {
            const el = e.currentTarget;
            const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
            if (atBottom !== follow) setFollow(atBottom);
          }}
          className="max-h-[60vh] min-h-48 overflow-auto rounded-md border bg-muted/40 p-3 font-mono text-xs leading-relaxed"
        >
          {events.length === 0 ? (
            <p className="text-muted-foreground">{isActive(job) ? "Waiting for events…" : "No events recorded."}</p>
          ) : (
            <ol>
              {events.map((ev) => (
                <li key={ev.id} data-level={ev.level} className="flex gap-2 whitespace-pre-wrap break-words">
                  <time dateTime={ev.at} className="shrink-0 text-muted-foreground">
                    {new Date(ev.at).toLocaleTimeString()}
                  </time>
                  <span className={cn("w-10 shrink-0 font-semibold uppercase", LEVEL_CLASS[ev.level])}>{ev.level}</span>
                  <span className="min-w-0">
                    {ev.repo ? <span className="text-sky-700 dark:text-sky-300">[{ev.repo}] </span> : null}
                    {ev.message}
                  </span>
                </li>
              ))}
            </ol>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

function rerunRequest(job: Job): JobRequest {
  const isUrl = !!job.repo && (job.repo.includes("://") || job.repo.startsWith("git@"));
  if (isUrl) return { repo_url: job.repo, auth_profile: job.auth_profile, branch: job.branch || undefined };
  return {
    ...(job.target_id != null ? { target_id: job.target_id } : {}),
    ...(job.repo ? { repo: job.repo } : {}),
    ...(job.branch ? { branch: job.branch } : {}),
  };
}

export function JobDetailPage() {
  const { id: idParam } = route.useParams();
  const id = Number(idParam);
  const q = useQuery({
    ...jobQuery(id),
    refetchInterval: (query) => (query.state.data && isActive(query.state.data) ? 5000 : false),
  });
  const cancel = useCancelJob();
  const scan = useScan();
  const scope = useJobScope();
  const [confirm, setConfirm] = React.useState(false);

  const back = (
    <Link to="/scans" search={{ tab: "jobs" }} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
      <ChevronLeft aria-hidden className="size-4" /> Jobs
    </Link>
  );
  if (q.isPending) return <Skeleton className="h-64 w-full" />;
  if (q.isError)
    return (
      <>
        {back}
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      </>
    );
  const job = q.data;

  return (
    <>
      {back}
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2">
            Job #{job.id} <JobStatusBadge status={job.status} />
          </span>
        }
        description={scope(job)}
        actions={
          isActive(job) ? (
            <Button variant="destructive" onClick={() => setConfirm(true)}>
              <CircleStop aria-hidden /> Cancel job
            </Button>
          ) : (
            <Button variant="outline" onClick={() => void scan.mutate(rerunRequest(job), "Re-run")} disabled={scan.isPending}>
              <RotateCw aria-hidden /> Run again
            </Button>
          )
        }
      />
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="min-w-0 lg:col-span-2">
          <LiveLog job={job} />
        </div>
        <Card>
          <CardHeader>
            <CardTitle>Details</CardTitle>
          </CardHeader>
          <CardContent>
            <KV
              items={[
                ["Trigger", job.trigger],
                ["Requested by", job.requested_by ?? "—"],
                ["Created", <RelativeTime key="c" value={job.created_at} />],
                ["Started", <RelativeTime key="s" value={job.started_at} fallback="not yet" />],
                ["Finished", <RelativeTime key="f" value={job.finished_at} fallback="—" />],
                ["Duration", job.started_at ? formatDuration(job.started_at, job.finished_at) : "—"],
                ["Attempts", String(job.attempts)],
                ...(job.branch ? ([["Branch", job.branch]] as [string, React.ReactNode][]) : []),
                ...(job.auth_profile ? ([["Auth profile", job.auth_profile]] as [string, React.ReactNode][]) : []),
                [
                  "Run",
                  job.run_id != null ? (
                    <Link key="r" to="/runs/$id" params={{ id: String(job.run_id) }} className="hover:underline">
                      #{job.run_id}
                    </Link>
                  ) : (
                    "—"
                  ),
                ],
                ...(job.error ? ([["Error", <span key="e" className="text-destructive">{job.error}</span>]] as [string, React.ReactNode][]) : []),
              ]}
            />
          </CardContent>
        </Card>
      </div>
      <ConfirmDialog
        open={confirm}
        onOpenChange={setConfirm}
        title={`Cancel job #${job.id}?`}
        description="The scan stops as soon as the worker notices. Results of repositories already scanned are kept."
        confirmLabel="Cancel job"
        destructive
        pending={cancel.isPending}
        onConfirm={() =>
          cancel.mutate(job.id, {
            onSuccess: () => {
              toast.success(`Cancel requested for job #${job.id}`);
              setConfirm(false);
              void q.refetch();
            },
            onError: (err) => {
              toast.error(errorMessage(err));
              setConfirm(false);
            },
          })
        }
      />
    </>
  );
}
