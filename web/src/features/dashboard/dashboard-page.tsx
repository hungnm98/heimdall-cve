import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { AlertOctagon, AlertTriangle, FolderGit2, Play, ShieldAlert, Skull } from "lucide-react";
import * as React from "react";
import { dashboardQuery } from "@/api/queries";
import type { Severity } from "@/api/types";
import { HealthBadge, RunStatusBadge, SupportBadge } from "@/components/badges";
import { EmptyState, ErrorState, PageHeader, RelativeTime } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/misc";
import { FindingsTable } from "@/features/findings/findings-table";
import { JobsTable } from "@/features/jobs/jobs-table";
import { useScanAll } from "@/features/jobs/use-scan";
import { countOf } from "@/lib/severity";
import { cn } from "@/lib/utils";

// Recharts is the largest dependency: load it only with the chart.
const TrendChart = React.lazy(() => import("./trend-chart").then((m) => ({ default: m.TrendChart })));

function StatCard({
  label,
  value,
  icon: Icon,
  tone,
  to,
}: {
  label: string;
  value: number;
  icon: typeof AlertOctagon;
  tone: string;
  to: React.ReactNode;
}) {
  return (
    <Card className="relative">
      <CardContent className="flex items-center gap-3 p-4">
        <span className={cn("rounded-md p-2", tone)}>
          <Icon aria-hidden className="size-5" />
        </span>
        <div>
          <p className="text-2xl font-semibold tabular-nums">{value.toLocaleString()}</p>
          <p className="text-sm text-muted-foreground">{to}</p>
        </div>
        <span className="sr-only">{label}</span>
      </CardContent>
    </Card>
  );
}

function SevLink({ sev, label, kev }: { sev?: Severity; label: string; kev?: boolean }) {
  return (
    <Link
      to="/findings"
      search={{ status: "open", ...(sev ? { min_severity: sev } : {}), ...(kev ? { kev: true } : {}) }}
      className="after:absolute after:inset-0 hover:underline"
    >
      {label}
    </Link>
  );
}

export function DashboardPage() {
  const q = useQuery({ ...dashboardQuery(), refetchInterval: (query) => (query.state.data?.active_jobs.length ? 5000 : false) });
  const scanAll = useScanAll();

  const header = (
    <PageHeader
      title="Dashboard"
      description="Open risk across all scanned repositories."
      actions={
        <Button onClick={() => scanAll.mutate()} disabled={scanAll.isPending}>
          <Play aria-hidden /> Scan all targets
        </Button>
      }
    />
  );

  if (q.isPending)
    return (
      <>
        {header}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5" aria-busy="true" aria-label="Loading dashboard">
          {Array.from({ length: 5 }, (_, i) => (
            <Skeleton key={i} className="h-20" />
          ))}
        </div>
        <Skeleton className="mt-4 h-72" />
      </>
    );
  if (q.isError)
    return (
      <>
        {header}
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      </>
    );
  const d = q.data;

  if (d.repos === 0 && d.trend.length === 0)
    return (
      <>
        {header}
        <EmptyState
          title="Nothing scanned yet"
          description="Add a target (an organization, user or repository) and run the first scan."
          action={
            <Button asChild>
              <Link to="/targets/new">Add a target</Link>
            </Button>
          }
        />
      </>
    );

  return (
    <>
      {header}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard
          label="Open critical findings"
          value={countOf(d.open_by_severity, "CRITICAL")}
          icon={AlertOctagon}
          tone="bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200"
          to={<SevLink sev="CRITICAL" label="Critical" />}
        />
        <StatCard
          label="Open high findings"
          value={countOf(d.open_by_severity, "HIGH")}
          icon={AlertTriangle}
          tone="bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200"
          to={<SevLink sev="HIGH" label="High" />}
        />
        <StatCard
          label="Open known exploited"
          value={d.open_kev}
          icon={ShieldAlert}
          tone="bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200"
          to={<SevLink kev label="Known exploited (KEV)" />}
        />
        <StatCard
          label="Open malicious packages"
          value={d.open_malicious}
          icon={Skull}
          tone="bg-violet-100 text-violet-800 dark:bg-violet-950 dark:text-violet-200"
          to="Malicious packages"
        />
        <StatCard
          label="Repositories"
          value={d.repos}
          icon={FolderGit2}
          tone="bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-200"
          to={
            <Link to="/repos" className="after:absolute after:inset-0 hover:underline">
              Repositories
            </Link>
          }
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Open findings per run</CardTitle>
            {d.last_run ? (
              <span className="flex items-center gap-2 text-sm text-muted-foreground">
                Last run{" "}
                <Link to="/runs/$id" params={{ id: String(d.last_run.id) }} className="hover:underline">
                  #{d.last_run.id}
                </Link>
                <RunStatusBadge status={d.last_run.status} />
                <RelativeTime value={d.last_run.started_at} />
              </span>
            ) : null}
          </CardHeader>
          <CardContent>
            <React.Suspense fallback={<Skeleton className="h-64 w-full" />}>
              <TrendChart runs={d.trend} />
            </React.Suspense>
          </CardContent>
        </Card>
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Active jobs</CardTitle>
            </CardHeader>
            <CardContent>
              {d.active_jobs.length ? (
                <JobsTable jobs={d.active_jobs} compact />
              ) : (
                <p className="text-sm text-muted-foreground">No scans running.</p>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>Source health</CardTitle>
            </CardHeader>
            <CardContent>
              {d.unhealthy_sources.length ? (
                <ul className="flex flex-col gap-2 text-sm">
                  {d.unhealthy_sources.map((s) => (
                    <li key={s.name}>
                      <span className="mr-2 font-medium">{s.name}</span>
                      <HealthBadge healthy={false} />
                      {s.error ? <p className="mt-0.5 text-xs text-muted-foreground">{s.error}</p> : null}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">All sources healthy.</p>
              )}
              <Link to="/settings" search={{ tab: "sources" }} className="mt-2 inline-block text-sm text-primary hover:underline">
                All sources
              </Link>
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="mt-4 grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Top 10 by priority</CardTitle>
            <Link to="/findings" search={{ status: "open" }} className="text-sm text-primary hover:underline">
              All findings
            </Link>
          </CardHeader>
          <CardContent>
            {d.top_findings.length ? (
              <FindingsTable findings={d.top_findings} caption="Top findings by priority" />
            ) : (
              <p className="text-sm text-muted-foreground">No open findings.</p>
            )}
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>End-of-life runtimes</CardTitle>
          </CardHeader>
          <CardContent>
            {d.eol_runtimes.length ? (
              <ul className="flex flex-col divide-y text-sm">
                {d.eol_runtimes.map((r) => {
                  const [owner, name] = (r.repo ?? "").split("/");
                  return (
                    <li key={`${r.repo}|${r.name}|${r.origin}`} className="flex flex-wrap items-center justify-between gap-2 py-2">
                      <div className="min-w-0">
                        <div className="font-medium">
                          {r.name} {r.version}
                        </div>
                        {owner && name ? (
                          <Link to="/repos/$owner/$name" params={{ owner, name }} className="text-xs text-muted-foreground hover:underline">
                            {r.repo}
                          </Link>
                        ) : null}
                      </div>
                      <div className="text-right">
                        <SupportBadge status={r.status} />
                        {r.eol_date ? <div className="text-xs text-muted-foreground">EOL {r.eol_date}</div> : null}
                      </div>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">No runtime is end-of-life or close to it.</p>
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
