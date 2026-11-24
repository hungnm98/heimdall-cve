import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { ChevronLeft } from "lucide-react";
import { diffQuery, runQuery, runsQuery } from "@/api/queries";
import type { Finding } from "@/api/types";
import { HealthBadge, RunStatusBadge, SeverityCounts } from "@/components/badges";
import { EmptyState, ErrorState, KV, PageHeader, RelativeTime, TableSkeleton } from "@/components/common";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { NativeSelect } from "@/components/ui/input";
import { Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";
import { FindingsTable } from "@/features/findings/findings-table";
import { formatDuration } from "@/lib/time";

const route = getRouteApi("/runs/$id");

function DiffList({ findings, empty }: { findings: Finding[]; empty: string }) {
  return findings.length ? <FindingsTable findings={findings} /> : <EmptyState title={empty} />;
}

function RunDiff({ id, against }: { id: number; against?: number }) {
  const navigate = route.useNavigate();
  const runs = useInfiniteQuery(runsQuery());
  const others = (runs.data?.pages.flatMap((p) => p.items) ?? []).filter((r) => r.id !== id);
  const q = useQuery(diffQuery(id, against));

  return (
    <Card>
      <CardHeader className="flex-row flex-wrap items-center justify-between gap-2">
        <CardTitle>Changes</CardTitle>
        <div className="flex items-center gap-2">
          <label htmlFor="diff-against" className="text-sm text-muted-foreground">
            Compared with
          </label>
          <NativeSelect
            id="diff-against"
            className="w-auto"
            value={against ?? ""}
            onChange={(e) => void navigate({ search: { against: e.target.value ? Number(e.target.value) : undefined }, replace: true })}
          >
            <option value="">Previous run</option>
            {others.map((r) => (
              <option key={r.id} value={r.id}>
                #{r.id} · {new Date(r.started_at).toLocaleDateString()}
              </option>
            ))}
          </NativeSelect>
        </div>
      </CardHeader>
      <CardContent>
        {q.isPending ? (
          <TableSkeleton rows={4} />
        ) : q.isError ? (
          <ErrorState error={q.error} onRetry={() => void q.refetch()} />
        ) : (
          <Tabs defaultValue="new">
            <p className="mb-2 text-sm text-muted-foreground">
              Run #{q.data.from_run} → #{q.data.to_run}
            </p>
            <TabsList>
              <TabsTrigger value="new">New ({q.data.new.length})</TabsTrigger>
              <TabsTrigger value="fixed">Fixed ({q.data.fixed.length})</TabsTrigger>
              <TabsTrigger value="open">Still open ({q.data.still_open.length})</TabsTrigger>
            </TabsList>
            <TabsContent value="new">
              <DiffList findings={q.data.new} empty="No new findings" />
            </TabsContent>
            <TabsContent value="fixed">
              <DiffList findings={q.data.fixed} empty="Nothing was fixed" />
            </TabsContent>
            <TabsContent value="open">
              <DiffList findings={q.data.still_open} empty="Nothing still open" />
            </TabsContent>
          </Tabs>
        )}
      </CardContent>
    </Card>
  );
}

export function RunDetailPage() {
  const { id: idParam } = route.useParams();
  const { against } = route.useSearch();
  const id = Number(idParam);
  const q = useQuery(runQuery(id));

  const back = (
    <Link to="/scans" search={{ tab: "runs" }} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
      <ChevronLeft aria-hidden className="size-4" /> Scans
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
  const r = q.data;
  return (
    <>
      {back}
      <PageHeader
        title={
          <span className="inline-flex items-center gap-2">
            Run #{r.id} <RunStatusBadge status={r.status} />
          </span>
        }
      />
      <div className="mb-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <KV
              items={[
                ["Started", <RelativeTime key="s" value={r.started_at} />],
                ["Duration", formatDuration(r.started_at, r.finished_at)],
                ["Targets", r.targets?.join(", ") || "—"],
                ["Repos scanned", String(r.repos_scanned?.length ?? 0)],
                ["Repos failed", r.repos_failed?.length ? <span key="f" className="text-destructive">{r.repos_failed.join(", ")}</span> : "0"],
                ["Open", r.stats ? <SeverityCounts key="o" counts={r.stats.open_by_severity} /> : "—"],
                ["New / fixed", r.stats ? `+${r.stats.new ?? 0} / −${r.stats.fixed ?? 0}` : "—"],
                ...(r.error ? ([["Error", <span key="e" className="text-destructive">{r.error}</span>]] as [string, React.ReactNode][]) : []),
              ]}
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Sources</CardTitle>
          </CardHeader>
          <CardContent>
            {r.sources?.length ? (
              <Table>
                <THead>
                  <tr>
                    <TH>Source</TH>
                    <TH>Health</TH>
                    <TH>Calls</TH>
                    <TH>Time</TH>
                  </tr>
                </THead>
                <TBody>
                  {r.sources.map((s) => (
                    <TR key={s.name}>
                      <TD>
                        {s.name}
                        {s.error ? <div className="text-xs text-destructive">{s.error}</div> : null}
                      </TD>
                      <TD>
                        <HealthBadge healthy={s.healthy} />
                      </TD>
                      <TD className="tabular-nums">{s.calls ?? "—"}</TD>
                      <TD className="tabular-nums">{s.duration_ms !== undefined ? `${(s.duration_ms / 1000).toFixed(1)}s` : "—"}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            ) : (
              <p className="text-sm text-muted-foreground">No source information.</p>
            )}
          </CardContent>
        </Card>
      </div>
      <RunDiff id={id} against={against} />
    </>
  );
}
