import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { getRouteApi } from "@tanstack/react-router";
import { Send } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { errorMessage } from "@/api/problem";
import { auditQuery, metaQuery, notifiersQuery, sourcesQuery, useTestNotifier } from "@/api/queries";
import type { NotifierStatus, SourceStatus } from "@/api/types";
import { HealthBadge } from "@/components/badges";
import { EmptyState, ErrorState, KV, LoadMore, PageHeader, RelativeTime, TableSkeleton } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { SortableTH, SortedTH, useClientSort } from "@/components/ui/sortable-header";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";

const route = getRouteApi("/settings");

const SOURCE_SORT = {
  name: (s: SourceStatus) => s.name,
  health: (s: SourceStatus) => (s.healthy ? 1 : 0),
  last: (s: SourceStatus) => (s.last_seen ? Date.parse(s.last_seen) : null),
};
const NOTIFIER_SORT = {
  name: (n: NotifierStatus) => n.name,
  type: (n: NotifierStatus) => n.type,
};
const NO_ROWS: never[] = [];

function Sources() {
  const q = useQuery(sourcesQuery());
  const { sorted, sort, setSort } = useClientSort(q.data?.items ?? NO_ROWS, SOURCE_SORT);
  if (q.isPending) return <TableSkeleton rows={5} cols={4} />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  if (q.data.items.length === 0) return <EmptyState title="No sources configured" />;
  return (
    <Table>
      <caption className="sr-only">Advisory sources</caption>
      <THead>
        <tr>
          <SortableTH sortKey="name" sort={sort} onSort={setSort}>
            Source
          </SortableTH>
          <TH>Provides</TH>
          <SortableTH sortKey="health" sort={sort} onSort={setSort}>
            Health
          </SortableTH>
          <SortableTH sortKey="last" first="desc" sort={sort} onSort={setSort}>
            Last refresh
          </SortableTH>
        </tr>
      </THead>
      <TBody>
        {sorted.map((s) => (
          <TR key={s.name}>
            <TD className="font-medium">
              {s.name}
              {s.error ? <div className="text-xs font-normal text-destructive">{s.error}</div> : null}
            </TD>
            <TD>
              <span className="flex flex-wrap gap-1">
                {s.kinds.map((k) => (
                  <Badge key={k} variant="outline">
                    {k}
                  </Badge>
                ))}
              </span>
            </TD>
            <TD>
              <HealthBadge healthy={s.healthy} />
            </TD>
            <TD>
              <RelativeTime value={s.last_seen} fallback="never" />
            </TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

function Notifiers() {
  const q = useQuery(notifiersQuery());
  const test = useTestNotifier();
  const [sending, setSending] = React.useState<string | null>(null);
  const { sorted, sort, setSort } = useClientSort(q.data?.items ?? NO_ROWS, NOTIFIER_SORT);
  if (q.isPending) return <TableSkeleton rows={2} cols={3} />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  if (q.data.items.length === 0)
    return <EmptyState title="No notifiers" description="Add a Slack or webhook notifier in the config file to get alerts about new findings." />;
  return (
    <Table>
      <caption className="sr-only">Notifiers</caption>
      <THead>
        <tr>
          <SortableTH sortKey="name" sort={sort} onSort={setSort}>
            Name
          </SortableTH>
          <SortableTH sortKey="type" sort={sort} onSort={setSort}>
            Type
          </SortableTH>
          <TH className="text-right">Actions</TH>
        </tr>
      </THead>
      <TBody>
        {sorted.map((n) => (
          <TR key={n.name}>
            <TD className="font-medium">{n.name}</TD>
            <TD>
              <Badge variant="secondary">{n.type}</Badge>
            </TD>
            <TD className="text-right">
              <Button
                size="sm"
                variant="outline"
                disabled={sending === n.name}
                onClick={() => {
                  setSending(n.name);
                  test.mutate(n.name, {
                    onSuccess: () => toast.success(`Test message sent to ${n.name}`),
                    onError: (err) => toast.error(`${n.name}: ${errorMessage(err)}`),
                    onSettled: () => setSending(null),
                  });
                }}
              >
                <Send aria-hidden /> {sending === n.name ? "Sending…" : "Send test"}
              </Button>
            </TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

function Audit() {
  const q = useInfiniteQuery(auditQuery());
  const entries = q.data?.pages.flatMap((p) => p.items) ?? [];
  if (q.isPending) return <TableSkeleton rows={8} cols={4} />;
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  if (entries.length === 0) return <EmptyState title="No audit entries yet" description="Every write through the UI, API or MCP is recorded here." />;
  return (
    <>
      <Table>
        <caption className="sr-only">Audit log</caption>
        <THead>
          <tr>
            <SortedTH order="desc" title="Newest first">
              When
            </SortedTH>
            <TH>Actor</TH>
            <TH>Action</TH>
            <TH className="hidden sm:table-cell">Object</TH>
            <TH className="hidden lg:table-cell">Details</TH>
          </tr>
        </THead>
        <TBody>
          {entries.map((a) => (
            <TR key={a.id}>
              <TD>
                <RelativeTime value={a.at} />
              </TD>
              <TD className="whitespace-nowrap">{a.actor}</TD>
              <TD>
                <code className="text-xs">{a.action}</code>
              </TD>
              <TD className="hidden whitespace-nowrap sm:table-cell">
                {a.object_type ? `${a.object_type} ${a.object_id ?? ""}` : "—"}
              </TD>
              <TD className="hidden max-w-sm lg:table-cell">
                {a.details && Object.keys(a.details).length ? (
                  <code className="line-clamp-2 break-all text-xs text-muted-foreground">{JSON.stringify(a.details)}</code>
                ) : (
                  "—"
                )}
              </TD>
            </TR>
          ))}
        </TBody>
      </Table>
      <LoadMore shown={entries.length} hasNextPage={q.hasNextPage} isFetchingNextPage={q.isFetchingNextPage} fetchNextPage={q.fetchNextPage} />
    </>
  );
}

function About() {
  const q = useQuery(metaQuery());
  if (!q.data) return null;
  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>Server</CardTitle>
      </CardHeader>
      <CardContent>
        <KV
          items={[
            ["Version", q.data.version],
            ["Jobs backend", q.data.jobs_backend],
            ["Secrets in UI", q.data.secrets_enabled ? "enabled" : "disabled (no master key)"],
            ["Providers", q.data.providers?.join(", ") || "—"],
          ]}
        />
      </CardContent>
    </Card>
  );
}

export function SettingsPage() {
  const { tab = "sources" } = route.useSearch();
  const navigate = route.useNavigate();
  return (
    <>
      <PageHeader title="Settings" description="Advisory sources, notifications and the audit trail." />
      <Tabs value={tab} onValueChange={(v) => void navigate({ search: { tab: v as typeof tab }, replace: true })}>
        <TabsList>
          <TabsTrigger value="sources">Sources</TabsTrigger>
          <TabsTrigger value="notifiers">Notifiers</TabsTrigger>
          <TabsTrigger value="audit">Audit log</TabsTrigger>
        </TabsList>
        <TabsContent value="sources">
          <Sources />
        </TabsContent>
        <TabsContent value="notifiers">
          <Notifiers />
        </TabsContent>
        <TabsContent value="audit">
          <Audit />
        </TabsContent>
      </Tabs>
      <About />
    </>
  );
}
