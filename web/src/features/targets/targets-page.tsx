import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Eye, Pencil, Play, Plus, Trash2 } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { errorMessage } from "@/api/problem";
import { targetsQuery, useDeleteTarget, useSaveTarget } from "@/api/queries";
import type { Target } from "@/api/types";
import { OriginBadge } from "@/components/badges";
import { EmptyState, ErrorState, PageHeader, RelativeTime, TableSkeleton } from "@/components/common";
import { Button } from "@/components/ui/button";
import { ConfirmDialog } from "@/components/ui/dialog";
import { Switch } from "@/components/ui/misc";
import { SortableTH, useClientSort } from "@/components/ui/sortable-header";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";
import { useScan } from "@/features/jobs/use-scan";
import { describeSchedule } from "@/lib/schedule";
import { targetInputOf } from "./target-model";

const TARGET_SORT = {
  label: (t: Target) => t.label,
  auth: (t: Target) => t.auth,
  next_run: (t: Target) => (t.enabled && t.next_run_at ? Date.parse(t.next_run_at) : null),
  enabled: (t: Target) => ((t.enabled ?? true) ? 1 : 0),
};

export function TargetsPage() {
  const q = useQuery(targetsQuery());
  const save = useSaveTarget();
  const del = useDeleteTarget();
  const scan = useScan();
  const [deleting, setDeleting] = React.useState<Target | null>(null);

  const toggle = (t: Target, enabled: boolean) =>
    save.mutate(
      { id: t.id, body: { ...targetInputOf(t), enabled } },
      {
        onSuccess: () => toast.success(`${t.label} ${enabled ? "enabled" : "disabled"}`),
        onError: (err) => toast.error(errorMessage(err)),
      },
    );

  const targets = q.data?.items ?? [];
  const { sorted, sort, setSort } = useClientSort(targets, TARGET_SORT);
  const hasConfig = targets.some((t) => t.origin === "config");

  return (
    <>
      <PageHeader
        title="Targets"
        description="Organizations, users and repositories that Heimdall scans."
        actions={
          <Button asChild>
            <Link to="/targets/new">
              <Plus aria-hidden /> Add target
            </Link>
          </Button>
        }
      />
      {hasConfig ? (
        <p className="mb-4 text-sm text-muted-foreground">
          Targets marked <OriginBadge origin="config" /> come from the config file. They are read-only here; edit the config file to change them.
        </p>
      ) : null}
      {q.isPending ? (
        <TableSkeleton />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : targets.length === 0 ? (
        <EmptyState
          title="No targets yet"
          description="Add an organization, a user or a repository URL to start scanning."
          action={
            <Button asChild>
              <Link to="/targets/new">
                <Plus aria-hidden /> Add target
              </Link>
            </Button>
          }
        />
      ) : (
        <Table>
          <caption className="sr-only">Targets</caption>
          <THead>
            <tr>
              <SortableTH sortKey="label" sort={sort} onSort={setSort}>
                Target
              </SortableTH>
              <SortableTH sortKey="auth" sort={sort} onSort={setSort} className="hidden md:table-cell">
                Auth
              </SortableTH>
              <SortableTH sortKey="next_run" sort={sort} onSort={setSort} className="hidden sm:table-cell">
                Schedule
              </SortableTH>
              <SortableTH sortKey="enabled" first="desc" sort={sort} onSort={setSort}>
                Enabled
              </SortableTH>
              <TH className="text-right">Actions</TH>
            </tr>
          </THead>
          <TBody>
            {sorted.map((t) => {
              const ro = t.origin === "config";
              return (
                <TR key={t.id}>
                  <TD>
                    <div className="flex flex-wrap items-center gap-2">
                      <Link to="/targets/$id" params={{ id: String(t.id) }} className="font-medium hover:underline">
                        {t.label}
                      </Link>
                      <OriginBadge origin={t.origin} />
                    </div>
                    {t.branch ? <div className="text-xs text-muted-foreground">branch {t.branch}</div> : null}
                  </TD>
                  <TD className="hidden md:table-cell">
                    <code className="text-xs">{t.auth}</code>
                    {t.list_auth ? <div className="text-xs text-muted-foreground">list: {t.list_auth}</div> : null}
                  </TD>
                  <TD className="hidden sm:table-cell">
                    <div>{describeSchedule(t.schedule)}</div>
                    {t.next_run_at && t.enabled ? (
                      <div className="text-xs text-muted-foreground">
                        next <RelativeTime value={t.next_run_at} />
                      </div>
                    ) : null}
                  </TD>
                  <TD>
                    <Switch
                      checked={t.enabled ?? true}
                      disabled={ro || save.isPending}
                      onCheckedChange={(v) => toggle(t, v)}
                      aria-label={`${t.enabled ? "Disable" : "Enable"} ${t.label}`}
                      title={ro ? "Read-only: defined in the config file" : undefined}
                    />
                  </TD>
                  <TD>
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="outline" onClick={() => void scan.mutate({ target_id: t.id }, `Scan of ${t.label}`)} aria-label={`Scan ${t.label} now`}>
                        <Play aria-hidden /> <span className="hidden lg:inline">Scan now</span>
                      </Button>
                      <Button size="sm" variant="ghost" asChild aria-label={ro ? `View ${t.label}` : `Edit ${t.label}`}>
                        <Link to="/targets/$id" params={{ id: String(t.id) }}>
                          {ro ? <Eye aria-hidden /> : <Pencil aria-hidden />}
                        </Link>
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={ro}
                        onClick={() => setDeleting(t)}
                        aria-label={`Delete ${t.label}`}
                        title={ro ? "Read-only: defined in the config file" : undefined}
                      >
                        <Trash2 aria-hidden />
                      </Button>
                    </div>
                  </TD>
                </TR>
              );
            })}
          </TBody>
        </Table>
      )}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete ${deleting?.label ?? "target"}?`}
        description="The target stops being scanned. Past runs and findings are kept."
        confirmLabel="Delete"
        destructive
        pending={del.isPending}
        onConfirm={() =>
          deleting &&
          del.mutate(deleting.id, {
            onSuccess: () => {
              toast.success(`Deleted ${deleting.label}`);
              setDeleting(null);
            },
            onError: (err) => toast.error(errorMessage(err)),
          })
        }
      />
    </>
  );
}
