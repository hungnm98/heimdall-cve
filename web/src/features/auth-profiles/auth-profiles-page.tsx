import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { Pencil, PlugZap, Plus, Trash2 } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { errorMessage } from "@/api/problem";
import { authProfilesQuery, metaQuery, targetsQuery, useDeleteAuthProfile, useTestAuthProfile } from "@/api/queries";
import type { AuthProfile } from "@/api/types";
import { OriginBadge } from "@/components/badges";
import { EmptyState, ErrorState, PageHeader, RelativeTime, TableSkeleton } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ConfirmDialog, Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";
import { AuthProfileForm } from "./auth-profile-form";

type Editing = { mode: "create" } | { mode: "edit"; profile: AuthProfile } | null;

export function AuthProfilesPage() {
  const q = useQuery(authProfilesQuery());
  const meta = useQuery(metaQuery());
  const targets = useQuery(targetsQuery());
  const test = useTestAuthProfile();
  const del = useDeleteAuthProfile();
  const [editing, setEditing] = React.useState<Editing>(null);
  const [deleting, setDeleting] = React.useState<AuthProfile | null>(null);
  const [testing, setTesting] = React.useState<string | null>(null);
  const secretsEnabled = meta.data?.secrets_enabled ?? false;

  const labelOf = (id: number) => targets.data?.items.find((t) => t.id === id)?.label ?? `#${id}`;
  const profiles = q.data?.items ?? [];

  const runTest = (name: string) => {
    setTesting(name);
    test.mutate(name, {
      onSuccess: (r) => (r.ok ? toast.success(`${name}: ${r.message}`) : toast.error(`${name}: ${r.message}`)),
      onError: (err) => toast.error(errorMessage(err)),
      onSettled: () => setTesting(null),
    });
  };

  return (
    <>
      <PageHeader
        title="Auth profiles"
        description="Credentials used to list repositories and read code. Secrets are write-only and stored encrypted."
        actions={
          <Button onClick={() => setEditing({ mode: "create" })}>
            <Plus aria-hidden /> Add profile
          </Button>
        }
      />
      {meta.data && !secretsEnabled ? (
        <p role="status" className="mb-4 rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100">
          Secret entry is disabled: the server has no master key configured (<code>HEIMDALL_MASTER_KEY</code>). Profiles can still reference secrets from the environment via the config file.
        </p>
      ) : null}
      {q.isPending ? (
        <TableSkeleton />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : profiles.length === 0 ? (
        <EmptyState
          title="No auth profiles"
          description="Add a token, GitHub App or SSH key so targets can be listed and scanned."
          action={
            <Button onClick={() => setEditing({ mode: "create" })}>
              <Plus aria-hidden /> Add profile
            </Button>
          }
        />
      ) : (
        <Table>
          <caption className="sr-only">Auth profiles</caption>
          <THead>
            <tr>
              <TH>Name</TH>
              <TH>Type</TH>
              <TH>Secret</TH>
              <TH className="hidden md:table-cell">Used by</TH>
              <TH className="hidden lg:table-cell">Updated</TH>
              <TH className="text-right">Actions</TH>
            </tr>
          </THead>
          <TBody>
            {profiles.map((p) => {
              const ro = p.origin === "config";
              const used = p.used_by ?? [];
              return (
                <TR key={p.name}>
                  <TD>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-medium">{p.name}</span>
                      <OriginBadge origin={p.origin} />
                    </div>
                  </TD>
                  <TD>
                    <Badge variant="secondary">{p.type}</Badge>
                  </TD>
                  <TD>
                    {p.has_secret ? (
                      <code className="text-xs" title="Fingerprint: not reversible">
                        {p.secret_fingerprint ?? "set"}
                      </code>
                    ) : (
                      <Badge variant="warning">no secret</Badge>
                    )}
                  </TD>
                  <TD className="hidden md:table-cell">
                    {used.length ? (
                      <ul className="flex flex-wrap gap-1">
                        {used.map((id) => (
                          <li key={id}>
                            <Link to="/targets/$id" params={{ id: String(id) }} className="text-xs hover:underline">
                              {labelOf(id)}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <span className="text-xs text-muted-foreground">unused</span>
                    )}
                  </TD>
                  <TD className="hidden lg:table-cell">
                    <RelativeTime value={p.updated_at} />
                  </TD>
                  <TD>
                    <div className="flex justify-end gap-1">
                      <Button size="sm" variant="outline" onClick={() => runTest(p.name)} disabled={testing === p.name} aria-label={`Test connection of ${p.name}`}>
                        <PlugZap aria-hidden /> <span className="hidden lg:inline">{testing === p.name ? "Testing…" : "Test"}</span>
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={ro}
                        onClick={() => setEditing({ mode: "edit", profile: p })}
                        aria-label={`Edit ${p.name}`}
                        title={ro ? "Read-only: defined in the config file" : undefined}
                      >
                        <Pencil aria-hidden />
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={ro}
                        onClick={() => setDeleting(p)}
                        aria-label={`Delete ${p.name}`}
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

      <Dialog open={editing !== null} onOpenChange={(o) => !o && setEditing(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing?.mode === "edit" ? `Edit ${editing.profile.name}` : "Add auth profile"}</DialogTitle>
            <DialogDescription>
              {editing?.mode === "edit" ? "Change the options or replace the secret." : "Create a credential that targets can use."}
            </DialogDescription>
          </DialogHeader>
          {editing ? (
            <AuthProfileForm
              key={editing.mode === "edit" ? editing.profile.name : "new"}
              profile={editing.mode === "edit" ? editing.profile : undefined}
              secretsEnabled={secretsEnabled}
              onDone={() => setEditing(null)}
              onCancel={() => setEditing(null)}
            />
          ) : null}
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete ${deleting?.name ?? "profile"}?`}
        description={
          deleting?.used_by?.length
            ? `It is still used by ${deleting.used_by.map(labelOf).join(", ")}; the server will refuse until those targets use another profile.`
            : "The encrypted secret is deleted as well. This cannot be undone."
        }
        confirmLabel="Delete"
        destructive
        pending={del.isPending}
        onConfirm={() =>
          deleting &&
          del.mutate(deleting.name, {
            onSuccess: () => {
              toast.success(`Deleted ${deleting.name}`);
              setDeleting(null);
            },
            onError: (err) => {
              toast.error(errorMessage(err));
              setDeleting(null);
            },
          })
        }
      />
    </>
  );
}
