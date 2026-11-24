import { useQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { ChevronLeft, GitBranch, Play, RefreshCw } from "lucide-react";
import * as React from "react";
import { repoQuery, targetsQuery } from "@/api/queries";
import type { RepoDetail } from "@/api/types";
import { BumpBadge, SeverityBadge, SeverityCounts, SupportBadge } from "@/components/badges";
import { CopyButton, EmptyState, ErrorState, ExtLink, Field, RelativeTime } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Checkbox, Input, NativeSelect } from "@/components/ui/input";
import { Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/misc";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";
import { FindingsTable } from "@/features/findings/findings-table";
import { useScan } from "@/features/jobs/use-scan";
import { repoUrl } from "@/lib/utils";

const route = getRouteApi("/repos/$owner/$name");

function UpgradePlan({ plan }: { plan: RepoDetail["upgrade_plan"] }) {
  if (plan.length === 0)
    return <EmptyState title="Nothing to upgrade" description="No open dependency finding has a recommended version." />;
  return (
    <Table>
      <caption className="sr-only">Upgrade plan</caption>
      <THead>
        <tr>
          <TH>Severity</TH>
          <TH>Package</TH>
          <TH>Current → recommended</TH>
          <TH className="hidden md:table-cell">Advisories</TH>
          <TH>Command</TH>
        </tr>
      </THead>
      <TBody>
        {plan.map((u) => (
          <TR key={`${u.manifest}|${u.package.name}`}>
            <TD>
              <SeverityBadge severity={u.severity} />
            </TD>
            <TD>
              <div className="font-medium">{u.package.name}</div>
              <div className="text-xs text-muted-foreground">
                {u.manifest} · {u.direct ? "direct" : "transitive"}
              </div>
            </TD>
            <TD className="whitespace-nowrap">
              <code className="text-xs">{u.package.version}</code> → <code className="text-xs">{u.recommended || "—"}</code>{" "}
              <BumpBadge bump={u.bump} />
            </TD>
            <TD className="hidden text-xs md:table-cell">
              <span className="font-mono">{u.advisories.join(", ")}</span>
            </TD>
            <TD>{u.advice ? <CopyButton text={u.advice} label="Copy" ariaLabel={`Copy upgrade command for ${u.package.name}`} /> : <span className="text-muted-foreground">—</span>}</TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

function Runtimes({ runtimes }: { runtimes: RepoDetail["runtimes"] }) {
  if (runtimes.length === 0) return <EmptyState title="No runtimes detected" />;
  return (
    <Table>
      <caption className="sr-only">Runtimes</caption>
      <THead>
        <tr>
          <TH>Runtime</TH>
          <TH>Support</TH>
          <TH>End of life</TH>
          <TH className="hidden sm:table-cell">Declared in</TH>
          <TH>Latest</TH>
        </tr>
      </THead>
      <TBody>
        {runtimes.map((r) => (
          <TR key={`${r.name}|${r.origin}`}>
            <TD className="font-medium">
              {r.name} {r.version}
            </TD>
            <TD>
              <SupportBadge status={r.status} />
            </TD>
            <TD>{r.eol_date ?? "—"}</TD>
            <TD className="hidden sm:table-cell">
              <code className="text-xs">{r.origin}</code>
              {r.via ? <span className="text-xs text-muted-foreground"> ({r.via})</span> : null}
            </TD>
            <TD className="whitespace-nowrap text-xs">
              {r.latest_patch ?? "—"} / cycle {r.latest_cycle ?? "—"}
            </TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

function BranchScanDialog({
  open,
  onOpenChange,
  onScan,
  initial,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onScan: (branch: string, force: boolean) => void;
  initial: string;
}) {
  const [branch, setBranch] = React.useState(initial);
  const [force, setForce] = React.useState(false);
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            onScan(branch.trim(), force);
            onOpenChange(false);
          }}
        >
          <DialogHeader>
            <DialogTitle>Scan another branch</DialogTitle>
            <DialogDescription>Runs a one-off scan of this repository on the given branch. The target keeps its configured branch.</DialogDescription>
          </DialogHeader>
          <Field id="scan-branch" label="Branch" hint="Empty = the repository's default branch.">
            <Input value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="main" />
          </Field>
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={force} onChange={(e) => setForce(e.target.checked)} /> Rescan even if the HEAD commit is unchanged
          </label>
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit">Scan</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function RepoDetailPage() {
  const { owner, name } = route.useParams();
  const { branch = "" } = route.useSearch();
  const navigate = route.useNavigate();
  const q = useQuery(repoQuery(owner, name, branch));
  const targets = useQuery(targetsQuery());
  const scan = useScan();
  const [branchOpen, setBranchOpen] = React.useState(false);

  if (q.isPending)
    return (
      <div className="flex flex-col gap-4" aria-busy="true" aria-label="Loading repository">
        <Skeleton className="h-8 w-1/3" />
        <Skeleton className="h-64 w-full" />
      </div>
    );
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const { repo, findings, runtimes, upgrade_plan, branches } = q.data;
  const shown = branches.find((b) => (branch ? b.name === branch : b.primary));
  const target = targets.data?.items.find((t) => t.id === repo.target_id);
  const req = { target_id: repo.target_id, repo: repo.full_name };

  return (
    <>
      <Link to="/repos" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft aria-hidden className="size-4" /> Repositories
      </Link>
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <h1 className="break-words text-xl font-semibold tracking-tight sm:text-2xl">{repo.full_name}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
            <ExtLink href={repoUrl(repo.full_name, repo.html_url)}>Open on {repo.host ?? "GitHub"}</ExtLink>
            {branches.length > 1 ? (
              <label className="inline-flex items-center gap-1">
                <GitBranch aria-hidden className="size-3" />
                <span className="sr-only">Branch</span>
                <NativeSelect
                  className="h-7 w-auto py-0 text-sm"
                  value={branch}
                  onChange={(e) => void navigate({ search: e.target.value ? { branch: e.target.value } : {} })}
                >
                  {branches.map((b) => (
                    <option key={b.name} value={b.primary ? "" : b.name}>
                      {b.name}
                      {b.primary ? " (primary)" : ""} — {Object.values(b.open_by_severity).reduce((n, c) => n + c, 0)} open
                    </option>
                  ))}
                </NativeSelect>
              </label>
            ) : (
              <span className="inline-flex items-center gap-1">
                <GitBranch aria-hidden className="size-3" /> {repo.ref || repo.default_branch}
              </span>
            )}
            <span>Target: {target?.label ?? `#${repo.target_id}`}</span>
            <span>
              Last scan: <RelativeTime value={repo.last_scanned_at} fallback="never" />
            </span>
            {(shown?.head_sha ?? repo.last_head_sha) ? (
              <code className="text-xs">{(shown?.head_sha ?? repo.last_head_sha ?? "").slice(0, 10)}</code>
            ) : null}
          </div>
          <div className="mt-2">
            <SeverityCounts counts={shown?.open_by_severity ?? repo.open_by_severity} />
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={() => scan.mutate(req, `Scan of ${repo.full_name}`)}>
            <Play aria-hidden /> Scan
          </Button>
          <Button variant="outline" onClick={() => scan.mutate({ ...req, force: true }, `Forced rescan of ${repo.full_name}`)}>
            <RefreshCw aria-hidden /> Force rescan
          </Button>
          <Button variant="outline" onClick={() => setBranchOpen(true)}>
            <GitBranch aria-hidden /> Other branch…
          </Button>
        </div>
      </div>
      <Tabs defaultValue="plan">
        <TabsList>
          <TabsTrigger value="plan">Upgrade plan ({upgrade_plan.length})</TabsTrigger>
          <TabsTrigger value="runtimes">Runtimes ({runtimes.length})</TabsTrigger>
          <TabsTrigger value="findings">Findings ({findings.length})</TabsTrigger>
        </TabsList>
        <TabsContent value="plan">
          <UpgradePlan plan={upgrade_plan} />
        </TabsContent>
        <TabsContent value="runtimes">
          <Runtimes runtimes={runtimes} />
        </TabsContent>
        <TabsContent value="findings">
          {findings.length ? (
            <FindingsTable findings={findings} showRepo={false} caption={`Findings in ${repo.full_name}`} />
          ) : (
            <EmptyState title="No findings" description="This repository has no known vulnerable dependencies." />
          )}
        </TabsContent>
      </Tabs>
      <BranchScanDialog
        open={branchOpen}
        onOpenChange={setBranchOpen}
        initial={repo.ref || repo.default_branch || ""}
        onScan={(branch, force) => scan.mutate({ ...req, branch: branch || undefined, force }, `Scan of ${repo.full_name}@${branch || "default"}`)}
      />
    </>
  );
}
