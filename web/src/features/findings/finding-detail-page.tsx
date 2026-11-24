import { useQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { AlertTriangle, ArrowRight, BellOff, ChevronLeft, RotateCcw } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { errorMessage } from "@/api/problem";
import { findingQuery, useUnsuppressFinding } from "@/api/queries";
import type { FindingDetail } from "@/api/types";
import {
  BumpBadge,
  FindingStatusBadge,
  KevBadge,
  MaliciousBadge,
  SeverityBadge,
  SupportBadge,
  UnverifiedBadge,
} from "@/components/badges";
import { CopyButton, ErrorState, ExtLink, KV, RelativeTime } from "@/components/common";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/misc";
import { osvUrl } from "@/lib/utils";
import { findingTitle } from "./findings-table";
import { SuppressDialog } from "./suppress-dialog";

const route = getRouteApi("/findings/$id");

/** Advisory ids that OSV knows about (it aliases CVE, GHSA, GO, PYSEC, MAL…). */
const isOsvId = (id: string) => /^(CVE|GHSA|GO|PYSEC|MAL|RUSTSEC|OSV|GSD)-/i.test(id);

function AdvisoryLink({ id }: { id: string }) {
  return isOsvId(id) ? (
    <ExtLink href={osvUrl(id)} className="font-mono text-sm">
      {id}
    </ExtLink>
  ) : (
    <span className="font-mono text-sm">{id}</span>
  );
}

function Upgrade({ f }: { f: FindingDetail }) {
  const current = f.package?.version ?? f.runtime?.version;
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <code className="rounded bg-muted px-2 py-1">{current ?? "—"}</code>
        <ArrowRight aria-label="upgrade to" className="size-4" />
        <code className="rounded bg-muted px-2 py-1">{f.recommended_version ?? "no fixed version"}</code>
        <BumpBadge bump={f.bump} />
      </div>
      {f.bump === "major" ? (
        <p className="flex items-start gap-2 rounded-md border border-amber-300 bg-amber-50 p-2 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100">
          <AlertTriangle aria-hidden className="mt-0.5 size-4 shrink-0" />
          Major version upgrade: expect breaking API changes. Read the changelog and run the full test suite.
        </p>
      ) : null}
      {f.fixed_versions?.length ? (
        <p className="text-sm text-muted-foreground">
          Fixed in: {f.fixed_versions.map((v) => <code key={v} className="mr-1">{v}</code>)}
        </p>
      ) : null}
      {f.advice ? (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <code className="block min-w-0 flex-1 overflow-x-auto whitespace-pre rounded-md bg-muted px-3 py-2 text-sm">{f.advice}</code>
          <CopyButton text={f.advice} label="Copy command" />
        </div>
      ) : null}
    </div>
  );
}

export function FindingDetailPage() {
  const { id } = route.useParams();
  const q = useQuery(findingQuery(id));
  const [suppressOpen, setSuppressOpen] = React.useState(false);
  const [unsuppressOpen, setUnsuppressOpen] = React.useState(false);
  const unsuppress = useUnsuppressFinding();

  if (q.isPending) {
    return (
      <div className="flex flex-col gap-4" aria-busy="true" aria-label="Loading finding">
        <Skeleton className="h-8 w-1/2" />
        <Skeleton className="h-40 w-full" />
        <Skeleton className="h-40 w-full" />
      </div>
    );
  }
  if (q.isError) return <ErrorState error={q.error} onRetry={() => void q.refetch()} />;
  const f = q.data;
  const [owner, name] = f.repo.split("/");
  const advisories = [f.advisory_id, ...(f.aliases ?? [])].filter((x): x is string => !!x);

  return (
    <>
      <Link to="/findings" search={{ status: "open" }} className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ChevronLeft aria-hidden className="size-4" /> Findings
      </Link>
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <FindingStatusBadge status={f.status} />
            {f.in_kev ? <KevBadge /> : null}
            {f.malicious ? <MaliciousBadge /> : null}
            {!f.verified ? <UnverifiedBadge /> : null}
            <Badge variant="outline">{f.kind}</Badge>
          </div>
          <h1 className="break-words text-xl font-semibold tracking-tight sm:text-2xl">
            {findingTitle(f)}
            {f.package ? <span className="font-normal text-muted-foreground">@{f.package.version}</span> : null}
          </h1>
          {f.summary ? <p className="mt-1 text-muted-foreground">{f.summary}</p> : null}
        </div>
        <div className="flex shrink-0 gap-2">
          {f.status === "suppressed" ? (
            <Button variant="outline" onClick={() => setUnsuppressOpen(true)}>
              <RotateCcw aria-hidden /> Unsuppress
            </Button>
          ) : f.status === "open" ? (
            <Button variant="outline" onClick={() => setSuppressOpen(true)}>
              <BellOff aria-hidden /> Suppress
            </Button>
          ) : null}
        </div>
      </div>

      {!f.verified ? (
        <p className="mb-4 rounded-md border border-violet-300 bg-violet-50 p-3 text-sm text-violet-900 dark:border-violet-800 dark:bg-violet-950 dark:text-violet-100">
          This finding was reported only by an AI agent and has not been confirmed by an advisory database. Verify it before acting on it.
        </p>
      ) : null}

      {f.status === "suppressed" && f.suppression ? (
        <Card className="mb-4 border-dashed">
          <CardHeader>
            <CardTitle>Suppressed</CardTitle>
          </CardHeader>
          <CardContent>
            <KV
              items={[
                ["Reason", f.suppression.reason],
                ["Expires", <RelativeTime key="e" value={f.suppression.expires_at} />],
                ["By", f.suppression.actor ?? "—"],
                ["Since", <RelativeTime key="s" value={f.suppression.created_at} />],
              ]}
            />
          </CardContent>
        </Card>
      ) : null}

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-4 lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Remediation</CardTitle>
            </CardHeader>
            <CardContent>
              <Upgrade f={f} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Advisories</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {advisories.length ? (
                <ul className="flex flex-wrap gap-x-4 gap-y-1">
                  {advisories.map((a) => (
                    <li key={a}>
                      <AdvisoryLink id={a} />
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground">No advisory identifiers.</p>
              )}
              {f.references?.length ? (
                <div>
                  <h3 className="mb-1 text-sm font-medium">References</h3>
                  <ul className="flex flex-col gap-1 text-sm">
                    {f.references.map((r) => (
                      <li key={r} className="break-all">
                        <ExtLink href={r}>{r}</ExtLink>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </CardContent>
          </Card>

          {f.runtime ? (
            <Card>
              <CardHeader>
                <CardTitle>Runtime</CardTitle>
              </CardHeader>
              <CardContent>
                <KV
                  items={[
                    ["Runtime", `${f.runtime.name} ${f.runtime.version}`],
                    ["Support", <SupportBadge key="s" status={f.runtime.status} />],
                    ["End of life", f.runtime.eol_date ?? "—"],
                    ["Declared in", `${f.runtime.origin}${f.runtime.via ? ` (${f.runtime.via})` : ""}`],
                    ["Latest", `${f.runtime.latest_patch ?? "—"} (cycle ${f.runtime.latest_cycle ?? "—"})`],
                  ]}
                />
              </CardContent>
            </Card>
          ) : null}
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          <Card>
            <CardHeader>
              <CardTitle>Details</CardTitle>
            </CardHeader>
            <CardContent>
              <KV
                items={[
                  [
                    "Repository",
                    owner && name ? (
                      <Link key="r" to="/repos/$owner/$name" params={{ owner, name }} className="hover:underline">
                        {f.repo}
                      </Link>
                    ) : (
                      f.repo
                    ),
                  ],
                  ["Manifest", <code key="m">{f.manifest_path}</code>],
                  ...(f.package ? ([["Ecosystem", f.package.ecosystem], ["purl", <code key="p" className="break-all text-xs">{f.package.purl}</code>]] as [React.ReactNode, React.ReactNode][]) : []),
                  ["Dependency", f.direct === undefined ? "—" : f.direct ? "direct" : `transitive${f.parents?.length ? ` via ${f.parents.join(", ")}` : ""}`],
                  ...(f.scope ? ([["Scope", f.scope]] as [React.ReactNode, React.ReactNode][]) : []),
                  ["CVSS", f.cvss_score !== undefined ? (
                    <span key="c">
                      <strong>{f.cvss_score.toFixed(1)}</strong>
                      {f.cvss_vector ? <code className="ml-2 block break-all text-xs text-muted-foreground">{f.cvss_vector}</code> : null}
                    </span>
                  ) : "—"],
                  ["EPSS", f.epss !== undefined ? `${(f.epss * 100).toFixed(1)}% (percentile ${((f.epss_percentile ?? 0) * 100).toFixed(0)})` : "—"],
                  ["Priority", f.priority !== undefined ? f.priority.toFixed(1) : "—"],
                  ["Sources", f.sources.length ? f.sources.join(", ") : "—"],
                  ["First seen", <RelativeTime key="fs" value={f.first_seen} />],
                  ["Last seen", <RelativeTime key="ls" value={f.last_seen} />],
                ]}
              />
            </CardContent>
          </Card>
        </div>
      </div>

      <SuppressDialog findingId={f.id} open={suppressOpen} onOpenChange={setSuppressOpen} />
      <ConfirmDialog
        open={unsuppressOpen}
        onOpenChange={setUnsuppressOpen}
        title="Unsuppress finding?"
        description="The finding reopens and appears in reports and notifications again."
        confirmLabel="Unsuppress"
        pending={unsuppress.isPending}
        onConfirm={() =>
          unsuppress.mutate(f.id, {
            onSuccess: () => {
              toast.success("Finding reopened");
              setUnsuppressOpen(false);
            },
            onError: (err) => toast.error(errorMessage(err)),
          })
        }
      />
    </>
  );
}
