import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { Lock, Play, Search } from "lucide-react";
import * as React from "react";
import { reposQuery, targetsQuery } from "@/api/queries";
import { SeverityCounts } from "@/components/badges";
import { EmptyState, ErrorState, LoadMore, PageHeader, RelativeTime, TableSkeleton } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";
import { useScan } from "@/features/jobs/use-scan";

const route = getRouteApi("/repos");

export function ReposPage() {
  const { q: search } = route.useSearch();
  const navigate = route.useNavigate();
  const [text, setText] = React.useState(search ?? "");
  React.useEffect(() => setText(search ?? ""), [search]);
  React.useEffect(() => {
    const t = setTimeout(() => {
      if ((text.trim() || undefined) !== search) void navigate({ search: { q: text.trim() || undefined }, replace: true });
    }, 300);
    return () => clearTimeout(t);
  }, [text, search, navigate]);

  const q = useInfiniteQuery(reposQuery({ q: search }));
  const targets = useQuery(targetsQuery());
  const labelOf = (id: number) => targets.data?.items.find((t) => t.id === id)?.label ?? `#${id}`;
  const repos = q.data?.pages.flatMap((p) => p.items) ?? [];
  const scan = useScan();

  return (
    <>
      <PageHeader title="Repositories" description="Repositories discovered from your targets, with their open findings." />
      <div className="relative mb-4 max-w-md">
        <label htmlFor="repo-q" className="sr-only">
          Search repositories
        </label>
        <Search aria-hidden className="pointer-events-none absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
        <Input id="repo-q" type="search" className="pl-8" placeholder="Search owner/name" value={text} onChange={(e) => setText(e.target.value)} />
      </div>
      {q.isPending ? (
        <TableSkeleton />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : repos.length === 0 ? (
        search ? (
          <EmptyState title={`No repositories match “${search}”`} action={<Button variant="outline" onClick={() => setText("")}>Clear search</Button>} />
        ) : (
          <EmptyState
            title="No repositories yet"
            description="Repositories appear here after a target is scanned."
            action={
              <Button asChild>
                <Link to="/targets/new">Add a target</Link>
              </Button>
            }
          />
        )
      ) : (
        <>
          <Table>
            <caption className="sr-only">Repositories</caption>
            <THead>
              <tr>
                <TH>Repository</TH>
                <TH>Open findings</TH>
                <TH className="hidden md:table-cell">Target</TH>
                <TH className="hidden sm:table-cell">Branch</TH>
                <TH>Last scan</TH>
                <TH>
                  <span className="sr-only">Actions</span>
                </TH>
              </tr>
            </THead>
            <TBody>
              {repos.map((r) => (
                <TR key={`${r.target_id}:${r.full_name}`}>
                  <TD>
                    <Link to="/repos/$owner/$name" params={{ owner: r.owner, name: r.name }} className="font-medium hover:underline">
                      {r.full_name}
                    </Link>
                    {r.private ? <Lock aria-label="private" className="ml-1 inline size-3 text-muted-foreground" /> : null}
                    {r.archived ? <span className="ml-1 text-xs text-muted-foreground">(archived)</span> : null}
                  </TD>
                  <TD>
                    <SeverityCounts counts={r.open_by_severity} />
                  </TD>
                  <TD className="hidden whitespace-nowrap text-muted-foreground md:table-cell">{labelOf(r.target_id)}</TD>
                  <TD className="hidden sm:table-cell">
                    <code className="text-xs">{r.ref || r.default_branch}</code>
                  </TD>
                  <TD>
                    <RelativeTime value={r.last_scanned_at} fallback="never" />
                  </TD>
                  <TD className="text-right">
                    <Button
                      size="sm"
                      variant="outline"
                      aria-label={`Scan ${r.full_name}`}
                      onClick={() => scan.mutate({ target_id: r.target_id, repo: r.full_name }, `Scan of ${r.full_name}`)}
                    >
                      <Play aria-hidden /> Scan
                    </Button>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
          <LoadMore shown={repos.length} hasNextPage={q.hasNextPage} isFetchingNextPage={q.isFetchingNextPage} fetchNextPage={q.fetchNextPage} />
        </>
      )}
    </>
  );
}
