import { useInfiniteQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { SearchX } from "lucide-react";
import { findingsQuery } from "@/api/queries";
import { EmptyState, ErrorState, LoadMore, PageHeader, TableSkeleton } from "@/components/common";
import { Button } from "@/components/ui/button";
import { FindingsFilters, hasFilters, toFindingsQuery } from "./filters";
import { FindingsTable } from "./findings-table";

const route = getRouteApi("/findings");

export function FindingsPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const q = useInfiniteQuery(findingsQuery(toFindingsQuery(search)));
  const findings = q.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <>
      <PageHeader
        title="Findings"
        description="Vulnerable dependencies, malicious packages and end-of-life runtimes, ordered by severity."
      />
      <FindingsFilters />
      {q.isPending ? (
        <TableSkeleton rows={8} cols={6} />
      ) : q.isError ? (
        <ErrorState error={q.error} onRetry={() => void q.refetch()} />
      ) : findings.length === 0 ? (
        hasFilters(search) ? (
          <EmptyState
            icon={SearchX}
            title="No findings match these filters"
            description="Try a lower minimum severity, another status, or clear the filters."
            action={
              <Button variant="outline" onClick={() => void navigate({ search: {}, replace: true })}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <EmptyState
            title="No findings yet"
            description="Run a scan to check your repositories for vulnerable dependencies and EOL runtimes."
            action={
              <Button asChild>
                <Link to="/targets">Set up targets</Link>
              </Button>
            }
          />
        )
      ) : (
        <>
          <FindingsTable findings={findings} virtualize caption="Findings" />
          <LoadMore
            shown={findings.length}
            hasNextPage={q.hasNextPage}
            isFetchingNextPage={q.isFetchingNextPage}
            fetchNextPage={q.fetchNextPage}
          />
        </>
      )}
    </>
  );
}
