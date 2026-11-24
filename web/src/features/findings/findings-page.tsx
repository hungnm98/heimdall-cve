import { useInfiniteQuery } from "@tanstack/react-query";
import { getRouteApi, Link } from "@tanstack/react-router";
import { SearchX } from "lucide-react";
import { findingsQuery } from "@/api/queries";
import { EmptyState, ErrorState, LoadMore, PageHeader, TableSkeleton } from "@/components/common";
import { Button } from "@/components/ui/button";
import { clearFilters, type FindingSearch, FindingsFilters, hasFilters, toFindingsQuery } from "./filters";
import { DEFAULT_FINDING_SORT, FINDING_SORT_FIRST, FindingsTable, type FindingSortState } from "./findings-table";

const route = getRouteApi("/findings");

/** The sort shown by the table for the URL's sort/order (absent: the API default). */
export function sortOfSearch(s: FindingSearch): FindingSortState {
  const key = s.sort ?? DEFAULT_FINDING_SORT.key;
  return { key, order: s.order ?? FINDING_SORT_FIRST[key] };
}

/** URL sort/order for a table sort; the API default leaves the URL clean. */
export function searchOfSort(s: FindingSortState): Pick<FindingSearch, "sort" | "order"> {
  const isDefault = s.key === DEFAULT_FINDING_SORT.key && s.order === DEFAULT_FINDING_SORT.order;
  return isDefault ? { sort: undefined, order: undefined } : { sort: s.key, order: s.order };
}

export function FindingsPage() {
  const search = route.useSearch();
  const navigate = route.useNavigate();
  const q = useInfiniteQuery(findingsQuery(toFindingsQuery(search)));
  const findings = q.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <>
      <PageHeader
        title="Findings"
        description="Vulnerable dependencies, malicious packages and end-of-life runtimes, worst first. Sort by any column with an arrow."
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
              <Button variant="outline" onClick={() => void navigate({ search: clearFilters, replace: true })}>
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
          <FindingsTable
            findings={findings}
            virtualize
            caption="Findings"
            sort={sortOfSearch(search)}
            onSortChange={(s) => void navigate({ search: (prev) => ({ ...prev, ...searchOfSort(s) }), replace: true })}
          />
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
