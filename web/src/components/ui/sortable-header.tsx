import { ArrowDown, ArrowUp, ArrowUpDown } from "lucide-react";
import * as React from "react";
import { cn } from "@/lib/utils";
import { TH } from "./table";

export type SortOrder = "asc" | "desc";

export interface SortState<K extends string = string> {
  key: K;
  order: SortOrder;
}

/**
 * The sort after activating column `key`: an inactive column starts at its
 * `first` order (desc for severity, priority and dates; asc for names), the
 * active column flips.
 */
export function nextSort<K extends string>(current: SortState<K> | undefined, key: K, first: SortOrder): SortState<K> {
  if (current?.key !== key) return { key, order: first };
  return { key, order: current.order === "asc" ? "desc" : "asc" };
}

const ariaSort = (order: SortOrder) => (order === "asc" ? "ascending" : "descending");

/**
 * A column header that sorts its table: a button inside the `th` (keyboard
 * operable, visible focus ring) with an icon for unsorted / ascending /
 * descending, and `aria-sort` on the `th` of the active column.
 */
export function SortableTH<K extends string>({
  sortKey,
  first = "asc",
  sort,
  onSort,
  className,
  children,
  ...props
}: {
  sortKey: K;
  /** Order of the first activation. */
  first?: SortOrder;
  sort: SortState<K> | undefined;
  onSort: (next: SortState<K>) => void;
} & Omit<React.ThHTMLAttributes<HTMLTableCellElement>, "onClick">) {
  const active = sort?.key === sortKey ? sort.order : undefined;
  const Icon = active === "asc" ? ArrowUp : active === "desc" ? ArrowDown : ArrowUpDown;
  return (
    <TH aria-sort={active ? ariaSort(active) : undefined} className={className} {...props}>
      <button
        type="button"
        onClick={() => onSort(nextSort(sort, sortKey, first))}
        className={cn(
          "-mx-1 inline-flex items-center gap-1 rounded px-1 py-0.5 uppercase tracking-wide hover:text-foreground",
          "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring",
          active && "text-foreground",
        )}
      >
        {children}
        <Icon aria-hidden className={cn("size-3.5 shrink-0", !active && "opacity-50")} />
      </button>
    </TH>
  );
}

/**
 * Header of a column a list is always ordered by (e.g. newest first for a
 * paginated log): shows the order without offering to change it.
 */
export function SortedTH({
  order,
  className,
  children,
  ...props
}: { order: SortOrder } & React.ThHTMLAttributes<HTMLTableCellElement>) {
  const Icon = order === "asc" ? ArrowUp : ArrowDown;
  return (
    <TH aria-sort={ariaSort(order)} className={className} {...props}>
      <span className="inline-flex items-center gap-1">
        {children}
        <Icon aria-hidden className="size-3.5 shrink-0" />
      </span>
    </TH>
  );
}

type SortValue = string | number | null | undefined;

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: "base" });

/** Compares sort values; missing values sort as the smallest. */
export function compareValues(a: SortValue, b: SortValue): number {
  if (a == null || a === "") return b == null || b === "" ? 0 : -1;
  if (b == null || b === "") return 1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  return collator.compare(String(a), String(b));
}

/**
 * Client-side sort for a list that is fully in memory (never a page of a
 * paginated list: those sort on the server). Without a sort the rows keep
 * their given order; ties keep it too (stable sort).
 */
export function useClientSort<T, K extends string>(
  rows: readonly T[],
  accessors: Record<K, (row: T) => SortValue>,
  initial?: SortState<K>,
) {
  const [sort, setSort] = React.useState<SortState<K> | undefined>(initial);
  const sorted = React.useMemo(() => {
    if (!sort) return rows;
    const get = accessors[sort.key];
    const dir = sort.order === "asc" ? 1 : -1;
    return [...rows].sort((a, b) => dir * compareValues(get(a), get(b)));
    // accessors are expected to be stable per column key
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, sort]);
  return { sorted, sort, setSort };
}
