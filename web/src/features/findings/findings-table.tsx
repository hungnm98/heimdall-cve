import { Link } from "@tanstack/react-router";
import {
  type ColumnDef,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { useWindowVirtualizer } from "@tanstack/react-virtual";
import { ArrowRight } from "lucide-react";
import * as React from "react";
import type { Finding } from "@/api/types";
import {
  BumpBadge,
  FindingStatusBadge,
  KevBadge,
  MaliciousBadge,
  SeverityBadge,
  UnverifiedBadge,
} from "@/components/badges";
import { RelativeTime } from "@/components/common";
import { TBody, TD, TH, THead, TR, Table } from "@/components/ui/table";

export function findingTitle(f: Finding) {
  if (f.package) return f.package.name;
  if (f.runtime) return `${f.runtime.name} ${f.runtime.version}`;
  return f.advisory_id ?? f.id;
}

/** Priority 0–100 (90+ exploited, 70+ likely exploited), with EPSS when known. */
function PriorityScore({ finding: f }: { finding: Finding }) {
  if (f.priority === undefined) return <span className="text-muted-foreground">—</span>;
  const tone = f.priority >= 90 ? "text-red-600 dark:text-red-400" : f.priority >= 70 ? "text-orange-600 dark:text-orange-400" : "";
  return (
    <div className="whitespace-nowrap tabular-nums">
      <span className={`font-semibold ${tone}`}>{Math.round(f.priority)}</span>
      {f.epss ? <div className="text-xs text-muted-foreground">EPSS {(f.epss * 100).toFixed(1)}%</div> : null}
    </div>
  );
}

function columns(showRepo: boolean): ColumnDef<Finding>[] {
  const cols: ColumnDef<Finding>[] = [
    {
      id: "severity",
      header: "Severity",
      cell: ({ row }) => <SeverityBadge severity={row.original.severity} />,
    },
    {
      id: "priority",
      header: "Priority",
      cell: ({ row }) => <PriorityScore finding={row.original} />,
    },
    {
      id: "what",
      header: "Package / advisory",
      cell: ({ row }) => {
        const f = row.original;
        return (
          <div className="min-w-56 max-w-md">
            <Link
              to="/findings/$id"
              params={{ id: f.id }}
              className="font-medium text-foreground underline-offset-4 hover:underline"
            >
              {findingTitle(f)}
              {f.package ? <span className="font-normal text-muted-foreground">@{f.package.version}</span> : null}
            </Link>
            <div className="mt-0.5 flex flex-wrap items-center gap-1 text-xs text-muted-foreground">
              <span className="font-mono">{f.advisory_id}</span>
              {f.in_kev ? <KevBadge /> : null}
              {f.malicious ? <MaliciousBadge /> : null}
              {!f.verified ? <UnverifiedBadge /> : null}
            </div>
            {f.summary ? <p className="mt-0.5 line-clamp-1 text-xs text-muted-foreground">{f.summary}</p> : null}
          </div>
        );
      },
    },
  ];
  if (showRepo) {
    cols.push({
      id: "repo",
      header: "Repository",
      cell: ({ row }) => {
        const [owner, name] = row.original.repo.split("/");
        return owner && name ? (
          <Link to="/repos/$owner/$name" params={{ owner, name }} className="whitespace-nowrap hover:underline">
            {row.original.repo}
          </Link>
        ) : (
          row.original.repo
        );
      },
    });
  }
  cols.push(
    {
      id: "fix",
      header: "Fix",
      cell: ({ row }) => {
        const f = row.original;
        if (!f.recommended_version) return <BumpBadge bump={f.bump} />;
        return (
          <span className="inline-flex flex-wrap items-center gap-1 whitespace-nowrap text-xs">
            <ArrowRight aria-hidden className="size-3" />
            <span className="sr-only">upgrade to</span>
            <code>{f.recommended_version}</code>
            <BumpBadge bump={f.bump} />
          </span>
        );
      },
    },
    { id: "status", header: "Status", cell: ({ row }) => <FindingStatusBadge status={row.original.status} /> },
    { id: "first_seen", header: "First seen", cell: ({ row }) => <RelativeTime value={row.original.first_seen} /> },
  );
  return cols;
}

/**
 * Findings table. With `virtualize`, only rows near the viewport are rendered,
 * so thousands of loaded findings stay cheap (rows use the window as scroller).
 */
export function FindingsTable({
  findings,
  showRepo = true,
  virtualize = false,
  caption,
}: {
  findings: Finding[];
  showRepo?: boolean;
  virtualize?: boolean;
  caption?: string;
}) {
  const cols = React.useMemo(() => columns(showRepo), [showRepo]);
  const table = useReactTable({ data: findings, columns: cols, getCoreRowModel: getCoreRowModel(), getRowId: (f) => f.id });
  const rows = table.getRowModel().rows;
  const bodyRef = React.useRef<HTMLTableSectionElement>(null);
  const [margin, setMargin] = React.useState(0);
  React.useLayoutEffect(() => {
    if (virtualize) setMargin((bodyRef.current?.getBoundingClientRect().top ?? 0) + window.scrollY);
  }, [virtualize]);
  const virtualizer = useWindowVirtualizer({
    count: rows.length,
    estimateSize: () => 72,
    overscan: 12,
    scrollMargin: margin,
    enabled: virtualize,
  });

  const items = virtualize ? virtualizer.getVirtualItems() : null;
  const visible = items ? items.map((v) => rows[v.index]!) : rows;
  const padTop = items && items.length ? items[0]!.start - margin : 0;
  const padBottom = items && items.length ? virtualizer.getTotalSize() - (items[items.length - 1]!.end - margin) : 0;

  return (
    <Table aria-rowcount={rows.length + 1}>
      {caption ? <caption className="sr-only">{caption}</caption> : null}
      <THead>
        {table.getHeaderGroups().map((hg) => (
          <tr key={hg.id}>
            {hg.headers.map((h) => (
              <TH key={h.id}>{flexRender(h.column.columnDef.header, h.getContext())}</TH>
            ))}
          </tr>
        ))}
      </THead>
      <TBody ref={bodyRef}>
        {padTop > 0 ? (
          <tr aria-hidden>
            <td style={{ height: padTop }} colSpan={cols.length} />
          </tr>
        ) : null}
        {visible.map((row) => (
          <TR key={row.id} data-index={row.index} aria-rowindex={row.index + 2}>
            {row.getVisibleCells().map((cell) => (
              <TD key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TD>
            ))}
          </TR>
        ))}
        {padBottom > 0 ? (
          <tr aria-hidden>
            <td style={{ height: padBottom }} colSpan={cols.length} />
          </tr>
        ) : null}
      </TBody>
    </Table>
  );
}
