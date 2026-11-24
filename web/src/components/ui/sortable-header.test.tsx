import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { compareValues, nextSort, SortableTH, type SortState, useClientSort } from "./sortable-header";
import { TBody, TD, THead, TR, Table } from "./table";

describe("nextSort", () => {
  it("starts a column at its first order, then flips it", () => {
    expect(nextSort(undefined, "severity", "desc")).toEqual({ key: "severity", order: "desc" });
    expect(nextSort({ key: "severity", order: "desc" }, "severity", "desc")).toEqual({ key: "severity", order: "asc" });
    expect(nextSort({ key: "severity", order: "asc" }, "severity", "desc")).toEqual({ key: "severity", order: "desc" });
    // switching column restarts at that column's first order
    expect(nextSort({ key: "severity", order: "asc" }, "name", "asc")).toEqual({ key: "name", order: "asc" });
    expect(nextSort({ key: "name", order: "asc" }, "first_seen", "desc")).toEqual({ key: "first_seen", order: "desc" });
  });
});

describe("compareValues", () => {
  it("sorts missing values first, numbers numerically, text naturally and case-insensitively", () => {
    expect(["b", null, "A", "a10", "a9"].sort(compareValues)).toEqual([null, "A", "a9", "a10", "b"]);
    expect([10, 9, null, 100].sort(compareValues)).toEqual([null, 9, 10, 100]);
  });
});

type Row = { name: string; score: number };
const ROWS: Row[] = [
  { name: "beta", score: 2 },
  { name: "alpha", score: 3 },
  { name: "gamma", score: 1 },
];
const SORT = { name: (r: Row) => r.name, score: (r: Row) => r.score };

function Demo({ initial }: { initial?: SortState<"name" | "score"> }) {
  const { sorted, sort, setSort } = useClientSort(ROWS, SORT, initial);
  return (
    <Table>
      <THead>
        <tr>
          <SortableTH sortKey="name" sort={sort} onSort={setSort}>
            Name
          </SortableTH>
          <SortableTH sortKey="score" first="desc" sort={sort} onSort={setSort}>
            Score
          </SortableTH>
        </tr>
      </THead>
      <TBody>
        {sorted.map((r) => (
          <TR key={r.name}>
            <TD>{r.name}</TD>
            <TD>{r.score}</TD>
          </TR>
        ))}
      </TBody>
    </Table>
  );
}

const names = () => screen.getAllByRole("row").slice(1).map((r) => within(r).getAllByRole("cell")[0]!.textContent);
const header = (name: string) => screen.getByRole("columnheader", { name });

describe("SortableTH + useClientSort", () => {
  it("keeps the given order until a header is used, with no aria-sort", () => {
    render(<Demo />);
    expect(names()).toEqual(["beta", "alpha", "gamma"]);
    expect(header("Name")).not.toHaveAttribute("aria-sort");
    expect(header("Score")).not.toHaveAttribute("aria-sort");
  });

  it("sorts on click: name A→Z first, score highest first, then flips", async () => {
    const user = userEvent.setup();
    render(<Demo />);
    await user.click(screen.getByRole("button", { name: "Name" }));
    expect(names()).toEqual(["alpha", "beta", "gamma"]);
    expect(header("Name")).toHaveAttribute("aria-sort", "ascending");

    await user.click(screen.getByRole("button", { name: "Name" }));
    expect(names()).toEqual(["gamma", "beta", "alpha"]);
    expect(header("Name")).toHaveAttribute("aria-sort", "descending");

    await user.click(screen.getByRole("button", { name: "Score" }));
    expect(names()).toEqual(["alpha", "beta", "gamma"]); // 3, 2, 1
    expect(header("Score")).toHaveAttribute("aria-sort", "descending");
    expect(header("Name")).not.toHaveAttribute("aria-sort"); // only one sorted column
  });

  it("is keyboard operable (a real button in the header cell)", async () => {
    const user = userEvent.setup();
    render(<Demo initial={{ key: "score", order: "desc" }} />);
    expect(header("Score")).toHaveAttribute("aria-sort", "descending");
    await user.tab();
    expect(screen.getByRole("button", { name: "Name" })).toHaveFocus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Score" })).toHaveFocus();
    await user.keyboard("{Enter}");
    expect(header("Score")).toHaveAttribute("aria-sort", "ascending");
    expect(names()).toEqual(["gamma", "beta", "alpha"]);
    await user.keyboard(" ");
    expect(header("Score")).toHaveAttribute("aria-sort", "descending");
  });
});
