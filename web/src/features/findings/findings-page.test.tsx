import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";
import { parseFindingSearch, toFindingsQuery } from "./filters";
import { searchOfSort, sortOfSearch } from "./findings-page";

function recordFindingRequests() {
  const seen: URLSearchParams[] = [];
  server.events.on("request:start", ({ request }) => {
    const url = new URL(request.url);
    if (url.pathname.endsWith("/api/v1/findings")) seen.push(url.searchParams);
  });
  return seen;
}

afterEach(() => server.events.removeAllListeners());

const table = () => screen.findByRole("table", { name: "Findings" });

describe("findings sort ↔ URL", () => {
  it("parses and maps sort/order, dropping unknown values", () => {
    expect(parseFindingSearch({ sort: "priority", order: "asc" })).toMatchObject({ sort: "priority", order: "asc" });
    expect(parseFindingSearch({ sort: "cvss", order: "up" })).toMatchObject({ sort: undefined, order: undefined });
    expect(toFindingsQuery({ sort: "name", order: "desc" })).toEqual({ sort: "name", order: "desc" });
    expect(sortOfSearch({})).toEqual({ key: "severity", order: "desc" });
    expect(sortOfSearch({ sort: "name" })).toEqual({ key: "name", order: "asc" });
    expect(sortOfSearch({ sort: "first_seen" })).toEqual({ key: "first_seen", order: "desc" });
    expect(searchOfSort({ key: "severity", order: "desc" })).toEqual({ sort: undefined, order: undefined });
    expect(searchOfSort({ key: "priority", order: "desc" })).toEqual({ sort: "priority", order: "desc" });
  });

  it("shows the server's default order (severity, worst first) without sort params", async () => {
    const seen = recordFindingRequests();
    renderApp("/findings");
    const t = await table();
    expect(within(t).getByRole("columnheader", { name: "Severity" })).toHaveAttribute("aria-sort", "descending");
    for (const name of ["Fix", "Status"]) expect(within(t).queryByRole("button", { name })).toBeNull();
    await waitFor(() => expect(seen.length).toBeGreaterThan(0));
    expect(seen[0]!.get("sort")).toBeNull();
    expect(seen[0]!.get("order")).toBeNull();
  });

  it("sorts on the server from the URL", async () => {
    const seen = recordFindingRequests();
    renderApp("/findings?sort=priority&order=asc");
    const t = await table();
    expect(within(t).getByRole("columnheader", { name: "Priority" })).toHaveAttribute("aria-sort", "ascending");
    expect(within(t).getByRole("columnheader", { name: "Severity" })).not.toHaveAttribute("aria-sort");
    await waitFor(() => expect(seen.length).toBeGreaterThan(0));
    expect(seen[0]!.get("sort")).toBe("priority");
    expect(seen[0]!.get("order")).toBe("asc");
  });

  it("writes header clicks to the URL and refetches in that order", async () => {
    const user = userEvent.setup();
    const seen = recordFindingRequests();
    const { history } = renderApp("/findings?status=open");
    const t = await table();

    await user.click(within(t).getByRole("button", { name: "First seen" }));
    await waitFor(() => expect(history.location.search).toContain("sort=first_seen"));
    expect(history.location.search).toContain("order=desc"); // newest first on the first click
    expect(history.location.search).toContain("status=open"); // filters kept
    await waitFor(() => expect(seen.some((p) => p.get("sort") === "first_seen" && p.get("order") === "desc")).toBe(true));

    await user.click(within(await table()).getByRole("button", { name: "Package / advisory" }));
    await waitFor(() => expect(history.location.search).toContain("sort=name"));
    expect(history.location.search).toContain("order=asc"); // A→Z first

    // Back to the default order: the URL drops sort/order.
    await user.click(within(await table()).getByRole("button", { name: "Severity" }));
    await waitFor(() => expect(history.location.search).not.toContain("sort="));
    expect(history.location.search).toContain("status=open");
  });

  it("keeps the sort when filters are cleared", async () => {
    const user = userEvent.setup();
    const { history } = renderApp("/findings?status=open&sort=repo&order=desc");
    const form = await screen.findByRole("search", { name: "Filter findings" });
    await user.click(within(form).getByRole("button", { name: /clear filters/i }));
    await waitFor(() => expect(history.location.search).not.toContain("status="));
    expect(history.location.search).toContain("sort=repo");
    expect(history.location.search).toContain("order=desc");
  });
});
