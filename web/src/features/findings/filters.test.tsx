import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";
import { parseFindingSearch, toFindingsQuery } from "./filters";

describe("parseFindingSearch / toFindingsQuery", () => {
  it("keeps valid params and drops unknown values", () => {
    expect(
      parseFindingSearch({ kind: "dependency", status: "bogus", min_severity: "HIGH", kev: "true", new_since: "2026-11-01", q: 123, repo: " " }),
    ).toEqual({ kind: "dependency", status: undefined, min_severity: "HIGH", kev: true, new_since: "2026-11-01", q: "123", repo: undefined });
    expect(parseFindingSearch({ new_since: "yesterday", kev: "maybe" })).toMatchObject({ new_since: undefined, kev: undefined });
  });

  it("maps the date filter to an RFC 3339 timestamp for the API", () => {
    expect(toFindingsQuery({ new_since: "2026-11-01", kev: false })).toEqual({ new_since: "2026-11-01T00:00:00Z", kev: false });
  });
});

describe("Findings filters ↔ URL", () => {
  it("initialises the controls from the URL and sends them to the API", async () => {
    const seen: URLSearchParams[] = [];
    server.events.on("request:start", ({ request }) => {
      const url = new URL(request.url);
      if (url.pathname.endsWith("/api/v1/findings")) seen.push(url.searchParams);
    });
    renderApp("/findings?min_severity=HIGH&kev=true&repo=acme%2Fapi");

    const form = await screen.findByRole("search", { name: "Filter findings" });
    expect(within(form).getByLabelText("Minimum severity")).toHaveValue("HIGH");
    expect(within(form).getByLabelText("Known exploited (KEV)")).toHaveValue("true");
    expect(within(form).getByLabelText("Repository")).toHaveValue("acme/api");
    await screen.findByRole("link", { name: /golang\.org\/x\/net/ });
    await waitFor(() => expect(seen.length).toBeGreaterThan(0));
    const params = seen[seen.length - 1]!;
    expect(params.get("min_severity")).toBe("HIGH");
    expect(params.get("kev")).toBe("true");
    expect(params.get("repo")).toBe("acme/api");
    server.events.removeAllListeners();
  });

  it("writes control changes back to the URL", async () => {
    const user = userEvent.setup();
    const { history } = renderApp("/findings");
    const form = await screen.findByRole("search", { name: "Filter findings" });

    await user.selectOptions(within(form).getByLabelText("Status"), "suppressed");
    await waitFor(() => expect(history.location.search).toContain("status=suppressed"));

    await user.type(within(form).getByLabelText("Search package or advisory id"), "lodash{Enter}");
    await waitFor(() => expect(history.location.search).toContain("q=lodash"));

    await user.click(within(form).getByRole("button", { name: /clear filters/i }));
    await waitFor(() => expect(history.location.search).toBe(""));
    expect(within(form).getByLabelText("Status")).toHaveValue("");
  });

  it("shows the problem detail and a retry button when the API fails", async () => {
    server.use(
      http.get("*/api/v1/findings", () =>
        HttpResponse.json({ title: "Bad Request", status: 400, detail: "unknown cursor" }, { status: 400, headers: { "Content-Type": "application/problem+json" } }),
      ),
    );
    renderApp("/findings");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Bad Request: unknown cursor");
    expect(within(alert).getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });
});
