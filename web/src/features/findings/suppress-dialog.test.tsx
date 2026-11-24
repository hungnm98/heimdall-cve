import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { db } from "@/mocks/db";
import { server } from "@/mocks/node";
import { renderWithQuery } from "@/test/render";
import { addDays, isoDate } from "@/lib/time";
import { SuppressDialog, validateSuppress } from "./suppress-dialog";

const NOW = new Date("2026-11-24T10:00:00Z");

describe("validateSuppress", () => {
  it("requires a reason of at least 3 characters", () => {
    expect(validateSuppress({ reason: " a ", expires: "2027-01-01" }, NOW).reason).toMatch(/at least 3/);
    expect(validateSuppress({ reason: "x".repeat(1001), expires: "2027-01-01" }, NOW).reason).toMatch(/1000/);
    expect(validateSuppress({ reason: "ok!", expires: "2027-01-01" }, NOW)).toEqual({});
  });

  it("requires an expiry in the future and at most one year ahead", () => {
    expect(validateSuppress({ reason: "fine", expires: "" }, NOW).expires).toMatch(/Choose/);
    expect(validateSuppress({ reason: "fine", expires: "2026-11-24" }, NOW).expires).toMatch(/future/);
    expect(validateSuppress({ reason: "fine", expires: isoDate(addDays(NOW, 365)) }, NOW)).toEqual({});
    expect(validateSuppress({ reason: "fine", expires: isoDate(addDays(NOW, 366)) }, NOW).expires).toMatch(/one year/);
  });
});

describe("SuppressDialog", () => {
  const finding = () => db.findings.find((f) => f.status === "open")!;

  it("blocks submission until the form is valid", async () => {
    const user = userEvent.setup();
    let calls = 0;
    server.use(http.put("*/api/v1/findings/:id/suppression", () => (calls++, new HttpResponse(null, { status: 204 }))));
    renderWithQuery(<SuppressDialog findingId={finding().id} open onOpenChange={() => {}} />);

    await user.click(screen.getByRole("button", { name: "Suppress" }));
    expect(await screen.findByText(/at least 3 characters/)).toBeInTheDocument();
    expect(screen.getByLabelText("Reason")).toHaveAttribute("aria-invalid", "true");

    const expires = screen.getByLabelText("Expires on (UTC)");
    await user.clear(expires);
    await user.type(expires, isoDate(addDays(new Date(), 400)));
    await user.type(screen.getByLabelText("Reason"), "Not reachable");
    await user.click(screen.getByRole("button", { name: "Suppress" }));
    expect(await screen.findByText(/at most one year/)).toBeInTheDocument();
    expect(calls).toBe(0);
  });

  it("sends reason and expiry with the CSRF headers and closes", async () => {
    const user = userEvent.setup();
    const f = finding();
    let captured: { body: unknown; headers: Headers } | undefined;
    server.use(
      http.put("*/api/v1/findings/:id/suppression", async ({ request }) => {
        captured = { body: await request.json(), headers: request.headers };
        return new HttpResponse(null, { status: 204 });
      }),
    );
    let open = true;
    renderWithQuery(<SuppressDialog findingId={f.id} open onOpenChange={(o) => (open = o)} />);
    await user.type(screen.getByLabelText("Reason"), "  Dev-only dependency  ");
    await user.click(screen.getByRole("button", { name: "Suppress" }));

    await waitFor(() => expect(open).toBe(false));
    expect(captured!.headers.get("X-Heimdall-Request")).toBe("1");
    expect(captured!.headers.get("Content-Type")).toBe("application/json");
    expect(captured!.body).toEqual({
      reason: "Dev-only dependency",
      expires_at: `${isoDate(addDays(new Date(), 90))}T00:00:00Z`,
    });
  });

  it("maps server field errors onto the form", async () => {
    const user = userEvent.setup();
    server.use(
      http.put("*/api/v1/findings/:id/suppression", () =>
        HttpResponse.json(
          { title: "Bad Request", status: 400, fields: { expires_at: "Too far in the future (server)" } },
          { status: 400, headers: { "Content-Type": "application/problem+json" } },
        ),
      ),
    );
    renderWithQuery(<SuppressDialog findingId={finding().id} open onOpenChange={() => {}} />);
    await user.type(screen.getByLabelText("Reason"), "Accepted risk");
    await user.click(screen.getByRole("button", { name: "Suppress" }));
    expect(await screen.findByText("Too far in the future (server)")).toBeInTheDocument();
    expect(screen.getByLabelText("Expires on (UTC)")).toHaveAttribute("aria-invalid", "true");
  });
});
