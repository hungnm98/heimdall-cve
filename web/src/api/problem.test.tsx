import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it } from "vitest";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";
import { api, unwrap } from "./client";
import { ApiError, errorMessage, splitFieldErrors, toApiError } from "./problem";

describe("problem+json", () => {
  it("parses RFC 9457 documents", () => {
    const err = toApiError(400, "Bad Request", {
      type: "about:blank",
      title: "Bad Request",
      status: 400,
      detail: "Validation failed",
      fields: { owner: "Required", "filter.max_repos": "Must be positive" },
    });
    expect(err).toBeInstanceOf(ApiError);
    expect(err.message).toBe("Validation failed");
    expect(errorMessage(err)).toBe("Bad Request: Validation failed");
    expect(splitFieldErrors(err, ["owner", "url"])).toEqual({
      fields: { owner: "Required" },
      other: { "filter.max_repos": "Must be positive" },
    });
  });

  it("falls back to the status line for non-problem bodies", () => {
    const err = toApiError(502, "Bad Gateway", "<html>upstream down</html>");
    expect(err.title).toBe("Bad Gateway");
    expect(err.status).toBe(502);
    expect(err.fields).toEqual({});
  });

  it("unwrap throws ApiError for error responses", async () => {
    server.use(
      http.get("*/api/v1/targets/:id", () =>
        HttpResponse.json({ title: "Not Found", status: 404, detail: "Target 9 not found" }, { status: 404, headers: { "Content-Type": "application/problem+json" } }),
      ),
    );
    await expect(unwrap(api.GET("/targets/{id}", { params: { path: { id: 9 } } }))).rejects.toMatchObject({
      status: 404,
      detail: "Target 9 not found",
    });
  });

  it("maps `fields` onto the target form fields and lists the unknown ones", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("*/api/v1/targets/preview", () =>
        HttpResponse.json(
          {
            title: "Bad Request",
            status: 400,
            detail: "Validation failed",
            fields: { owner: "Organization acme-x does not exist", branch: "Branch names cannot contain spaces", "filter.weird": "Unknown option" },
          },
          { status: 400, headers: { "Content-Type": "application/problem+json" } },
        ),
      ),
    );
    renderApp("/targets/new");
    await user.type(await screen.findByLabelText("Organization"), "acme-x");
    // wait for profiles to load into the select
    await screen.findByRole("option", { name: "github-token (token)" });
    await user.click(screen.getByRole("button", { name: /preview repositories/i }));

    const owner = screen.getByLabelText("Organization");
    expect(await screen.findByText("Organization acme-x does not exist")).toBeInTheDocument();
    expect(owner).toHaveAttribute("aria-invalid", "true");
    expect(owner.getAttribute("aria-describedby")).toContain("t-owner-error");
    expect(screen.getByLabelText("Branch")).toHaveAttribute("aria-invalid", "true");
    const alert = screen.getAllByRole("alert").find((el) => el.textContent?.includes("filter.weird"))!;
    expect(within(alert).getByText(/Unknown option/)).toBeInTheDocument();
  });
});
