import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { describe, expect, it, vi } from "vitest";
import { db } from "@/mocks/db";
import { server } from "@/mocks/node";
import { renderWithQuery } from "@/test/render";
import { AuthProfileForm } from "./auth-profile-form";

function capturePatch() {
  const bodies: Record<string, unknown>[] = [];
  server.use(
    http.patch("*/api/v1/auth-profiles/:name", async ({ request, params }) => {
      const body = (await request.json()) as Record<string, unknown>;
      bodies.push(body);
      return HttpResponse.json({ ...db.profile(db.profiles.find((p) => p.name === params.name)!), updated_at: new Date().toISOString() });
    }),
  );
  return bodies;
}

describe("AuthProfileForm", () => {
  const profile = () => db.profile(db.profiles.find((p) => p.name === "globex-app")!);

  it("never pre-fills the secret and omits it when left empty", async () => {
    const user = userEvent.setup();
    const bodies = capturePatch();
    const onDone = vi.fn();
    renderWithQuery(<AuthProfileForm profile={profile()} secretsEnabled onDone={onDone} onCancel={() => {}} />);

    const secret = screen.getByLabelText(/private key/i);
    expect(secret).toHaveValue("");
    expect(secret).toHaveAttribute("placeholder", "Leave empty to keep the current secret");

    await user.clear(screen.getByLabelText("Installation ID"));
    await user.type(screen.getByLabelText("Installation ID"), "777");
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).not.toHaveProperty("secret");
    expect(bodies[0]).not.toHaveProperty("secret_kind");
    expect(bodies[0]).toMatchObject({ name: "globex-app", type: "app", options: { app_id: 412233, installation_id: 777 } });
  });

  it("treats a whitespace-only secret as empty", async () => {
    const user = userEvent.setup();
    const bodies = capturePatch();
    const p = db.profile(db.profiles.find((x) => x.name === "spare-token")!);
    renderWithQuery(<AuthProfileForm profile={p} secretsEnabled onDone={() => {}} onCancel={() => {}} />);
    await user.type(screen.getByLabelText(/access token/i), "   ");
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).not.toHaveProperty("secret");
  });

  it("sends a replaced secret with its kind", async () => {
    const user = userEvent.setup();
    const bodies = capturePatch();
    const p = db.profile(db.profiles.find((x) => x.name === "spare-token")!);
    renderWithQuery(<AuthProfileForm profile={p} secretsEnabled onDone={() => {}} onCancel={() => {}} />);
    const input = screen.getByLabelText(/access token/i);
    expect(input).toHaveAttribute("type", "password");
    await user.type(input, "ghp_example");
    await user.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toMatchObject({ secret: "ghp_example", secret_kind: "token" });
  });

  it("hides the secret input and explains why when secrets are disabled", () => {
    renderWithQuery(<AuthProfileForm secretsEnabled={false} onDone={() => {}} onCancel={() => {}} />);
    expect(screen.queryByLabelText(/access token/i)).not.toBeInTheDocument();
    expect(screen.getByText(/no master key/i)).toBeInTheDocument();
  });

  it("shows server field errors next to the field", async () => {
    const user = userEvent.setup();
    server.use(
      http.post("*/api/v1/auth-profiles", () =>
        HttpResponse.json(
          { title: "Conflict", status: 409, detail: 'Auth profile "dup" already exists' },
          { status: 409, headers: { "Content-Type": "application/problem+json" } },
        ),
      ),
    );
    renderWithQuery(<AuthProfileForm secretsEnabled onDone={() => {}} onCancel={() => {}} />);
    await user.type(screen.getByLabelText("Name"), "dup");
    await user.type(screen.getByLabelText(/access token/i), "ghp_x");
    await user.click(screen.getByRole("button", { name: "Create profile" }));
    expect(await screen.findByRole("alert")).toHaveTextContent('Conflict: Auth profile "dup" already exists');
  });
});
