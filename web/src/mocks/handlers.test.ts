import { describe, expect, it } from "vitest";
import { api, unwrap } from "@/api/client";
import { db } from "./db";

describe("mock API", () => {
  it("paginates findings with an opaque cursor, ordered by severity", async () => {
    const first = await unwrap(api.GET("/findings", { params: { query: { limit: 10 } } }));
    expect(db.findings.length).toBeGreaterThan(50); // more than one default page, so "Load more" shows
    expect(first.items).toHaveLength(10);
    expect(first.next_cursor).toBeTruthy();
    const second = await unwrap(api.GET("/findings", { params: { query: { limit: 10, cursor: first.next_cursor } } }));
    expect(second.items[0]!.id).not.toBe(first.items[0]!.id);
    const all = await unwrap(api.GET("/findings", { params: { query: { limit: 500 } } }));
    expect(all.items.length).toBe(db.findings.length);
    expect(all.next_cursor).toBeUndefined();
    const ranks = all.items.map((f) => ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"].indexOf(f.severity));
    expect([...ranks].sort((a, b) => b - a)).toEqual(ranks);
  });

  it("covers every severity, KEV, malicious, unverified and EOL runtimes", () => {
    const sev = new Set(db.findings.map((f) => f.severity));
    for (const s of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) expect(sev).toContain(s);
    expect(db.findings.some((f) => f.in_kev)).toBe(true);
    expect(db.findings.some((f) => f.malicious)).toBe(true);
    expect(db.findings.some((f) => !f.verified)).toBe(true);
    expect(db.findings.some((f) => f.runtime?.status === "eol")).toBe(true);
    expect(new Set(db.jobs.map((j) => j.status))).toEqual(new Set(["queued", "running", "succeeded", "failed", "canceled"]));
  });

  it("returns the existing active job for the same scope (200 instead of 201)", async () => {
    const a = await api.POST("/jobs", { body: { target_id: 2 } });
    const b = await api.POST("/jobs", { body: { target_id: 2 } });
    expect(a.response.status).toBe(201);
    expect(b.response.status).toBe(200);
    expect(b.data!.id).toBe(a.data!.id);
  });

  it("rejects writes without the CSRF header", async () => {
    const res = await fetch(new URL("api/v1/jobs", document.baseURI), { method: "POST", body: "{}", headers: { "Content-Type": "application/json" } });
    expect(res.status).toBe(403);
    expect(res.headers.get("Content-Type")).toContain("application/problem+json");
  });

  it("keeps config targets read-only", async () => {
    const t = db.targets.find((x) => x.origin === "config")!;
    const res = await api.DELETE("/targets/{id}", { params: { path: { id: t.id } } });
    expect(res.response.status).toBe(409);
  });
});
