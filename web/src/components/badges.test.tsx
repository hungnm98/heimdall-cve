import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Severity } from "@/api/types";
import { SEVERITIES, SEVERITY_CLASS } from "@/lib/severity";
import { SeverityBadge, SeverityCounts } from "./badges";

describe("SeverityBadge", () => {
  it.each([
    ["CRITICAL", "Critical"],
    ["HIGH", "High"],
    ["MEDIUM", "Medium"],
    ["LOW", "Low"],
    ["UNKNOWN", "Unknown"],
  ] as [Severity, string][])("shows a text label for %s, not only a colour", (sev, label) => {
    render(<SeverityBadge severity={sev} />);
    const badge = screen.getByText(label);
    expect(badge).toHaveAttribute("data-severity", sev);
    // The shared palette is applied, so the colour matches everywhere else.
    for (const cls of SEVERITY_CLASS[sev].split(" ").slice(0, 2)) expect(badge).toHaveClass(cls);
  });

  it("uses a distinct colour per severity", () => {
    const bgs = SEVERITIES.map((s) => SEVERITY_CLASS[s].split(" ")[0]);
    expect(new Set(bgs).size).toBe(SEVERITIES.length);
  });
});

describe("SeverityCounts", () => {
  it("gives screen readers the full severity name", () => {
    render(<SeverityCounts counts={{ CRITICAL: 2, HIGH: 0, LOW: 5 }} />);
    expect(screen.getByTitle("2 Critical")).toHaveTextContent("Critical 2");
    expect(screen.getByTitle("5 Low")).toBeInTheDocument();
    expect(screen.queryByTitle(/High/)).not.toBeInTheDocument();
  });

  it("says when nothing is open", () => {
    render(<SeverityCounts counts={{}} />);
    expect(screen.getByText("None open")).toBeInTheDocument();
  });
});
