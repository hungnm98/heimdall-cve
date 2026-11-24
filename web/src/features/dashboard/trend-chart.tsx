import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ScanRun, Severity } from "@/api/types";
import { countOf, SEVERITY_COLOR, SEVERITY_LABEL } from "@/lib/severity";

const SERIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/** Open findings per run, stacked by severity (oldest run first). */
export function TrendChart({ runs }: { runs: ScanRun[] }) {
  const data = runs
    .filter((r) => r.stats?.open_by_severity)
    .map((r) => ({
      id: r.id,
      day: new Date(r.started_at).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
      ...Object.fromEntries(SERIES.map((s) => [s, countOf(r.stats?.open_by_severity, s)])),
      new: r.stats?.new ?? 0,
      fixed: r.stats?.fixed ?? 0,
    }));
  if (data.length === 0) return <p className="text-sm text-muted-foreground">No completed runs yet.</p>;

  return (
    <figure>
      <div className="h-64 w-full" aria-hidden>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 8, right: 8, bottom: 0, left: -16 }} barCategoryGap="20%">
            <CartesianGrid vertical={false} stroke="var(--border)" />
            <XAxis dataKey="day" tickLine={false} axisLine={false} fontSize={11} stroke="var(--muted-foreground)" minTickGap={16} />
            <YAxis allowDecimals={false} tickLine={false} axisLine={false} fontSize={11} stroke="var(--muted-foreground)" />
            <Tooltip
              cursor={{ fill: "var(--muted)", opacity: 0.6 }}
              contentStyle={{
                background: "var(--popover)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                color: "var(--popover-foreground)",
                fontSize: 12,
              }}
              labelFormatter={(label, payload) => {
                const p = payload?.[0]?.payload as { id: number; new: number; fixed: number } | undefined;
                return p ? `${label} · run #${p.id} · +${p.new} new / −${p.fixed} fixed` : String(label);
              }}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} formatter={(v: string) => <span style={{ color: "var(--foreground)" }}>{v}</span>} />
            {SERIES.map((s, i) => (
              <Bar
                key={s}
                dataKey={s}
                name={SEVERITY_LABEL[s]}
                stackId="open"
                fill={SEVERITY_COLOR[s]}
                stroke="var(--card)"
                strokeWidth={1}
                radius={i === SERIES.length - 1 ? [4, 4, 0, 0] : 0}
                isAnimationActive={false}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <figcaption className="sr-only">Open findings by severity for the last {data.length} runs.</figcaption>
      <table className="sr-only">
        <thead>
          <tr>
            <th>Run</th>
            {SERIES.map((s) => (
              <th key={s}>{SEVERITY_LABEL[s]}</th>
            ))}
            <th>New</th>
            <th>Fixed</th>
          </tr>
        </thead>
        <tbody>
          {data.map((d) => (
            <tr key={d.id}>
              <td>
                {d.day} (#{d.id})
              </td>
              {SERIES.map((s) => (
                <td key={s}>{(d as unknown as Record<string, number>)[s]}</td>
              ))}
              <td>{d.new}</td>
              <td>{d.fixed}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
