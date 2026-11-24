import {
  AlertOctagon,
  AlertTriangle,
  Bot,
  CircleCheck,
  CircleDashed,
  CircleX,
  Clock,
  Info,
  Loader2,
  ShieldAlert,
  Skull,
} from "lucide-react";
import type {
  BumpType,
  FindingStatus,
  JobStatus,
  Origin,
  RunStatus,
  Severity,
  SupportStatus,
} from "@/api/types";
import { Badge, type BadgeProps } from "@/components/ui/badge";
import { SEVERITY_CLASS, SEVERITY_LABEL } from "@/lib/severity";
import { cn } from "@/lib/utils";

const SEVERITY_ICON: Record<Severity, typeof AlertOctagon> = {
  CRITICAL: AlertOctagon,
  HIGH: AlertTriangle,
  MEDIUM: Info,
  LOW: Info,
  UNKNOWN: CircleDashed,
};

/** Severity indicator: colour + icon + text label, so colour is never the only signal. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const Icon = SEVERITY_ICON[severity];
  return (
    <span
      data-severity={severity}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
        SEVERITY_CLASS[severity],
        className,
      )}
    >
      <Icon aria-hidden className="size-3" />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

/** Compact "C 3 · H 5" style counts with full labels for screen readers. */
export function SeverityCounts({
  counts,
  className,
}: {
  counts: Record<string, number> | undefined;
  className?: string;
}) {
  const order: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const items = order.filter((s) => (counts?.[s] ?? 0) > 0);
  if (items.length === 0) return <span className="text-xs text-muted-foreground">None open</span>;
  return (
    <span className={cn("inline-flex flex-wrap gap-1", className)}>
      {items.map((s) => (
        <span
          key={s}
          title={`${counts?.[s]} ${SEVERITY_LABEL[s]}`}
          className={cn("rounded border px-1.5 text-xs font-semibold tabular-nums", SEVERITY_CLASS[s])}
        >
          <span aria-hidden>{s[0]}</span>
          <span className="sr-only">{SEVERITY_LABEL[s]}</span> {counts?.[s]}
        </span>
      ))}
    </span>
  );
}

export function KevBadge() {
  return (
    <Badge variant="danger" title="Listed in the CISA Known Exploited Vulnerabilities catalog">
      <ShieldAlert aria-hidden /> KEV
    </Badge>
  );
}

export function MaliciousBadge() {
  return (
    <Badge variant="danger" title="Known malicious package">
      <Skull aria-hidden /> Malicious
    </Badge>
  );
}

export function UnverifiedBadge() {
  return (
    <Badge variant="purple" title="Reported only by an AI agent; not confirmed by an advisory database">
      <Bot aria-hidden /> AI agent — unverified
    </Badge>
  );
}

const JOB: Record<JobStatus, { v: BadgeProps["variant"]; icon: typeof Clock }> = {
  queued: { v: "secondary", icon: Clock },
  running: { v: "info", icon: Loader2 },
  succeeded: { v: "success", icon: CircleCheck },
  failed: { v: "danger", icon: CircleX },
  canceled: { v: "outline", icon: CircleX },
};

export function JobStatusBadge({ status }: { status: JobStatus }) {
  const { v, icon: Icon } = JOB[status];
  return (
    <Badge variant={v} data-status={status}>
      <Icon aria-hidden className={cn(status === "running" && "animate-spin")} />
      {status}
    </Badge>
  );
}

const RUN: Record<RunStatus, BadgeProps["variant"]> = {
  running: "info",
  succeeded: "success",
  partial: "warning",
  failed: "danger",
};

export function RunStatusBadge({ status }: { status: RunStatus }) {
  return <Badge variant={RUN[status]}>{status}</Badge>;
}

const FINDING: Record<FindingStatus, BadgeProps["variant"]> = {
  open: "warning",
  fixed: "success",
  suppressed: "secondary",
  removed: "outline",
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return <Badge variant={FINDING[status]}>{status}</Badge>;
}

const SUPPORT: Record<SupportStatus, { v: BadgeProps["variant"]; label: string }> = {
  supported: { v: "success", label: "Supported" },
  "security-only": { v: "info", label: "Security fixes only" },
  "eol-soon": { v: "warning", label: "EOL soon" },
  eol: { v: "danger", label: "End of life" },
  unknown: { v: "outline", label: "Unknown" },
};

export function SupportBadge({ status }: { status: SupportStatus }) {
  const { v, label } = SUPPORT[status];
  return <Badge variant={v}>{label}</Badge>;
}

export function BumpBadge({ bump }: { bump: BumpType | undefined }) {
  if (!bump) return null;
  if (bump === "no-fix-available") return <Badge variant="outline">No fix available</Badge>;
  if (bump === "major")
    return (
      <Badge variant="warning" title="Major version bump: may contain breaking changes">
        <AlertTriangle aria-hidden /> major
      </Badge>
    );
  return <Badge variant="secondary">{bump}</Badge>;
}

export function OriginBadge({ origin }: { origin: Origin }) {
  return origin === "config" ? (
    <Badge variant="outline" title="Defined in the config file; read-only in the UI">
      config
    </Badge>
  ) : (
    <Badge variant="secondary">ui</Badge>
  );
}

export function HealthBadge({ healthy }: { healthy: boolean }) {
  return healthy ? (
    <Badge variant="success">
      <CircleCheck aria-hidden /> healthy
    </Badge>
  ) : (
    <Badge variant="danger">
      <CircleX aria-hidden /> unhealthy
    </Badge>
  );
}
