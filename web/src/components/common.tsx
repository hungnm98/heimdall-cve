import { AlertCircle, Check, Copy, ExternalLink, Inbox, RotateCw } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { errorMessage } from "@/api/problem";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/misc";
import { absoluteTime, relativeTime } from "@/lib/time";
import { cn } from "@/lib/utils";

/** Relative time with the absolute (local + UTC) time as a tooltip. */
export function RelativeTime({ value, fallback = "—" }: { value?: string | null; fallback?: string }) {
  if (!value) return <span className="text-muted-foreground">{fallback}</span>;
  return (
    <time dateTime={value} title={absoluteTime(value)} className="whitespace-nowrap">
      {relativeTime(value)}
    </time>
  );
}

export function PageHeader({
  title,
  description,
  actions,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div className="min-w-0">
        <h1 className="truncate text-xl font-semibold tracking-tight sm:text-2xl">{title}</h1>
        {description ? <p className="mt-1 text-sm text-muted-foreground">{description}</p> : null}
      </div>
      {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
    </div>
  );
}

export function EmptyState({
  title,
  description,
  action,
  icon: Icon = Inbox,
}: {
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  icon?: typeof Inbox;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-8 text-center">
      <Icon aria-hidden className="size-8 text-muted-foreground" />
      <p className="font-medium">{title}</p>
      {description ? <p className="max-w-md text-sm text-muted-foreground">{description}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  return (
    <div
      role="alert"
      className="flex flex-col items-center justify-center gap-2 rounded-lg border border-destructive/40 bg-destructive/5 p-6 text-center"
    >
      <AlertCircle aria-hidden className="size-7 text-destructive" />
      <p className="font-medium">Something went wrong</p>
      <p className="max-w-lg text-sm text-muted-foreground">{errorMessage(error)}</p>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-1">
          <RotateCw aria-hidden /> Retry
        </Button>
      ) : null}
    </div>
  );
}

export function InlineError({ error }: { error: unknown }) {
  if (!error) return null;
  return (
    <p role="alert" className="flex items-start gap-2 rounded-md bg-destructive/10 p-2 text-sm text-destructive">
      <AlertCircle aria-hidden className="mt-0.5 size-4 shrink-0" />
      {errorMessage(error)}
    </p>
  );
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="rounded-lg border bg-card p-3" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex gap-3 py-2">
          {Array.from({ length: cols }, (_, c) => (
            <Skeleton key={c} className={cn("h-4", c === 0 ? "w-1/3" : "flex-1")} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function LoadMore({
  hasNextPage,
  isFetchingNextPage,
  fetchNextPage,
  shown,
}: {
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => unknown;
  shown: number;
}) {
  return (
    <div className="mt-3 flex items-center justify-between gap-2 text-sm text-muted-foreground">
      <span aria-live="polite">{shown.toLocaleString()} shown</span>
      {hasNextPage ? (
        <Button variant="outline" size="sm" onClick={() => fetchNextPage()} disabled={isFetchingNextPage}>
          {isFetchingNextPage ? "Loading…" : "Load more"}
        </Button>
      ) : (
        <span>End of list</span>
      )}
    </div>
  );
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function CopyButton({ text, label = "Copy", ariaLabel }: { text: string; label?: string; ariaLabel?: string }) {
  const [copied, setCopied] = React.useState(false);
  return (
    <Button
      variant="outline"
      size="sm"
      aria-label={copied ? "Copied" : (ariaLabel ?? label)}
      onClick={async () => {
        if (await copyText(text)) {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } else {
          toast.error("Could not copy to the clipboard");
        }
      }}
    >
      {copied ? <Check aria-hidden /> : <Copy aria-hidden />}
      {copied ? "Copied" : label}
    </Button>
  );
}

export function ExtLink({ href, children, className }: { href: string; children: React.ReactNode; className?: string }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noreferrer noopener"
      className={cn("inline-flex items-center gap-1 text-primary underline-offset-4 hover:underline", className)}
    >
      {children}
      <ExternalLink aria-hidden className="size-3" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}

/** Label + control + hint + error with the ARIA wiring done once. */
export function Field({
  id,
  label,
  hint,
  error,
  children,
  className,
}: {
  id: string;
  label: React.ReactNode;
  hint?: React.ReactNode;
  error?: string;
  children: React.ReactElement<Record<string, unknown>>;
  className?: string;
}) {
  const hintId = hint ? `${id}-hint` : undefined;
  const errId = error ? `${id}-error` : undefined;
  const control = React.cloneElement(children, {
    id,
    "aria-invalid": error ? true : undefined,
    "aria-describedby": [hintId, errId].filter(Boolean).join(" ") || undefined,
  });
  return (
    <div className={cn("flex flex-col gap-1.5", className)}>
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      {control}
      {hint ? (
        <p id={hintId} className="text-xs text-muted-foreground">
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={errId} className="text-xs font-medium text-destructive">
          {error}
        </p>
      ) : null}
    </div>
  );
}

export function KV({ items }: { items: [React.ReactNode, React.ReactNode][] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-4 gap-y-2 text-sm sm:grid-cols-[max-content_1fr]">
      {items.map(([k, v], i) => (
        <React.Fragment key={i}>
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0 break-words">{v}</dd>
        </React.Fragment>
      ))}
    </dl>
  );
}
