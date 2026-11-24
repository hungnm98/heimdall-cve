import { Switch as SW, Tabs as T } from "radix-ui";
import type * as React from "react";
import { cn } from "@/lib/utils";

export function Skeleton({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div aria-hidden className={cn("animate-pulse rounded-md bg-muted", className)} {...props} />;
}

export function Switch({ className, ...props }: React.ComponentProps<typeof SW.Root>) {
  return (
    <SW.Root
      className={cn(
        "peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border-2 border-transparent bg-input transition-colors data-[state=checked]:bg-primary disabled:cursor-not-allowed disabled:opacity-50",
        className,
      )}
      {...props}
    >
      <SW.Thumb className="pointer-events-none block size-4 rounded-full bg-background shadow-sm transition-transform data-[state=checked]:translate-x-4" />
    </SW.Root>
  );
}

export const Tabs = T.Root;

export function TabsList({ className, ...props }: React.ComponentProps<typeof T.List>) {
  return (
    <T.List
      className={cn(
        "inline-flex h-9 max-w-full items-center gap-1 overflow-x-auto rounded-lg bg-muted p-1 text-muted-foreground",
        className,
      )}
      {...props}
    />
  );
}

export function TabsTrigger({ className, ...props }: React.ComponentProps<typeof T.Trigger>) {
  return (
    <T.Trigger
      className={cn(
        "inline-flex cursor-pointer items-center gap-1.5 whitespace-nowrap rounded-md px-3 py-1 text-sm font-medium transition-colors data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm",
        className,
      )}
      {...props}
    />
  );
}

export function TabsContent({ className, ...props }: React.ComponentProps<typeof T.Content>) {
  return <T.Content className={cn("mt-4", className)} {...props} />;
}
