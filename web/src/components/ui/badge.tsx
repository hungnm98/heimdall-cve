import { cva, type VariantProps } from "class-variance-authority";
import type * as React from "react";
import { cn } from "@/lib/utils";

export const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap [&_svg]:size-3",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground",
        secondary: "border-transparent bg-secondary text-secondary-foreground",
        outline: "text-foreground",
        destructive: "border-transparent bg-destructive text-destructive-foreground",
        success:
          "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-200",
        warning:
          "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200",
        danger:
          "border-red-300 bg-red-50 text-red-900 dark:border-red-800 dark:bg-red-950 dark:text-red-200",
        info: "border-sky-300 bg-sky-50 text-sky-900 dark:border-sky-800 dark:bg-sky-950 dark:text-sky-200",
        purple:
          "border-violet-300 bg-violet-50 text-violet-900 dark:border-violet-800 dark:bg-violet-950 dark:text-violet-200",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}
