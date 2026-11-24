import * as React from "react";
import { cn } from "@/lib/utils";

const field =
  "w-full min-w-0 rounded-md border border-input bg-background px-3 text-sm shadow-xs placeholder:text-muted-foreground focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-50 aria-[invalid=true]:border-destructive";

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, type = "text", ...props }, ref) => (
    <input ref={ref} type={type} className={cn(field, "h-9 py-1", className)} {...props} />
  ),
);
Input.displayName = "Input";

export const Textarea = React.forwardRef<
  HTMLTextAreaElement,
  React.TextareaHTMLAttributes<HTMLTextAreaElement>
>(({ className, ...props }, ref) => (
  <textarea ref={ref} className={cn(field, "min-h-20 py-2", className)} {...props} />
));
Textarea.displayName = "Textarea";

/** Native select styled like the inputs: accessible and keyboard friendly by default. */
export const NativeSelect = React.forwardRef<
  HTMLSelectElement,
  React.SelectHTMLAttributes<HTMLSelectElement>
>(({ className, ...props }, ref) => (
  <select ref={ref} className={cn(field, "h-9 py-1 pr-8", className)} {...props} />
));
NativeSelect.displayName = "NativeSelect";

export function Label({ className, ...props }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn("text-sm font-medium leading-none", className)} {...props} />;
}

export function Checkbox({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      type="checkbox"
      className={cn("size-4 rounded border-input accent-primary", className)}
      {...props}
    />
  );
}
