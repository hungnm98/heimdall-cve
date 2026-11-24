import { XIcon } from "lucide-react";
import { AlertDialog as AD, Dialog as D } from "radix-ui";
import type * as React from "react";
import { cn } from "@/lib/utils";
import { buttonVariants } from "./button";

// Radix Dialog traps focus, restores it on close and closes on ESC.

export const Dialog = D.Root;
export const DialogTrigger = D.Trigger;
export const DialogClose = D.Close;

const overlay = "fixed inset-0 z-50 bg-black/50";
const panel =
  "fixed left-1/2 top-1/2 z-50 grid max-h-[90dvh] w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-lg border bg-popover p-5 text-popover-foreground shadow-lg";

export function DialogContent({
  className,
  children,
  ...props
}: React.ComponentProps<typeof D.Content>) {
  return (
    <D.Portal>
      <D.Overlay className={overlay} />
      <D.Content className={cn(panel, className)} {...props}>
        {children}
        <D.Close
          className="absolute right-3 top-3 rounded-sm p-1 opacity-70 hover:opacity-100"
          aria-label="Close"
        >
          <XIcon className="size-4" />
        </D.Close>
      </D.Content>
    </D.Portal>
  );
}

export function DialogHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("flex flex-col gap-1.5 pr-6", className)} {...props} />;
}

export function DialogFooter({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn("flex flex-col-reverse gap-2 sm:flex-row sm:justify-end", className)}
      {...props}
    />
  );
}

export function DialogTitle({ className, ...props }: React.ComponentProps<typeof D.Title>) {
  return <D.Title className={cn("text-lg font-semibold", className)} {...props} />;
}

export function DialogDescription({
  className,
  ...props
}: React.ComponentProps<typeof D.Description>) {
  return <D.Description className={cn("text-sm text-muted-foreground", className)} {...props} />;
}

/** Side panel variant, used for the mobile navigation. */
export function SheetContent({
  className,
  children,
  ...props
}: React.ComponentProps<typeof D.Content>) {
  return (
    <D.Portal>
      <D.Overlay className={overlay} />
      <D.Content
        className={cn(
          "fixed inset-y-0 left-0 z-50 flex w-72 max-w-[85vw] flex-col border-r bg-background shadow-lg",
          className,
        )}
        {...props}
      >
        {children}
        <D.Close
          className="absolute right-3 top-3 rounded-sm p-1 opacity-70 hover:opacity-100"
          aria-label="Close navigation"
        >
          <XIcon className="size-4" />
        </D.Close>
      </D.Content>
    </D.Portal>
  );
}

// ---- confirm dialog ----------------------------------------------------------

export interface ConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description: React.ReactNode;
  confirmLabel: string;
  destructive?: boolean;
  pending?: boolean;
  onConfirm: () => void;
}

export function ConfirmDialog({
  open,
  onOpenChange,
  title,
  description,
  confirmLabel,
  destructive,
  pending,
  onConfirm,
}: ConfirmDialogProps) {
  return (
    <AD.Root open={open} onOpenChange={onOpenChange}>
      <AD.Portal>
        <AD.Overlay className={overlay} />
        <AD.Content className={panel}>
          <AD.Title className="text-lg font-semibold">{title}</AD.Title>
          <AD.Description className="text-sm text-muted-foreground">{description}</AD.Description>
          <div className="flex flex-col-reverse gap-2 sm:flex-row sm:justify-end">
            <AD.Cancel className={buttonVariants({ variant: "outline" })}>Cancel</AD.Cancel>
            <AD.Action
              className={buttonVariants({ variant: destructive ? "destructive" : "default" })}
              disabled={pending}
              onClick={(e) => {
                // Keep the dialog open until the caller closes it (after the request).
                e.preventDefault();
                onConfirm();
              }}
            >
              {confirmLabel}
            </AD.Action>
          </div>
        </AD.Content>
      </AD.Portal>
    </AD.Root>
  );
}
