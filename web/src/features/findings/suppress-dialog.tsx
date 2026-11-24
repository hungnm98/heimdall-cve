import * as React from "react";
import { toast } from "sonner";
import { splitFieldErrors } from "@/api/problem";
import { useSuppressFinding } from "@/api/queries";
import { Field, InlineError } from "@/components/common";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input, Textarea } from "@/components/ui/input";
import { addDays, isoDate } from "@/lib/time";

export const MAX_SUPPRESS_DAYS = 365;
export const DEFAULT_SUPPRESS_DAYS = 90;

export interface SuppressForm {
  reason: string;
  /** yyyy-mm-dd, interpreted as 00:00 UTC */
  expires: string;
}

/** Client-side validation mirroring the API: reason 3–1000 chars, expiry in the future and ≤ 1 year. */
export function validateSuppress(form: SuppressForm, now = new Date()): Partial<Record<keyof SuppressForm, string>> {
  const errors: Partial<Record<keyof SuppressForm, string>> = {};
  const reason = form.reason.trim();
  if (reason.length < 3) errors.reason = "Explain why this finding is accepted (at least 3 characters).";
  else if (reason.length > 1000) errors.reason = "Keep the reason under 1000 characters.";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(form.expires)) {
    errors.expires = "Choose an expiry date.";
  } else {
    const exp = Date.parse(`${form.expires}T00:00:00Z`);
    if (Number.isNaN(exp) || exp <= now.getTime()) errors.expires = "The expiry date must be in the future.";
    else if (form.expires > isoDate(addDays(now, MAX_SUPPRESS_DAYS)))
      errors.expires = "Suppressions can last at most one year.";
  }
  return errors;
}

export function SuppressDialog({
  findingId,
  open,
  onOpenChange,
}: {
  findingId: string;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const now = React.useMemo(() => new Date(), []);
  const [form, setForm] = React.useState<SuppressForm>({
    reason: "",
    expires: isoDate(addDays(now, DEFAULT_SUPPRESS_DAYS)),
  });
  const [errors, setErrors] = React.useState<Partial<Record<keyof SuppressForm, string>>>({});
  const mutation = useSuppressFinding();

  React.useEffect(() => {
    if (!open) {
      setErrors({});
      mutation.reset();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    const errs = validateSuppress(form);
    setErrors(errs);
    if (Object.keys(errs).length) return;
    mutation.mutate(
      { id: findingId, body: { reason: form.reason.trim(), expires_at: `${form.expires}T00:00:00Z` } },
      {
        onSuccess: () => {
          toast.success(`Finding suppressed until ${form.expires}`);
          onOpenChange(false);
          setForm((f) => ({ ...f, reason: "" }));
        },
        onError: (err) => {
          const { fields } = splitFieldErrors(err, ["reason", "expires_at"]);
          setErrors({ reason: fields.reason, expires: fields.expires_at });
        },
      },
    );
  };

  const { other } = splitFieldErrors(mutation.error, ["reason", "expires_at"]);
  const showGeneric = mutation.isError && (Object.keys(splitFieldErrors(mutation.error, ["reason", "expires_at"]).fields).length === 0 || Object.keys(other).length > 0);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Suppress finding</DialogTitle>
            <DialogDescription>
              The finding is hidden from reports until the expiry date, then reopens automatically. The reason is recorded in the audit log.
            </DialogDescription>
          </DialogHeader>
          <Field id="suppress-reason" label="Reason" error={errors.reason} hint="Why is this risk accepted? Link a ticket if there is one.">
            <Textarea
              value={form.reason}
              maxLength={1000}
              onChange={(e) => setForm({ ...form, reason: e.target.value })}
              placeholder="e.g. Vulnerable function is never called; tracked in SEC-123"
              required
            />
          </Field>
          <Field id="suppress-expires" label="Expires on (UTC)" error={errors.expires} hint="At most one year from today.">
            <Input
              type="date"
              value={form.expires}
              min={isoDate(addDays(now, 1))}
              max={isoDate(addDays(now, MAX_SUPPRESS_DAYS))}
              onChange={(e) => setForm({ ...form, expires: e.target.value })}
              required
            />
          </Field>
          {showGeneric ? <InlineError error={mutation.error} /> : null}
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending ? "Suppressing…" : "Suppress"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
