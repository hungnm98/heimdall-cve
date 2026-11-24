import { useQueryClient } from "@tanstack/react-query";
import { useRouter } from "@tanstack/react-router";
import * as React from "react";
import { toast } from "sonner";
import { api } from "@/api/client";
import { errorMessage, toApiError } from "@/api/problem";
import { keys } from "@/api/queries";
import type { JobRequest } from "@/api/types";

/**
 * Triggers a scan job and toasts a link to its live log. Not tied to the
 * calling component's lifetime, so it also works from toast actions.
 */
export function useScan() {
  const qc = useQueryClient();
  const router = useRouter();
  const [isPending, setPending] = React.useState(false);

  const mutate = React.useCallback(
    async (req: JobRequest, what = "Scan") => {
      setPending(true);
      try {
        const { data, error, response } = await api.POST("/jobs", { body: req });
        if (!response.ok || !data) throw toApiError(response.status, response.statusText, error);
        const existing = response.status === 200;
        toast.success(existing ? `${what} is already in progress (job #${data.id})` : `${what} queued as job #${data.id}`, {
          action: { label: "View log", onClick: () => void router.navigate({ to: "/jobs/$id", params: { id: String(data.id) } }) },
        });
        void qc.invalidateQueries({ queryKey: keys.jobs });
        void qc.invalidateQueries({ queryKey: keys.dashboard });
        return data;
      } catch (err) {
        toast.error(errorMessage(err));
        return undefined;
      } finally {
        setPending(false);
      }
    },
    [qc, router],
  );

  return { mutate, isPending };
}

export function useScanAll() {
  const scan = useScan();
  return { isPending: scan.isPending, mutate: () => void scan.mutate({}, "Scan of all enabled targets") };
}
