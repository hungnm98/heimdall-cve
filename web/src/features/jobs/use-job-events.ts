import * as React from "react";
import { API_BASE } from "@/api/client";
import type { Job, JobEvent } from "@/api/types";

export type StreamState = "connecting" | "open" | "reconnecting" | "done" | "error";

/**
 * Follows /jobs/{id}/events over Server-Sent Events.
 * - The browser reconnects by itself (sending Last-Event-ID) after transient drops.
 * - If the stream is closed for good (e.g. proxy error), we retry with backoff;
 *   events are de-duplicated by id because a fresh connection replays them.
 * - `done` closes the stream and hands over the final Job.
 */
export function useJobEvents(jobId: number, onDone: (job: Job) => void) {
  const [events, setEvents] = React.useState<JobEvent[]>([]);
  const [state, setState] = React.useState<StreamState>("connecting");
  const [attempt, setAttempt] = React.useState(0);
  const onDoneRef = React.useRef(onDone);
  React.useEffect(() => {
    onDoneRef.current = onDone;
  });

  React.useEffect(() => {
    setEvents([]);
    setState("connecting");
  }, [jobId]);

  React.useEffect(() => {
    let finished = false;
    let retry: ReturnType<typeof setTimeout> | undefined;
    const es = new EventSource(`${API_BASE}/jobs/${jobId}/events`);
    es.onopen = () => setState("open");
    es.addEventListener("progress", (e) => {
      let ev: JobEvent;
      try {
        ev = JSON.parse((e as MessageEvent<string>).data) as JobEvent;
      } catch {
        return;
      }
      setEvents((prev) => {
        if (prev.length && prev[prev.length - 1]!.id < ev.id) return [...prev, ev];
        if (prev.some((p) => p.id === ev.id)) return prev;
        return [...prev, ev].sort((a, b) => a.id - b.id);
      });
    });
    es.addEventListener("done", (e) => {
      finished = true;
      es.close();
      setState("done");
      try {
        onDoneRef.current(JSON.parse((e as MessageEvent<string>).data) as Job);
      } catch {
        // ignore malformed payload; the job query refetches anyway
      }
    });
    es.onerror = () => {
      if (finished) return;
      if (es.readyState === EventSource.CONNECTING) {
        setState("reconnecting");
      } else {
        setState("error");
        retry = setTimeout(() => setAttempt((a) => a + 1), Math.min(30_000, 1000 * 2 ** Math.min(attempt, 5)));
      }
    };
    return () => {
      finished = true;
      es.close();
      if (retry) clearTimeout(retry);
    };
  }, [jobId, attempt]);

  const reconnect = React.useCallback(() => setAttempt((a) => a + 1), []);
  return { events, state, reconnect };
}
