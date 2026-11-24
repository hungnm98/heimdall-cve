package api

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const sseBatch = 500

// wantsEventStream reports whether the client asked for SSE.
func wantsEventStream(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		if mt, _, err := mime.ParseMediaType(strings.TrimSpace(part)); err == nil && mt == "text/event-stream" {
			return true
		}
	}
	return false
}

// jobEvents serves GET /jobs/{id}/events: an SSE stream with Accept:
// text/event-stream, otherwise a JSON page.
func (h *handler) jobEvents(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	q := newQuery(r)
	after, limit := q.int64("after_id"), q.limit()
	if !q.ok(w) {
		return
	}
	if !wantsEventStream(r) {
		evs, err := h.s.Jobs.Events(r.Context(), id, after, limit)
		if err != nil {
			h.writeError(w, r, err)
			return
		}
		writeJSON(w, http.StatusOK, list(evs, "", toJobEvent))
		return
	}
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			after = n
		}
	}
	h.streamJob(w, r, id, after)
}

func (h *handler) streamJob(w http.ResponseWriter, r *http.Request, id, after int64) {
	ctx := r.Context()
	// Fail with a problem (not a broken stream) for an unknown job.
	if _, err := h.s.Jobs.Get(ctx, id); err != nil {
		h.writeError(w, r, err)
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{}) // streams outlive the server write timeout
	hd := w.Header()
	hd.Set("Content-Type", "text/event-stream")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Accel-Buffering", "no") // disable proxy buffering (nginx)
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}

	poll := time.NewTicker(h.opts.EventPoll)
	defer poll.Stop()
	heartbeat := time.NewTicker(h.opts.Heartbeat)
	defer heartbeat.Stop()
	for {
		// Read the job before its events: every event written before the job
		// finished is then guaranteed to be sent before `done`.
		job, err := h.s.Jobs.Get(ctx, id)
		if err != nil {
			h.streamError(w, r, err)
			return
		}
		for {
			evs, err := h.s.Jobs.Events(ctx, id, after, sseBatch)
			if err != nil {
				h.streamError(w, r, err)
				return
			}
			for _, e := range evs {
				data, _ := json.Marshal(toJobEvent(e))
				if _, err := fmt.Fprintf(w, "id: %d\nevent: progress\ndata: %s\n\n", e.ID, data); err != nil {
					return
				}
				after = e.ID
			}
			if len(evs) < sseBatch {
				break
			}
		}
		if !job.Status.Active() {
			data, _ := json.Marshal(toJob(*job))
			_, _ = fmt.Fprintf(w, "event: done\ndata: %s\n\n", data)
			_ = rc.Flush()
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-h.opts.Done:
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": keep-alive\n\n"); err != nil {
				return
			}
		case <-poll.C:
		}
	}
}

func (h *handler) streamError(w http.ResponseWriter, r *http.Request, err error) {
	if r.Context().Err() != nil {
		return
	}
	h.log.Error("job event stream failed", "request_id", requestID(r.Context()), "err", err)
	_, _ = fmt.Fprint(w, "event: error\ndata: {\"title\":\"stream failed\"}\n\n")
}
