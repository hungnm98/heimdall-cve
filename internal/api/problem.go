package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/hungnm98/heimdall-cve/internal/service"
)

// problem is an RFC 9457 problem details body.
type problem struct {
	Type   string            `json:"type,omitempty"`
	Title  string            `json:"title"`
	Status int               `json:"status"`
	Detail string            `json:"detail,omitempty"`
	Fields map[string]string `json:"fields,omitempty"`
}

func writeProblem(w http.ResponseWriter, p problem) {
	if p.Type == "" {
		p.Type = "about:blank"
	}
	if p.Title == "" {
		p.Title = http.StatusText(p.Status)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

func badRequest(w http.ResponseWriter, detail string, fields map[string]string) {
	writeProblem(w, problem{Status: http.StatusBadRequest, Title: "Invalid request", Detail: detail, Fields: fields})
}

// writeError maps service errors to problems. Unexpected errors are logged
// with the request id and answered without internal details.
func (h *handler) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *service.ValidationError
	var up *service.UpstreamError
	switch {
	case errors.As(err, &ve):
		writeProblem(w, problem{Status: http.StatusBadRequest, Title: "Invalid input", Detail: "one or more fields are invalid", Fields: ve.Fields})
	case errors.Is(err, service.ErrNotFound):
		writeProblem(w, problem{Status: http.StatusNotFound, Title: "Not found", Detail: err.Error()})
	case errors.Is(err, service.ErrReadOnly):
		writeProblem(w, problem{Status: http.StatusConflict, Title: "Read-only", Detail: "defined in the config file: edit the file instead"})
	case errors.Is(err, service.ErrConflict):
		writeProblem(w, problem{Status: http.StatusConflict, Title: "Conflict", Detail: err.Error()})
	case errors.Is(err, service.ErrUnavailable):
		writeProblem(w, problem{Status: http.StatusServiceUnavailable, Title: "Unavailable", Detail: err.Error()})
	case errors.As(err, &up):
		h.log.LogAttrs(r.Context(), slog.LevelWarn, "upstream error", slog.String("request_id", requestID(r.Context())), slog.Any("err", err))
		writeProblem(w, problem{Status: http.StatusBadGateway, Title: "Upstream error", Detail: up.Err.Error()})
	case errors.Is(err, context.Canceled):
		// Client went away; nothing useful can be written.
		w.WriteHeader(499)
	default:
		h.log.LogAttrs(r.Context(), slog.LevelError, "request failed", slog.String("request_id", requestID(r.Context())),
			slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.Any("err", err))
		writeProblem(w, problem{Status: http.StatusInternalServerError, Title: "Internal error",
			Detail: "the request failed; see the server log for request id " + requestID(r.Context())})
	}
}
