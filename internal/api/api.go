// Package api is the REST API of `heimdall serve` (contract: api/openapi.yaml).
// Handlers only parse input, call internal/service and render DTOs.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/service"
)

// Prefix is where the API is mounted.
const Prefix = "/api/v1"

// MaxBodyBytes bounds request bodies.
const MaxBodyBytes = 1 << 20

// Options configures the handler.
type Options struct {
	// TrustedUserHeader names a header set by an SSO proxy (e.g. X-Forwarded-Email);
	// its value is the audit actor. Empty: every actor is "anonymous".
	TrustedUserHeader string
	Logger            *slog.Logger
	Version           string
	JobsBackend       string
	Providers         []string
	AuthTypes         []string
	// Fallback serves every path outside the API (the embedded web UI). Nil = 404.
	Fallback http.Handler
	// Done stops open SSE streams when closed (server shutdown). Optional.
	Done <-chan struct{}
	// EventPoll and Heartbeat tune SSE (defaults 1s and 15s).
	EventPoll time.Duration
	Heartbeat time.Duration
}

type handler struct {
	s    *service.Services
	opts Options
	log  *slog.Logger
}

// NewHandler returns the full HTTP handler: /api/v1/*, /healthz, /readyz and
// opts.Fallback for everything else, wrapped in request id, security
// headers, actor, access log, panic recovery and (for the API) the CSRF guard.
func NewHandler(s *service.Services, opts Options) http.Handler {
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opts.EventPoll <= 0 {
		opts.EventPoll = time.Second
	}
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = 15 * time.Second
	}
	h := &handler{s: s, opts: opts, log: opts.Logger}

	api := http.NewServeMux()
	route := func(pattern string, fn http.HandlerFunc) {
		method, path, _ := strings.Cut(pattern, " ")
		api.HandleFunc(method+" "+Prefix+path, fn)
	}
	route("GET /meta", h.getMeta)
	route("GET /dashboard", h.getDashboard)
	route("GET /targets", h.listTargets)
	route("POST /targets", h.createTarget)
	route("POST /targets/preview", h.previewTarget)
	route("GET /targets/{id}", h.getTarget)
	route("PATCH /targets/{id}", h.updateTarget)
	route("DELETE /targets/{id}", h.deleteTarget)
	route("GET /auth-profiles", h.listAuthProfiles)
	route("POST /auth-profiles", h.createAuthProfile)
	route("PATCH /auth-profiles/{name}", h.updateAuthProfile)
	route("DELETE /auth-profiles/{name}", h.deleteAuthProfile)
	route("POST /auth-profiles/{name}/test", h.testAuthProfile)
	route("GET /repos", h.listRepos)
	route("GET /repos/{owner}/{name}", h.getRepo)
	route("GET /findings", h.listFindings)
	route("GET /findings/{id}", h.getFinding)
	route("PUT /findings/{id}/suppression", h.suppressFinding)
	route("DELETE /findings/{id}/suppression", h.unsuppressFinding)
	route("GET /runs", h.listRuns)
	route("GET /runs/{id}", h.getRun)
	route("GET /runs/{id}/diff", h.diffRun)
	route("GET /jobs", h.listJobs)
	route("POST /jobs", h.triggerJob)
	route("GET /jobs/{id}", h.getJob)
	route("POST /jobs/{id}/cancel", h.cancelJob)
	route("GET /jobs/{id}/events", h.jobEvents)
	route("GET /sources", h.listSources)
	route("GET /notifiers", h.listNotifiers)
	route("POST /notifiers/{name}/test", h.testNotifier)
	route("GET /audit", h.listAudit)
	api.HandleFunc(Prefix+"/", func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, problem{Status: http.StatusNotFound, Title: "Not found", Detail: "no such API endpoint"})
	})

	root := http.NewServeMux()
	root.Handle(Prefix+"/", withCSRFGuard(api))
	root.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	root.HandleFunc("GET /readyz", h.readyz)
	if opts.Fallback != nil {
		root.Handle("/", opts.Fallback)
	}
	return withRequestID(SecurityHeaders(withActor(opts.TrustedUserHeader, withAccessLog(h.log, root))))
}

// readyz checks that the store answers.
func (h *handler) readyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if _, err := h.s.System.Audit(ctx, 0, 1); err != nil {
		h.log.Warn("readiness check failed", "err", err)
		writeProblem(w, problem{Status: http.StatusServiceUnavailable, Title: "Not ready", Detail: "store unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decode reads a JSON body (max MaxBodyBytes). An empty body decodes as {}.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeProblem(w, problem{Status: http.StatusRequestEntityTooLarge, Title: "Body too large", Detail: "request bodies are limited to 1 MiB"})
			return false
		}
		badRequest(w, "malformed JSON body: "+err.Error(), nil)
		return false
	}
	return true
}

// pathID parses an integer path value; a malformed id cannot exist (404).
func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeProblem(w, problem{Status: http.StatusNotFound, Title: "Not found", Detail: "no such id"})
		return 0, false
	}
	return id, true
}

// query helpers: a malformed value is a 400 with the parameter as field.

type queryParser struct {
	r      *http.Request
	fields map[string]string
}

func newQuery(r *http.Request) *queryParser { return &queryParser{r: r, fields: map[string]string{}} }

func (q *queryParser) str(name string) string { return q.r.URL.Query().Get(name) }

func (q *queryParser) int64(name string) int64 {
	v := q.str(name)
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		q.fields[name] = "must be a non-negative integer"
	}
	return n
}

func (q *queryParser) limit() int { return int(q.int64("limit")) }

func (q *queryParser) bool(name string) bool {
	v := q.str(name)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		q.fields[name] = "must be true or false"
	}
	return b
}

func (q *queryParser) time(name string) time.Time {
	v := q.str(name)
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		q.fields[name] = "must be an RFC 3339 date-time"
	}
	return t
}

// cursorID parses a numeric keyset cursor.
func (q *queryParser) cursorID() int64 {
	v := q.str("cursor")
	if v == "" {
		return 0
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n <= 0 {
		q.fields["cursor"] = "invalid cursor"
	}
	return n
}

func (q *queryParser) ok(w http.ResponseWriter) bool {
	if len(q.fields) > 0 {
		badRequest(w, "invalid query parameters", q.fields)
		return false
	}
	return true
}
