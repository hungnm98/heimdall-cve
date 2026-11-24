package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/service"
)

type ctxKey int

const (
	ctxRequestID ctxKey = iota
	ctxActor
)

func requestID(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestID).(string)
	return id
}

func actorFrom(ctx context.Context) service.Actor {
	if a, ok := ctx.Value(ctxActor).(service.Actor); ok {
		return a
	}
	return "anonymous"
}

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// withRequestID reuses a well-formed incoming X-Request-ID or creates one.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID.MatchString(id) {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID, id)))
	})
}

// SecurityHeaders sets the headers every response carries (API and SPA).
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// statusRecorder captures the status and size for the access log. It keeps
// Flush and Unwrap working so SSE and http.ResponseController still function.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += int64(n)
	return n, err
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// withAccessLog logs one structured line per request and recovers panics.
func withAccessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		defer func() {
			if p := recover(); p != nil {
				if p == http.ErrAbortHandler {
					panic(p)
				}
				log.LogAttrs(r.Context(), slog.LevelError, "panic", slog.String("request_id", requestID(r.Context())),
					slog.Any("panic", p), slog.String("stack", string(debug.Stack())))
				if rec.status == 0 {
					writeProblem(rec, problem{Status: http.StatusInternalServerError, Title: "Internal error",
						Detail: "see the server log for request id " + requestID(r.Context())})
				}
			}
			log.LogAttrs(r.Context(), slog.LevelInfo, "http",
				slog.String("request_id", requestID(r.Context())), slog.String("method", r.Method),
				slog.String("path", r.URL.Path), slog.Int("status", rec.status), slog.Int64("bytes", rec.bytes),
				slog.Duration("duration", time.Since(start)), slog.String("actor", string(actorFrom(r.Context()))))
		}()
		next.ServeHTTP(rec, r)
	})
}

// withActor stores the acting user: the trusted proxy header when configured
// and present, otherwise "anonymous".
func withActor(header string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		actor := service.Actor("anonymous")
		if header != "" {
			if v := strings.TrimSpace(r.Header.Get(header)); v != "" {
				if len(v) > 256 {
					v = v[:256]
				}
				actor = service.Actor(v)
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxActor, actor)))
	})
}

func isWrite(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// withCSRFGuard rejects writes without Content-Type application/json and
// X-Heimdall-Request: 1. Browsers cannot send either cross-origin without a
// CORS preflight, which this server never approves.
func withCSRFGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isWrite(r.Method) {
			mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || mt != "application/json" || r.Header.Get("X-Heimdall-Request") != "1" {
				writeProblem(w, problem{Status: http.StatusForbidden, Title: "Forbidden",
					Detail: "writes require Content-Type: application/json and X-Heimdall-Request: 1"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
