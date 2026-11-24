package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// UpstreamError wraps a failure of an external system the service called on
// the user's behalf (VCS provider, notifier). Entry points map it to 502.
type UpstreamError struct{ Err error }

func (e *UpstreamError) Error() string { return "upstream: " + e.Err.Error() }
func (e *UpstreamError) Unwrap() error { return e.Err }

// Pagination bounds shared by every list.
const (
	DefaultLimit = 50
	MaxLimit     = 500
)

// ClampLimit applies DefaultLimit and MaxLimit.
func ClampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultLimit
	case n > MaxLimit:
		return MaxLimit
	}
	return n
}

// New returns the service implementations backed by d. d.Catalog defaults to
// d.Store when the store implements store.Catalog; the services require one.
func New(d Deps) *Services {
	if d.Catalog == nil {
		if c, ok := d.Store.(store.Catalog); ok {
			d.Catalog = c
		}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	b := &base{d: d}
	return &Services{
		Dashboard:    &dashboardSvc{b},
		Targets:      &targetsSvc{b},
		AuthProfiles: &authProfilesSvc{b},
		Repos:        &reposSvc{b},
		Findings:     &findingsSvc{b},
		Runs:         &runsSvc{b},
		Jobs:         &jobsSvc{b},
		System:       &systemSvc{b},
	}
}

// base holds what every service shares.
type base struct{ d Deps }

func (b *base) now() time.Time { return b.d.Now().UTC() }

// audit appends an audit entry. The write it describes already happened, so a
// failure is logged rather than returned (the caller's change must not look failed).
func (b *base) audit(ctx context.Context, actor Actor, action, objType, objID string, details map[string]any) {
	e := &model.AuditEntry{
		At: b.now(), Actor: actorName(actor), Action: action,
		ObjectType: objType, ObjectID: objID, Details: details,
	}
	if err := b.d.Catalog.AppendAudit(ctx, e); err != nil {
		b.d.Logger.Error("audit append failed", "action", action, "object", objType+":"+objID, "err", err)
	}
}

func actorName(a Actor) string {
	if a == "" {
		return "anonymous"
	}
	return string(a)
}

// fieldErrors collects validation messages.
type fieldErrors map[string]string

func (f fieldErrors) add(field, msg string) {
	if _, ok := f[field]; !ok {
		f[field] = msg
	}
}

func (f fieldErrors) err() error {
	if len(f) == 0 {
		return nil
	}
	return &ValidationError{Fields: f}
}

func invalid(field, msg string) error { return &ValidationError{Fields: map[string]string{field: msg}} }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ignoreNotFound turns ErrNotFound into nil.
func ignoreNotFound(err error) error {
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
