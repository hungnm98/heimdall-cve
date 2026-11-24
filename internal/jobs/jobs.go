// Package jobs is the port for background job backends (asynq + Valkey in
// production, inline for the CLI and tests).
//
// The queue only carries job IDs. The job record (scope, status, progress)
// lives in store.Catalog, so the UI and audit never depend on the queue's own
// retention, and a backend can be swapped without losing history.
package jobs

import (
	"context"
	"errors"

	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
)

// ErrNotFound is returned by Cancel for a job the backend does not know.
var ErrNotFound = errors.New("job not found in queue")

// Handler processes one scan job. It must be idempotent: a backend may
// deliver a job again after a crash or retry, so the handler re-reads the
// job record and does nothing for a job that is already finished or canceled.
// The ctx is canceled when the job is canceled or the worker shuts down.
type Handler interface {
	HandleScan(ctx context.Context, jobID int64) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, jobID int64) error

// HandleScan implements Handler.
func (f HandlerFunc) HandleScan(ctx context.Context, jobID int64) error { return f(ctx, jobID) }

// Backend enqueues jobs and runs workers.
type Backend interface {
	Name() string
	// Enqueue schedules jobID. Enqueuing an ID that is already queued or
	// running is a no-op (deduplicated by job ID).
	Enqueue(ctx context.Context, jobID int64) error
	// Cancel stops a queued or running job; its handler ctx is canceled.
	Cancel(ctx context.Context, jobID int64) error
	// Run processes jobs with h until ctx is done, then drains in-flight jobs.
	Run(ctx context.Context, h Handler) error
	Close() error
}

// Factory builds a Backend from the `jobs` config block.
type Factory = func(cfg plugin.Config, deps plugin.Deps) (Backend, error)

// Registry holds backends ("inline", "asynq").
var Registry = registry.New[Factory]("jobs")
