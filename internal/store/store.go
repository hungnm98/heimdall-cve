// Package store is the port for persistence: scan history, findings across
// runs, repo state for incremental scans and notification idempotency.
//
// Behaviour every implementation must follow is pinned by storetest.Run.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
)

// ErrNotFound is returned for a missing run or finding.
var ErrNotFound = errors.New("not found")

// FindingFilter selects findings. Zero fields do not filter.
type FindingFilter struct {
	Repo        string
	Kind        model.FindingKind
	Status      model.FindingStatus
	MinSeverity model.Severity
	InKEV       bool
	// Branch: only findings of this extra branch ("" = no branch filter).
	Branch string
	// DefaultBranchOnly: only default-branch findings (dashboards, counts).
	DefaultBranchOnly bool
	NewSince          time.Time // FirstSeen >= NewSince
	// Query matches a package name substring (case-insensitive) or an exact
	// advisory ID / alias (CVE-..., GHSA-..., GO-...).
	Query string
	// Sort and Order choose the order (see FindingSort); zero values mean
	// severity desc (worst first, then repo, then id).
	Sort  FindingSort
	Order SortOrder
	// After is an opaque keyset cursor (FindingCursor of the last item of the
	// previous page, for the same Sort and Order).
	After string
	Limit int
}

// Store persists Heimdall state. Implementations must be safe for concurrent use.
type Store interface {
	Migrate(ctx context.Context) error
	Close() error

	// StartRun inserts run with status running and sets run.ID.
	StartRun(ctx context.Context, run *model.ScanRun) error
	// FinishRun updates a run's end state.
	FinishRun(ctx context.Context, run *model.ScanRun) error
	GetRun(ctx context.Context, id int64) (*model.ScanRun, error)
	// LatestRun returns the newest finished run with ID < before (before=0: any).
	LatestRun(ctx context.Context, before int64) (*model.ScanRun, error)
	ListRuns(ctx context.Context, limit int) ([]model.ScanRun, error)

	// RecordFindings stores what run found in the scopes it scanned
	// (model.ScopeKey: "owner/name" = default branch, "owner/name@branch"):
	//  - a finding seen before keeps FirstSeen; LastSeen = at; fixed or
	//    removed → reopened
	//  - a suppressed finding stays suppressed
	//  - an open finding of a scope in scanned that is absent becomes fixed
	//  - scopes not in scanned are untouched (a failed repo is not "fixed")
	//  - findings sharing an ID within one call are stored once (last wins)
	// It returns the change relative to the previous state: New holds first
	// sightings and reopened findings, never suppressed ones.
	RecordFindings(ctx context.Context, runID int64, scanned []string, findings []model.Finding, at time.Time) (*model.Diff, error)
	ListFindings(ctx context.Context, f FindingFilter) ([]model.Finding, error)
	GetFinding(ctx context.Context, id string) (*model.Finding, error)
	SetFindingStatus(ctx context.Context, id string, status model.FindingStatus) error
	// DiffRuns compares the findings recorded by two runs. Fixed only counts
	// repos that run `to` scanned.
	DiffRuns(ctx context.Context, from, to int64) (*model.Diff, error)

	// MarkBranchesRemoved sets open findings of repo's extra branches that
	// are not in keep to StatusRemoved (branch deleted or no longer scanned)
	// and returns them.
	MarkBranchesRemoved(ctx context.Context, repo string, keep []string) ([]model.Finding, error)

	// GetRepoState returns ErrNotFound when the repo/ref was never scanned.
	GetRepoState(ctx context.Context, repo, ref string) (*model.RepoState, error)
	PutRepoState(ctx context.Context, s model.RepoState) error
	// ListRepoStates returns the scanned refs of a repo, by ref.
	ListRepoStates(ctx context.Context, repo string) ([]model.RepoState, error)

	// MarkNotified records an idempotency key (e.g. "finding.new:<id>").
	// It returns true the first time a key is seen, false afterwards.
	MarkNotified(ctx context.Context, key string, at time.Time) (bool, error)
}

// Snapshots caches parsed dependency graphs per commit (optional capability
// of a Store, detected with a type assertion). fingerprint identifies the
// parser build and scan settings; data is opaque to the store.
type Snapshots interface {
	// GetSnapshot returns ErrNotFound when there is none; a hit refreshes its use time.
	GetSnapshot(ctx context.Context, repo, sha, fingerprint string, at time.Time) ([]byte, error)
	// PutSnapshot stores data and prunes snapshots unused since before pruneBefore.
	PutSnapshot(ctx context.Context, repo, sha, fingerprint string, data []byte, at, pruneBefore time.Time) error
}

// Factory builds a Store from its config block (dsn...).
type Factory = func(cfg plugin.Config, deps plugin.Deps) (Store, error)

// Registry holds store drivers ("postgres", "memory").
var Registry = registry.New[Factory]("store")
