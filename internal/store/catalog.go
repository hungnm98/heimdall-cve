package store

import (
	"context"
	"errors"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/secret"
)

// ErrConflict is returned when a write would break a uniqueness or reference
// rule (duplicate name, deleting a profile still used by a target...).
var ErrConflict = errors.New("conflict")

// Catalog is an optional store capability holding what the web app manages:
// targets, auth profiles, sealed secrets, the cached repo list, jobs and the
// audit log. Detect it with a type assertion: `cat, ok := s.(store.Catalog)`.
// Behaviour is pinned by storetest.RunCatalog.
type Catalog interface {
	// Auth profiles, unique by name.
	ListAuthProfiles(ctx context.Context) ([]model.AuthProfile, error)
	GetAuthProfile(ctx context.Context, name string) (*model.AuthProfile, error)
	// SaveAuthProfile inserts (ID == 0) or updates by ID; sets ID and timestamps.
	// A different profile with the same name → ErrConflict.
	SaveAuthProfile(ctx context.Context, p *model.AuthProfile) error
	// DeleteAuthProfile → ErrConflict while a target references it.
	DeleteAuthProfile(ctx context.Context, name string) error

	// Sealed secrets.
	// SaveSecret inserts (ID == 0) or replaces by ID; sets ID.
	SaveSecret(ctx context.Context, s *SecretRecord) error
	GetSecret(ctx context.Context, id int64) (*SecretRecord, error)
	ListSecrets(ctx context.Context) ([]SecretRecord, error)
	DeleteSecret(ctx context.Context, id int64) error

	// Targets.
	ListTargets(ctx context.Context, f TargetFilter) ([]model.TargetSpec, error)
	GetTarget(ctx context.Context, id int64) (*model.TargetSpec, error)
	// SaveTarget inserts (ID == 0) or updates by ID; sets ID and timestamps.
	// Unknown auth profile → ErrConflict.
	SaveTarget(ctx context.Context, t *model.TargetSpec) error
	DeleteTarget(ctx context.Context, id int64) error
	// DueTargets returns enabled targets with NextRunAt <= now, oldest first.
	DueTargets(ctx context.Context, now time.Time) ([]model.TargetSpec, error)
	// DuePolls returns enabled targets with NextPollAt <= now, oldest first.
	DuePolls(ctx context.Context, now time.Time) ([]model.TargetSpec, error)

	// Cached repo list.
	// UpsertRepos records the repos a target listed at `at`.
	UpsertRepos(ctx context.Context, targetID int64, repos []model.Repo, at time.Time) error
	ListRepos(ctx context.Context, f RepoFilter) ([]model.RepoRecord, error)
	GetRepo(ctx context.Context, fullName string) (*model.RepoRecord, error)
	// MarkRepoScanned stores the HEAD scanned (also used for incremental scans).
	MarkRepoScanned(ctx context.Context, fullName, headSHA string, at time.Time) error

	// Jobs.
	// CreateJob inserts a job, unless an active job (queued/running) with the
	// same scope (TargetID, Repo) exists: then j is filled with that job and
	// created is false. This makes "scan now" idempotent.
	CreateJob(ctx context.Context, j *model.Job) (created bool, err error)
	GetJob(ctx context.Context, id int64) (*model.Job, error)
	ListJobs(ctx context.Context, f JobFilter) ([]model.Job, error)
	// UpdateJob saves status, run id, attempts, error and timestamps.
	UpdateJob(ctx context.Context, j *model.Job) error
	AppendJobEvent(ctx context.Context, e *model.JobEvent) error
	// ListJobEvents returns events with ID > afterID, oldest first (SSE resume).
	ListJobEvents(ctx context.Context, jobID, afterID int64, limit int) ([]model.JobEvent, error)

	// Suppressions. SaveSuppression upserts by FindingID and sets the finding's
	// status to suppressed (ErrNotFound for an unknown finding); DeleteSuppression
	// removes it and reopens the finding.
	SaveSuppression(ctx context.Context, s *model.Suppression) error
	GetSuppression(ctx context.Context, findingID string) (*model.Suppression, error)
	DeleteSuppression(ctx context.Context, findingID string) error
	// ExpiredSuppressions returns suppressions with ExpiresAt <= now.
	ExpiredSuppressions(ctx context.Context, now time.Time) ([]model.Suppression, error)

	// Audit log (append-only).
	AppendAudit(ctx context.Context, e *model.AuditEntry) error
	// ListAudit returns newest first, entries with ID < beforeID (0 = newest).
	ListAudit(ctx context.Context, beforeID int64, limit int) ([]model.AuditEntry, error)
}

// SecretRecord is a sealed secret as stored.
type SecretRecord struct {
	ID          int64
	Kind        string // token | private_key | ssh_key | webhook_url ...
	Sealed      secret.Sealed
	Fingerprint string
	CreatedAt   time.Time
	RotatedAt   *time.Time
}

// TargetFilter selects targets. Zero fields do not filter.
type TargetFilter struct {
	Enabled *bool
	Origin  model.Origin
}

// RepoFilter selects cached repos, ordered by full name unless Sort says
// otherwise (see RepoSort).
type RepoFilter struct {
	TargetID int64
	Query    string // substring of the full name
	Sort     RepoSort
	Order    SortOrder
	After    string // keyset cursor: RepoCursor of the last repo of the previous page
	Limit    int
}

// JobFilter selects jobs, newest first.
type JobFilter struct {
	Status   model.JobStatus
	TargetID int64
	BeforeID int64 // keyset cursor
	Limit    int
}
