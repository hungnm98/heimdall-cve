// Package service is the application layer shared by the REST API, the MCP
// server and the CLI. Entry points stay thin: parse input, call a service,
// render output. Every write takes an Actor and is audited by the service.
//
// Phase 0b freezes these interfaces; implementations (backed by store.Store +
// store.Catalog, jobs.Backend and core.Scanner) land in Phase 1 track E1.
package service

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// Errors mapped by entry points (HTTP: 400, 404, 409, 409, 503).
var (
	ErrNotFound    = store.ErrNotFound
	ErrConflict    = store.ErrConflict
	ErrReadOnly    = errors.New("read-only: defined in the config file")
	ErrUnavailable = errors.New("unavailable")
	ErrForbidden   = errors.New("forbidden: disabled by configuration")
	ErrRateLimited = errors.New("rate limited")
)

// ValidationError lists invalid input fields (HTTP 400 with field details).
type ValidationError struct {
	Fields map[string]string // field → message
}

func (e *ValidationError) Error() string {
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s: %s", k, e.Fields[k]))
	}
	return "invalid input: " + strings.Join(parts, "; ")
}

// Actor identifies who performs a write, for the audit log.
type Actor string

// Page is one page of a keyset-paginated list.
type Page[T any] struct {
	Items      []T
	NextCursor string // empty on the last page
}

// Services bundles every service.
type Services struct {
	Dashboard    Dashboard
	Targets      Targets
	AuthProfiles AuthProfiles
	Repos        Repos
	Findings     Findings
	Runs         Runs
	Jobs         Jobs
	System       System
	Intel        Intel     // nil when the store has no store.Intel
	Messenger    Messenger // nil when the store has no store.Intel
}

// ---- dashboard ----

// Dashboard summarises the current state.
type Dashboard interface {
	Summary(ctx context.Context, trendRuns int) (*DashboardSummary, error)
}

// DashboardSummary feeds the dashboard page.
type DashboardSummary struct {
	OpenBySeverity   map[model.Severity]int
	OpenKEV          int
	OpenMalicious    int
	Repos            int
	Trend            []model.ScanRun // newest last, with Stats
	TopFindings      []model.Finding // highest priority open findings
	EOLRuntimes      []model.RuntimeStatus
	UnhealthySources []model.SourceHealth // from the latest run
	ActiveJobs       []model.Job
	LastRun          *model.ScanRun
}

// ---- targets ----

// TargetInput is the writable part of a target.
type TargetInput struct {
	Kind     model.TargetKind
	Provider string // default github
	BaseURL  string
	Owner    string // org/user login (kind org/user)
	URL      string // repo URL (kind repo)
	Branch   string
	Auth     string
	ListAuth string // default Auth
	Repos    []string
	Filter   model.RepoFilter
	Schedule string // cron; "" = manual
	// Branches are extra branches (names or globs) scanned besides Branch.
	Branches    []string
	MaxBranches int    // 0 = default cap
	Poll        string // cron for "rescan what moved" checks; "" = off
	Enabled     bool
}

// Targets manages what is scanned. Config-origin targets return ErrReadOnly on write.
type Targets interface {
	List(ctx context.Context) ([]model.TargetSpec, error)
	Get(ctx context.Context, id int64) (*model.TargetSpec, error)
	Create(ctx context.Context, actor Actor, in TargetInput) (*model.TargetSpec, error)
	Update(ctx context.Context, actor Actor, id int64, in TargetInput) (*model.TargetSpec, error)
	Delete(ctx context.Context, actor Actor, id int64) error
	// Preview lists the repos the input would scan, without saving anything.
	Preview(ctx context.Context, in TargetInput) ([]model.Repo, error)
}

// ---- auth profiles ----

// AuthProfileInput is the writable part of a profile. Secret is write-only:
// nil keeps the current secret, a value replaces it (sealed before storage).
type AuthProfileInput struct {
	Name       string
	Type       string         // token | app | ssh
	Options    map[string]any // non-secret options (app_id, known_hosts, base_url...)
	Secret     *string
	SecretKind string // token | private_key | ssh_key
}

// ConnectionTest is the result of testing a profile against its provider.
type ConnectionTest struct {
	OK      bool
	Message string // e.g. "authenticated as app heimdall, 42 repos visible"
}

// AuthProfiles manages credentials. Secrets never leave the service in clear.
type AuthProfiles interface {
	List(ctx context.Context) ([]model.AuthProfile, error)
	Create(ctx context.Context, actor Actor, in AuthProfileInput) (*model.AuthProfile, error)
	Update(ctx context.Context, actor Actor, name string, in AuthProfileInput) (*model.AuthProfile, error)
	Delete(ctx context.Context, actor Actor, name string) error
	Test(ctx context.Context, name string) (*ConnectionTest, error)
	// SecretsEnabled reports whether a master key is configured (UI hides secret inputs otherwise).
	SecretsEnabled() bool
}

// ---- repos ----

// RepoDetail is everything about one repo.
type RepoDetail struct {
	Record      model.RepoRecord
	Branch      string          // the branch shown: "" = primary branch
	Branches    []BranchStatus  // every scanned branch, primary first
	Findings    []model.Finding // open on Branch, worst first
	Runtimes    []model.RuntimeStatus
	UpgradePlan []model.UpgradeItem
}

// BranchStatus is one scanned branch of a repo.
type BranchStatus struct {
	Name           string // the branch (ref) name
	Primary        bool   // the target branch or default branch (findings Branch "")
	HeadSHA        string
	ScannedAt      time.Time
	OpenBySeverity map[model.Severity]int
}

// Repos reads the cached repo list.
type Repos interface {
	List(ctx context.Context, f store.RepoFilter) (*Page[model.RepoRecord], error)
	// Get returns a repo's open findings on branch ("" = primary branch).
	Get(ctx context.Context, fullName, branch string) (*RepoDetail, error)
}

// ---- findings ----

// FindingDetail is a finding with its suppression, if any.
type FindingDetail struct {
	Finding     model.Finding
	Suppression *model.Suppression
}

// Findings reads and triages findings.
type Findings interface {
	List(ctx context.Context, f store.FindingFilter) (*Page[model.Finding], error)
	Get(ctx context.Context, id string) (*FindingDetail, error)
	// Suppress requires a non-empty reason and a future expiry (max 1 year).
	Suppress(ctx context.Context, actor Actor, id, reason string, expiresAt time.Time) error
	Unsuppress(ctx context.Context, actor Actor, id string) error
}

// ---- runs ----

// Runs reads scan history.
type Runs interface {
	List(ctx context.Context, beforeID int64, limit int) (*Page[model.ScanRun], error)
	Get(ctx context.Context, id int64) (*model.ScanRun, error)
	// Diff compares two runs; against = 0 means the run before id.
	Diff(ctx context.Context, id, against int64) (*model.Diff, error)
}

// ---- jobs ----

// JobRequest asks for a scan. Exactly one scope: TargetID, RepoURL (ad-hoc
// repo with AuthProfile), or neither (= every enabled target).
type JobRequest struct {
	TargetID    *int64
	Repo        string // optional "owner/name" within TargetID
	RepoURL     string
	Branch      string
	AuthProfile string
	Force       bool
	Trigger     model.JobTrigger
}

// Jobs triggers and follows scans.
type Jobs interface {
	// Trigger creates (or returns the already active) job for the scope and enqueues it.
	Trigger(ctx context.Context, actor Actor, req JobRequest) (job *model.Job, created bool, err error)
	List(ctx context.Context, f store.JobFilter) (*Page[model.Job], error)
	Get(ctx context.Context, id int64) (*model.Job, error)
	Cancel(ctx context.Context, actor Actor, id int64) error
	// Events returns progress after afterID; the API turns it into SSE.
	Events(ctx context.Context, id, afterID int64, limit int) ([]model.JobEvent, error)
}

// ---- system ----

// SourceStatus describes a configured source.
type SourceStatus struct {
	Name     string
	Kinds    []string // vuln-source, runtime-source...
	Healthy  bool
	Error    string
	LastSeen *time.Time // last run that used it
}

// NotifierStatus describes a configured notifier.
type NotifierStatus struct {
	Name string
	Type string
}

// System exposes configuration state and the audit log.
type System interface {
	Sources(ctx context.Context) ([]SourceStatus, error)
	Notifiers(ctx context.Context) ([]NotifierStatus, error)
	TestNotifier(ctx context.Context, actor Actor, name string) error
	Audit(ctx context.Context, beforeID int64, limit int) (*Page[model.AuditEntry], error)
}
