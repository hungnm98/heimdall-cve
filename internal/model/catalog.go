package model

import "time"

// Origin says who owns a record. Records from the config file are read-only
// in the UI; edit the file instead.
type Origin string

const (
	OriginConfig Origin = "config"
	OriginUI     Origin = "ui"
)

// TargetSpec is a stored target: what to scan, with which credentials, how often.
type TargetSpec struct {
	ID int64
	Target
	Schedule  string // cron expression; empty = manual only
	Enabled   bool
	Origin    Origin
	NextRunAt *time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AuthProfile is a stored credential profile. Options never hold secret
// values; the secret itself is sealed in the secret store (SecretID) or
// referenced by env/file in Options (config-origin profiles).
type AuthProfile struct {
	ID                int64
	Name              string
	Type              string // token | app | ssh
	Options           map[string]any
	SecretID          *int64
	SecretFingerprint string
	Origin            Origin
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// RepoRecord is a cached repo listing: the UI and incremental scans read it
// instead of listing orgs on every request.
type RepoRecord struct {
	Repo
	TargetID      int64
	LastListedAt  time.Time
	LastHeadSHA   string
	LastScannedAt *time.Time
}

// JobTrigger says what started a job.
type JobTrigger string

const (
	TriggerManual   JobTrigger = "manual"
	TriggerSchedule JobTrigger = "schedule"
	TriggerAPI      JobTrigger = "api"
	TriggerMCP      JobTrigger = "mcp"
	TriggerCLI      JobTrigger = "cli"
)

// JobStatus is the lifecycle of a scan job.
type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobSucceeded JobStatus = "succeeded"
	JobFailed    JobStatus = "failed"
	JobCanceled  JobStatus = "canceled"
)

// Active reports whether the job is queued or running.
func (s JobStatus) Active() bool { return s == JobQueued || s == JobRunning }

// Job is one scan request. Scope: TargetID nil = every enabled target;
// Repo set = only that repo ("owner/name", or a URL for an ad-hoc repo).
type Job struct {
	ID          int64
	TargetID    *int64
	Repo        string
	Branch      string
	AuthProfile string // for ad-hoc repo jobs
	BaseURL     string // API base URL for an ad-hoc repo on GitHub Enterprise; "" = github.com
	Force       bool   // rescan even if HEAD and source data are unchanged
	Trigger     JobTrigger
	Status      JobStatus
	RunID       *int64
	Attempts    int
	RequestedBy string
	Error       string
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
}

// JobEvent is one progress line, streamed to the UI.
type JobEvent struct {
	ID      int64
	JobID   int64
	At      time.Time
	Level   string // info | warn | error
	Repo    string
	Message string
}

// Suppression silences a finding until ExpiresAt. A reason and an expiry are
// mandatory: nothing is suppressed forever or without explanation.
type Suppression struct {
	FindingID string
	Reason    string
	ExpiresAt time.Time
	Actor     string
	CreatedAt time.Time
}

// AuditEntry records a write action from the UI, API, MCP or CLI.
type AuditEntry struct {
	ID         int64
	At         time.Time
	Actor      string // trusted proxy header value, "cli", "mcp", or "anonymous"
	Action     string // e.g. "target.create", "finding.suppress", "job.cancel"
	ObjectType string
	ObjectID   string
	Details    map[string]any // never secret values
}
