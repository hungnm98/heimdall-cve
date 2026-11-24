package service

import (
	"context"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/store"
)

// ---- AI-agent workflow (MCP) ----
//
// Contract frozen in Phase 3; implementations need a store implementing
// store.Intel (memstore, postgres) and are exposed by internal/mcpserver.

// QueueItem is a library an agent should analyze next.
type QueueItem struct {
	Usage        model.PackageUsage
	LastAnalysis *model.LibraryAnalysis // nil = never analyzed
	OpenFindings int
	Reason       string  // e.g. "never analyzed; direct in 3 repos"
	Score        float64 // higher = analyze first
}

// AdvisoryInput is an agent-submitted vulnerability.
type AdvisoryInput struct {
	OSV        []byte   // an OSV record (JSON); id must not collide with public prefixes unless it is an alias
	Evidence   []string // https URLs, at least one
	Confidence model.Confidence
}

// AnalysisInput is an agent's assessment of a library.
type AnalysisInput struct {
	Ecosystem          model.Ecosystem
	Name               string
	Version            string
	Verdict            model.Verdict
	Summary            string
	Evidence           []string // https URLs, at least one
	RecommendedVersion string
	Confidence         model.Confidence
}

// TriageFilter selects the triage queue. Zero fields take the defaults.
type TriageFilter struct {
	MinSeverity model.Severity // default HIGH; KEV and malicious findings are included at any severity
	Repo        string
	KEVOnly     bool
	Limit       int
	StaleAfter  time.Duration // an assessment older than this is redone (default DefaultStaleAfter)
}

// TriageItem is a finding an agent should assess next. A repo-agnostic item
// stands for every open finding of the same advisory on the same package
// version: one assessment covers all of Repos.
type TriageItem struct {
	Finding        model.Finding            // the highest-priority finding of the group; submit with its ID
	Repos          []string                 // repos the item covers, sorted
	LastAssessment *model.FindingAssessment // nil = never assessed
	Reason         string
}

// AssessmentInput is an agent's triage of a finding. The key (advisory,
// package version, repo) and the inputs hash come from the finding itself.
type AssessmentInput struct {
	FindingID  string
	Decision   model.Decision
	Score      float64  // 0-100, urgency
	Rationale  string   // at most 4000 characters
	Evidence   []string // https URLs; at least one unless the rationale has 20+ characters
	Confidence model.Confidence
	// RepoSpecific scopes the assessment to the finding's repo (the decision
	// depends on that repo's code, e.g. the vulnerable function is not
	// reachable there); otherwise it applies to every repo.
	RepoSpecific bool
}

// AssessmentStatus is the assessment that applies to a finding. Fresh means
// the finding facts the agent saw are unchanged and it is not older than
// the stale-after period: there is nothing to re-assess.
type AssessmentStatus struct {
	Assessment model.FindingAssessment
	Fresh      bool
}

// Intel serves inventory and agent intelligence.
type Intel interface {
	// Inventory lists what the last scans found in use.
	Inventory(ctx context.Context, f store.InventoryFilter) ([]model.InventoryItem, error)
	// AnalysisQueue ranks libraries to analyze: never analyzed or older than
	// staleAfter first, then direct dependencies, wide usage and open findings.
	AnalysisQueue(ctx context.Context, limit int, staleAfter time.Duration) ([]QueueItem, error)
	// SubmitAdvisory validates and stores an agent advisory (always
	// Sources=[agent], Verified=false). Needs writes enabled (ErrForbidden otherwise).
	SubmitAdvisory(ctx context.Context, actor Actor, in AdvisoryInput) (*model.AgentAdvisory, error)
	// SubmitAnalysis validates and stores an analysis. Needs writes enabled.
	SubmitAnalysis(ctx context.Context, actor Actor, in AnalysisInput) (*model.LibraryAnalysis, error)
	// Analyses returns the analysis history of a library, newest first.
	Analyses(ctx context.Context, eco model.Ecosystem, name string, limit int) ([]model.LibraryAnalysis, error)

	// TriageQueue lists open dependency findings at or above f.MinSeverity
	// (or in KEV, or malicious) without a fresh assessment, highest
	// Finding.Priority first, one item per advisory and package version
	// unless a repo-specific assessment splits a repo off.
	TriageQueue(ctx context.Context, f TriageFilter) ([]TriageItem, error)
	// SubmitAssessment validates and stores an agent triage of a dependency
	// finding. It never changes the finding. Needs writes enabled.
	SubmitAssessment(ctx context.Context, actor Actor, in AssessmentInput) (*model.FindingAssessment, error)
	// Assessments returns the assessments that apply to a finding
	// (repo-agnostic and for its repo), newest first.
	Assessments(ctx context.Context, findingID string, limit int) ([]model.FindingAssessment, error)
	// LatestAssessments returns, per finding ID, the assessment that applies
	// (the repo-specific one wins over the repo-agnostic one). Findings
	// never assessed, or not dependency findings, are absent.
	// staleAfter <= 0 means DefaultStaleAfter.
	LatestAssessments(ctx context.Context, findings []model.Finding, staleAfter time.Duration) (map[string]AssessmentStatus, error)
}

// MessageInput is a notification an agent sends to the team.
type MessageInput struct {
	Title    string
	Body     string
	Severity model.Severity
	Refs     []string // finding ids, advisory ids or URLs
}

// Messenger lets agents notify people through the configured notifiers.
type Messenger interface {
	// NotifyUser sends ev unless an identical message (title+body+refs) was
	// already sent (sent=false) or the daily limit is reached
	// (ErrRateLimited). Needs notify enabled (ErrForbidden otherwise).
	NotifyUser(ctx context.Context, actor Actor, in MessageInput) (sent bool, err error)
}
