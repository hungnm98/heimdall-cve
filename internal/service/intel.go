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
