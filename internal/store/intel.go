package store

import (
	"context"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// Intel is an optional store capability for the AI-agent workflow: the
// dependency inventory, agent-submitted advisories, library analyses and
// finding assessments.
// Detect it with a type assertion. Behaviour is pinned by storetest.RunIntel.
type Intel interface {
	// ReplaceInventory replaces everything recorded for repo by items
	// (a scan sees the whole repo). Private and unresolvable items are kept:
	// the inventory is about what is in use, not what is checkable.
	ReplaceInventory(ctx context.Context, repo string, items []model.InventoryItem, at time.Time) error
	// ListInventory returns items ordered by repo, manifest, ecosystem, name, version.
	ListInventory(ctx context.Context, f InventoryFilter) ([]model.InventoryItem, error)
	// PackageUsage aggregates public (non-private, resolvable) inventory per
	// (ecosystem, name), ordered by number of repos desc, then ecosystem, name.
	PackageUsage(ctx context.Context, f UsageFilter) ([]model.PackageUsage, error)

	// SaveAgentAdvisory inserts or replaces (by Advisory.ID) an agent advisory.
	SaveAgentAdvisory(ctx context.Context, a *model.AgentAdvisory) error
	// ListAgentAdvisories returns every agent advisory, ordered by ID.
	ListAgentAdvisories(ctx context.Context) ([]model.AgentAdvisory, error)

	// SaveAnalysis appends an analysis (history is kept) and sets its ID.
	SaveAnalysis(ctx context.Context, a *model.LibraryAnalysis) error
	// LatestAnalyses returns the newest analysis per (ecosystem, name)
	// matching f, ordered by ecosystem, name.
	LatestAnalyses(ctx context.Context, f AnalysisFilter) ([]model.LibraryAnalysis, error)
	// AnalysisHistory returns every analysis of one library, newest first.
	AnalysisHistory(ctx context.Context, eco model.Ecosystem, name string, limit int) ([]model.LibraryAnalysis, error)

	// SaveAssessment appends a finding assessment (history is kept) and sets its ID.
	SaveAssessment(ctx context.Context, a *model.FindingAssessment) error
	// LatestAssessments returns the newest assessment per key among those
	// that apply to one of keys: same advisory, ecosystem, package and
	// version, and repo "" (every repo) or that key's Repo. Ordered by
	// advisory, ecosystem, package, version, repo; each key appears once.
	LatestAssessments(ctx context.Context, keys []model.AssessmentKey) ([]model.FindingAssessment, error)
	// AssessmentHistory returns every assessment that applies to k (as in
	// LatestAssessments), newest first.
	AssessmentHistory(ctx context.Context, k model.AssessmentKey, limit int) ([]model.FindingAssessment, error)
}

// InventoryFilter selects inventory items. Zero fields do not filter.
type InventoryFilter struct {
	Repo       string
	Ecosystem  model.Ecosystem
	Name       string // exact package name
	DirectOnly bool
	Limit      int
}

// UsageFilter selects aggregated package usage.
type UsageFilter struct {
	Ecosystem  model.Ecosystem
	DirectOnly bool // only libraries that are a direct dependency somewhere
	Limit      int
}

// AnalysisFilter selects latest analyses. Zero fields do not filter.
type AnalysisFilter struct {
	Ecosystem model.Ecosystem
	Name      string
	Verdict   model.Verdict
	Limit     int
}
