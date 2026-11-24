package model

import "time"

// Confidence of agent-submitted intelligence.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// AgentSource is the source name of everything submitted by AI agents.
const AgentSource = "agent"

// AgentAdvisory is a vulnerability an AI agent found before public databases
// did. It enters scans as the "agent" source: findings it alone reports are
// marked unverified; once OSV/GHSA publish a record with a shared alias, the
// dedup merge makes them verified.
type AgentAdvisory struct {
	Advisory    Advisory // OSV-shaped; Sources = [agent], Verified = false
	Evidence    []string // https URLs, at least one
	Confidence  Confidence
	SubmittedBy string
	SubmittedAt time.Time
}

// Verdict is an agent's assessment of a library.
type Verdict string

const (
	VerdictOK         Verdict = "ok"                 // nothing notable
	VerdictSafeToBump Verdict = "safe-to-bump"       // the recommended upgrade has no breaking change
	VerdictBreaking   Verdict = "breaking-change"    // the upgrade needs code changes
	VerdictAbandoned  Verdict = "abandoned"          // unmaintained: plan a replacement
	VerdictSuspicious Verdict = "suspicious-release" // e.g. maintainer takeover, odd publish
	VerdictMalicious  Verdict = "malicious"
)

// LibraryAnalysis is one agent analysis of a library (history is kept).
type LibraryAnalysis struct {
	ID                 int64
	Ecosystem          Ecosystem
	Name               string
	Version            string // version analyzed; "" = the library in general
	Verdict            Verdict
	Summary            string
	Evidence           []string
	RecommendedVersion string
	Confidence         Confidence
	Agent              string
	AnalyzedAt         time.Time
}

// Decision is an agent's triage call on a finding.
type Decision string

const (
	DecisionFixNow        Decision = "fix-now"        // exploitable here: fix immediately
	DecisionSchedule      Decision = "schedule"       // fix in the normal upgrade cycle
	DecisionMonitor       Decision = "monitor"        // no action yet; watch for an exploit or a fix
	DecisionNotAffected   Decision = "not-affected"   // the vulnerable code is not reachable or not used
	DecisionFalsePositive Decision = "false-positive" // the advisory does not apply to this version
)

// AssessmentKey identifies what an assessment is about: one advisory on one
// package version, in every repo (Repo "") or in one repo.
type AssessmentKey struct {
	AdvisoryID string
	Ecosystem  Ecosystem
	Package    string
	Version    string
	Repo       string // "" = every repo using that package version
}

// FindingAssessment is one agent triage of a finding (history is kept; the
// newest per key wins). It is shown alongside the finding and never changes
// its priority, status or severity: it is unverified input.
type FindingAssessment struct {
	ID         int64
	AdvisoryID string // canonical advisory id of the finding
	Ecosystem  Ecosystem
	Package    string
	Version    string
	Repo       string // "" = every repo; set when the decision depends on the repo's code
	Decision   Decision
	Score      float64 // 0-100, the agent's urgency
	Rationale  string
	Evidence   []string // https URLs; may be empty when the rationale is substantial
	Confidence Confidence
	// InputsHash fingerprints the finding facts the agent saw (severity,
	// CVSS, KEV, malicious, EPSS bucket, fixed versions): once they change,
	// the assessment is no longer fresh.
	InputsHash string
	AssessedBy string
	AssessedAt time.Time
}

// Key returns the key of a.
func (a FindingAssessment) Key() AssessmentKey {
	return AssessmentKey{AdvisoryID: a.AdvisoryID, Ecosystem: a.Ecosystem, Package: a.Package, Version: a.Version, Repo: a.Repo}
}

// InventoryItem is one dependency of one manifest, as last scanned.
type InventoryItem struct {
	Repo         string
	ManifestPath string
	Package      Package
	Direct       bool
	Scope        Scope
	Private      bool
	Unresolvable string
}

// PackageUsage aggregates the inventory per library.
type PackageUsage struct {
	Ecosystem Ecosystem
	Name      string
	Versions  []string // distinct versions in use, sorted
	Repos     []string // repos using it, sorted
	Direct    bool     // a direct dependency somewhere
}
