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
