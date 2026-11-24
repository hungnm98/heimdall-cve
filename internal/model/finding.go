package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// FindingKind is what a finding is about.
type FindingKind string

const (
	KindDependency FindingKind = "dependency"
	KindRuntime    FindingKind = "runtime"
	KindCode       FindingKind = "code"
	KindSecret     FindingKind = "secret"
	KindConfig     FindingKind = "config"
)

// FindingStatus is the lifecycle state of a finding across scans.
type FindingStatus string

const (
	StatusOpen       FindingStatus = "open"
	StatusFixed      FindingStatus = "fixed"
	StatusSuppressed FindingStatus = "suppressed"
	// StatusRemoved: the branch it was found on is gone or no longer
	// scanned. Not a fix: the code was never changed.
	StatusRemoved FindingStatus = "removed"
)

// BumpType is the size of the recommended upgrade.
type BumpType string

const (
	BumpNone  BumpType = ""
	BumpPatch BumpType = "patch"
	BumpMinor BumpType = "minor"
	BumpMajor BumpType = "major" // breaking: needs testing
	BumpNoFix BumpType = "no-fix-available"
)

// Finding is one problem in one place. Its ID is stable across scans and
// across version bumps, so the store can deduplicate and track SLA.
type Finding struct {
	ID           string
	Kind         FindingKind
	Provider     string
	Repo         string // owner/name
	Branch       string // "" = the repo's default branch; else an extra scanned branch
	ManifestPath string
	Package      Package
	Direct       bool
	Scope        Scope
	Parents      []string

	AdvisoryID     string   // canonical ID after dedup
	Aliases        []string // every other ID of the same vulnerability
	Summary        string
	Severity       Severity
	CVSSVector     string
	CVSSScore      float64
	EPSS           float64
	EPSSPercentile float64
	InKEV          bool
	Malicious      bool
	Verified       bool // false when only unconfirmed agent sources report it
	References     []string

	FixedVersions      []string
	RecommendedVersion string
	Bump               BumpType
	Advice             string
	Priority           float64

	Runtime *RuntimeStatus // KindRuntime only

	Sources   []string
	FirstSeen time.Time
	LastSeen  time.Time
	Status    FindingStatus
}

// FindingID hashes the identity parts of a finding. pkgKey must be version-less
// (Package.Key()) so a bump that is still vulnerable keeps the same ID.
func FindingID(provider, repo, manifestPath, pkgKey, advisoryID string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{provider, repo, manifestPath, pkgKey, advisoryID}, "\x00")))
	return hex.EncodeToString(h[:12])
}

// ScopeKey is ScopeKey(f.Repo, f.Branch).
func (f *Finding) ScopeKey() string { return ScopeKey(f.Repo, f.Branch) }

// ComputeID sets f.ID from its identity fields and returns it.
func (f *Finding) ComputeID() string {
	key := f.Package.Key()
	if f.Kind == KindRuntime && f.Runtime != nil {
		key = "runtime:" + f.Runtime.Runtime.Name
	}
	repo := f.Repo
	if f.Branch != "" { // default-branch IDs predate multi-branch scans: keep them
		repo += "@" + f.Branch
	}
	f.ID = FindingID(f.Provider, repo, f.ManifestPath, key, f.AdvisoryID)
	return f.ID
}
