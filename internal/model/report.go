package model

import "time"

// Report is the input of every report format.
type Report struct {
	Run         ScanRun
	GeneratedAt time.Time
	Repos       []RepoReport
	Diff        *Diff
}

// RepoReport is everything known about one repo in a run.
type RepoReport struct {
	Repo        Repo
	HeadSHA     string
	Findings    []Finding
	Runtimes    []RuntimeStatus
	UpgradePlan []UpgradeItem
	Errors      []string
}

// UpgradeItem is one line of a repo's upgrade plan: one package, not one advisory.
type UpgradeItem struct {
	Package     Package
	Manifest    string
	Direct      bool
	Recommended string
	Bump        BumpType
	Severity    Severity // worst advisory
	Advisories  []string
	Advice      string // e.g. "go get example.com/x@v1.2.3"
}
