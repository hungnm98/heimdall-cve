package model

import "time"

// Runtime is a language runtime version declared somewhere in a repo.
type Runtime struct {
	Name    string // "go" | "node" | "ruby"
	Version string // as declared, e.g. "1.22", "1.22.5", "20"
	Origin  string // repo-relative file it came from
	Via     string // how it was declared: "go directive", "toolchain", "Dockerfile FROM"...
}

// SupportStatus is the lifecycle state of a runtime cycle.
type SupportStatus string

const (
	SupportSupported    SupportStatus = "supported"
	SupportSecurityOnly SupportStatus = "security-only"
	SupportEOLSoon      SupportStatus = "eol-soon"
	SupportEOL          SupportStatus = "eol"
	SupportUnknown      SupportStatus = "unknown"
)

// RuntimeStatus is the evaluation of one Runtime.
type RuntimeStatus struct {
	Runtime     Runtime
	Cycle       string // "1.22"
	Status      SupportStatus
	EOLDate     *time.Time
	LatestPatch string // latest release of the same cycle
	LatestCycle string // newest supported cycle
	Source      string
}
