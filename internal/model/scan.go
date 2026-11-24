package model

import "time"

// RunStatus is the outcome of a scan run.
type RunStatus string

const (
	RunRunning   RunStatus = "running"
	RunSucceeded RunStatus = "succeeded"
	RunPartial   RunStatus = "partial" // finished, but some repos or sources failed
	RunFailed    RunStatus = "failed"
)

// ScanRun is one execution of the pipeline.
type ScanRun struct {
	ID           int64
	StartedAt    time.Time
	FinishedAt   time.Time
	Status       RunStatus
	Targets      []string
	ReposScanned []string // full names actually scanned (scope for fixed detection)
	ReposFailed  []string
	Sources      []SourceHealth
	Error        string
}

// SourceHealth records how a source behaved during a run.
type SourceHealth struct {
	Name     string
	Healthy  bool
	Error    string
	Calls    int
	Duration time.Duration
}

// Diff is what changed between two runs.
type Diff struct {
	FromRun   int64
	ToRun     int64
	New       []Finding
	Fixed     []Finding
	StillOpen []Finding
}
