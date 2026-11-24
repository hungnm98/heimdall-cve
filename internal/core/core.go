// Package core is the scan pipeline: resolve repos → fetch manifests →
// parse → query sources → dedup → recommend → store → diff → notify.
//
// Phase 0b only freezes its entry point (Scanner); the implementation lands
// in Phase 2. Core depends on ports only, never on adapters.
package core

import (
	"context"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// Progress receives human-readable progress lines (streamed to the UI as job events).
type Progress interface {
	Event(level, repo, message string)
}

// ProgressFunc adapts a function to Progress.
type ProgressFunc func(level, repo, message string)

// Event implements Progress.
func (f ProgressFunc) Event(level, repo, message string) { f(level, repo, message) }

// Discard drops progress.
var Discard Progress = ProgressFunc(func(string, string, string) {})

// ScanRequest is what to scan.
type ScanRequest struct {
	Targets   []model.Target   // resolved by the caller (config, catalog, or an ad-hoc repo target)
	TargetIDs map[string]int64 // Target.String() → catalog id, to cache repo listings; may be nil
	Repo      string           // optional: only this "owner/name" within Targets
	Force     bool             // rescan even if HEAD and source data are unchanged
	Trigger   model.JobTrigger
}

// Scanner runs one scan and records it as a ScanRun. A repo or source
// failure makes the run partial, not failed; only setup errors fail it.
type Scanner interface {
	Scan(ctx context.Context, req ScanRequest, p Progress) (*model.ScanRun, error)
}
