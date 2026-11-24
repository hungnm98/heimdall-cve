// Package report is the port for report formats (markdown, json now; html,
// csv, sarif, cyclonedx later).
package report

import (
	"io"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
)

// Reporter renders a report. Output must be deterministic for the same input
// (sorted, no wall-clock time beyond Report.GeneratedAt) so golden tests work.
type Reporter interface {
	Format() string        // "md", "json"
	FileExtension() string // ".md", ".json"
	Render(w io.Writer, r *model.Report) error
}

// Factory builds a Reporter.
type Factory = func(cfg plugin.Config, deps plugin.Deps) (Reporter, error)

// Registry holds reporters by format name.
var Registry = registry.New[Factory]("report")
