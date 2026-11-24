// Package runtime is the port for language-runtime version detectors
// (go directive, .go-version, Dockerfile FROM, CI setup actions...).
package runtime

import (
	"context"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/registry"
)

// Detector finds declared versions of one runtime.
type Detector interface {
	Name() string
	// Runtime is the runtime it detects: "go", "node", "ruby".
	Runtime() string
	// Match reports whether a repo path may declare this runtime.
	Match(path string) bool
	// Detect returns every declaration found, each with its origin file.
	Detect(ctx context.Context, files model.FileSet) ([]model.Runtime, error)
}

// Factory builds a Detector.
type Factory = func(cfg plugin.Config, deps plugin.Deps) (Detector, error)

// Registry holds detectors by name.
var Registry = registry.New[Factory]("runtime-detector")
