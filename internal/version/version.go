// Package version compares package versions per ecosystem.
package version

import (
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"golang.org/x/mod/semver"
)

// Comparator understands one ecosystem's version scheme.
type Comparator interface {
	Valid(v string) bool
	// Compare returns -1, 0 or +1. Invalid versions sort before valid ones.
	Compare(a, b string) int
	// Bump classifies the upgrade from → to.
	Bump(from, to string) model.BumpType
}

// Go implements Comparator for Go module versions (semver with "v" prefix,
// pseudo-versions, "+incompatible").
type Go struct{}

var _ Comparator = Go{}

// Canonical normalises a Go version: adds "v", strips "+incompatible".
func (Go) Canonical(v string) string {
	v = strings.TrimSuffix(strings.TrimSpace(v), "+incompatible")
	if v != "" && !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	return v
}

func (g Go) Valid(v string) bool { return semver.IsValid(g.Canonical(v)) }

func (g Go) Compare(a, b string) int { return semver.Compare(g.Canonical(a), g.Canonical(b)) }

// Bump treats a minor bump on v0 as major: v0 gives no compatibility promise.
func (g Go) Bump(from, to string) model.BumpType {
	f, t := g.Canonical(from), g.Canonical(to)
	if !semver.IsValid(f) || !semver.IsValid(t) || semver.Compare(t, f) <= 0 {
		return model.BumpNone
	}
	if semver.Major(f) != semver.Major(t) {
		return model.BumpMajor
	}
	if semver.MajorMinor(f) != semver.MajorMinor(t) {
		if semver.Major(f) == "v0" {
			return model.BumpMajor
		}
		return model.BumpMinor
	}
	return model.BumpPatch
}
