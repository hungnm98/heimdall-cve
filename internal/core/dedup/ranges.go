package dedup

import (
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

// Comparators gives the version comparator of each ecosystem. An ecosystem
// without one cannot have its ranges evaluated (see Affects).
type Comparators map[model.Ecosystem]version.Comparator

// Version returns the version of p as OSV ranges spell it: the Go standard
// library and toolchain ("stdlib", "toolchain") drop the "go" prefix
// ("go1.22.1" → "1.22.1"); everything else is unchanged.
func Version(p model.Package) string {
	if p.Ecosystem == model.EcosystemGo && (p.Name == "stdlib" || p.Name == "toolchain") {
		return strings.TrimPrefix(p.Version, "go")
	}
	return p.Version
}

// Affects reports whether version v is affected by af, following OSV
// semantics, and returns the "fixed" versions of the ranges containing v:
//
//   - v is affected if it is listed in af.Versions, or lies in a range:
//     Introduced <= v (Introduced "0" or "" = from the beginning) and
//     v < Fixed, or v <= LastAffected, or no upper bound at all.
//   - A range whose bounds the comparator rejects is ignored.
//   - Without a comparator, or for a version the comparator cannot parse, the
//     ranges cannot be evaluated: the source's own match is trusted (sources
//     only return advisories they matched to the version) and every fixed
//     version is returned as a candidate.
func Affects(cmp version.Comparator, af model.Affected, v string) (bool, []string) {
	evaluable := cmp != nil && cmp.Valid(v)
	if !evaluable {
		var fixed []string
		for _, r := range af.Ranges {
			if r.Fixed != "" {
				fixed = append(fixed, r.Fixed)
			}
		}
		return true, fixed
	}
	affected := false
	for _, x := range af.Versions {
		if x == v || (cmp.Valid(x) && cmp.Compare(x, v) == 0) {
			affected = true
		}
	}
	var fixed []string
	for _, r := range af.Ranges {
		if !inRange(cmp, r, v) {
			continue
		}
		affected = true
		if r.Fixed != "" {
			fixed = append(fixed, r.Fixed)
		}
	}
	return affected, fixed
}

func inRange(cmp version.Comparator, r model.VersionRange, v string) bool {
	if r.Introduced != "" && r.Introduced != "0" {
		if !cmp.Valid(r.Introduced) || cmp.Compare(v, r.Introduced) < 0 {
			return false
		}
	}
	switch {
	case r.Fixed != "":
		return cmp.Valid(r.Fixed) && cmp.Compare(v, r.Fixed) < 0
	case r.LastAffected != "":
		return cmp.Valid(r.LastAffected) && cmp.Compare(v, r.LastAffected) <= 0
	}
	return true
}
