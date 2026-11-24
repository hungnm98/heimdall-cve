package dedup

import (
	"slices"
	"sort"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

// Location identifies the repo the dependency graphs belong to.
type Location struct {
	Provider string // e.g. "github"
	Repo     string // owner/name
}

type advRef struct {
	adv *model.Advisory
	af  []model.Affected // entries naming the package
}

// Findings returns one dependency finding per (manifest, package, advisory)
// where the advisory's ranges actually affect the dependency's version.
// advisories should be the output of Merge. Private and unresolvable
// dependencies are skipped. Findings are identified with Finding.ComputeID;
// two with the same ID (e.g. a package listed twice in one manifest) collapse
// into one, so nothing is counted twice. The result is sorted by manifest,
// package name and advisory ID.
//
// FixedVersions holds, ascending, the fixed versions of the ranges that
// contain the current version, minus any that the advisory itself still
// marks as affected (sources may disagree on the fix: GHSA "fixed 1.2.3" vs
// Go "fixed 1.2.4" keeps only 1.2.4). Empty means no fix is known.
func Findings(loc Location, graphs []model.DependencyGraph, advisories []model.Advisory, cmps Comparators) []model.Finding {
	index := map[string][]advRef{}
	for i := range advisories {
		a := &advisories[i]
		if a.Withdrawn != nil {
			continue
		}
		byPkg := map[string][]model.Affected{}
		var order []string
		for _, af := range a.Affected {
			k := string(af.Ecosystem) + "|" + af.Name
			if _, ok := byPkg[k]; !ok {
				order = append(order, k)
			}
			byPkg[k] = append(byPkg[k], af)
		}
		for _, k := range order {
			index[k] = append(index[k], advRef{adv: a, af: byPkg[k]})
		}
	}

	var out []model.Finding
	byID := map[string]int{}
	for _, g := range graphs {
		for _, d := range g.Dependencies {
			if d.Private || d.Unresolvable != "" || d.Version == "" {
				continue
			}
			cmp := cmps[d.Ecosystem]
			v := Version(d.Package)
			for _, ref := range index[string(d.Ecosystem)+"|"+d.Name] {
				affected, fixed := false, []string(nil)
				for _, af := range ref.af {
					ok, fx := Affects(cmp, af, v)
					affected = affected || ok
					fixed = append(fixed, fx...)
				}
				if !affected {
					continue
				}
				f := newFinding(loc, g.ManifestPath, d, ref.adv, fixCandidates(cmp, ref.af, fixed))
				if i, dup := byID[f.ID]; dup {
					collapse(&out[i], f, cmp)
					continue
				}
				byID[f.ID] = len(out)
				out = append(out, f)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.ManifestPath != b.ManifestPath {
			return a.ManifestPath < b.ManifestPath
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		return a.AdvisoryID < b.AdvisoryID
	})
	return out
}

// fixCandidates dedups and sorts fixed versions, dropping any the advisory
// still marks as affected.
func fixCandidates(cmp version.Comparator, afs []model.Affected, fixed []string) []string {
	var out []string
	for _, fx := range fixed {
		if slices.Contains(out, fx) {
			continue
		}
		stillAffected := false
		if cmp != nil && cmp.Valid(fx) {
			for _, af := range afs {
				if ok, _ := Affects(cmp, af, fx); ok {
					stillAffected = true
				}
			}
		}
		if !stillAffected {
			out = append(out, fx)
		}
	}
	sortVersions(cmp, out)
	return out
}

func sortVersions(cmp version.Comparator, vs []string) {
	sort.SliceStable(vs, func(i, j int) bool {
		if cmp != nil {
			if c := cmp.Compare(vs[i], vs[j]); c != 0 {
				return c < 0
			}
		}
		return vs[i] < vs[j]
	})
}

func newFinding(loc Location, manifest string, d model.Dependency, a *model.Advisory, fixed []string) model.Finding {
	f := model.Finding{
		Kind:          model.KindDependency,
		Provider:      loc.Provider,
		Repo:          loc.Repo,
		ManifestPath:  manifest,
		Package:       d.Package,
		Direct:        d.Direct,
		Scope:         d.Scope,
		Parents:       slices.Clone(d.Parents),
		AdvisoryID:    a.ID,
		Aliases:       slices.Clone(a.Aliases),
		Summary:       a.Summary,
		Severity:      a.Severity,
		CVSSVector:    a.CVSSVector,
		CVSSScore:     a.CVSSScore,
		Malicious:     a.IsMalicious(),
		Verified:      a.Verified,
		References:    slices.Clone(a.References),
		FixedVersions: fixed,
		Sources:       slices.Clone(a.Sources),
		Status:        model.StatusOpen,
	}
	if f.Severity == "" {
		f.Severity = model.SeverityUnknown
	}
	// A malicious package (OSV MAL-*) is compromised code running in the
	// build or the app: always the most urgent, whatever its record says.
	if f.Malicious {
		f.Severity = model.SeverityCritical
	}
	f.ComputeID()
	return f
}

// collapse folds a duplicate finding (same ID) into dst.
func collapse(dst *model.Finding, src model.Finding, cmp version.Comparator) {
	dst.Direct = dst.Direct || src.Direct
	if dst.Scope != model.ScopeProd && src.Scope == model.ScopeProd {
		dst.Scope = model.ScopeProd
	}
	dst.Parents = uniqueSorted(append(dst.Parents, src.Parents...), "")
	for _, fx := range src.FixedVersions {
		if !slices.Contains(dst.FixedVersions, fx) {
			dst.FixedVersions = append(dst.FixedVersions, fx)
		}
	}
	sortVersions(cmp, dst.FixedVersions)
}
