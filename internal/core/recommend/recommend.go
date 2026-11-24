// Package recommend computes upgrade recommendations (bootstrap §7, PLAN §3.4):
// per advisory the smallest fixed version above the current one, per package
// the maximum of those, the bump size, a ready-to-run command, and a per-repo
// upgrade plan with one line per package.
package recommend

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/core/dedup"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

// Apply fills RecommendedVersion, Bump and Advice of dependency findings and
// Advice of runtime findings, in place. Findings of the same package in the
// same manifest share one recommendation: the version that fixes all their
// fixable advisories. A finding whose advisory has no fix gets
// model.BumpNoFix and no recommended version.
func Apply(findings []model.Finding, cmps dedup.Comparators) {
	for _, g := range group(findings) {
		r := recommendGroup(g, cmps[g[0].Package.Ecosystem])
		for _, f := range g {
			if r.fixOf[f] == "" {
				f.RecommendedVersion, f.Bump = "", model.BumpNoFix
				f.Advice = noFixAdvice(f.Package, f.Malicious, []string{f.AdvisoryID})
				continue
			}
			f.RecommendedVersion, f.Bump, f.Advice = r.recommended, r.bump, r.advice
		}
	}
	for i := range findings {
		if f := &findings[i]; f.Kind == model.KindRuntime && f.Runtime != nil {
			f.Advice = RuntimeAdvice(*f.Runtime)
		}
	}
}

// Plan builds a repo's upgrade plan from its dependency findings: one item
// per (manifest, package), carrying the worst severity and every advisory
// ID, sorted by severity (worst first), then package name and manifest.
// Fixed and suppressed findings are left out.
func Plan(findings []model.Finding, cmps dedup.Comparators) []model.UpgradeItem {
	var open []model.Finding
	for _, f := range findings {
		if f.Status != model.StatusFixed && f.Status != model.StatusSuppressed {
			open = append(open, f)
		}
	}
	var items []model.UpgradeItem
	for _, g := range group(open) {
		r := recommendGroup(g, cmps[g[0].Package.Ecosystem])
		item := model.UpgradeItem{
			Package:  g[0].Package,
			Manifest: g[0].ManifestPath,
			Severity: model.SeverityUnknown,
		}
		var noFix []string
		malicious := false
		for _, f := range g {
			item.Direct = item.Direct || f.Direct
			if f.Severity.Rank() > item.Severity.Rank() {
				item.Severity = f.Severity
			}
			item.Advisories = append(item.Advisories, f.AdvisoryID)
			if r.fixOf[f] == "" {
				noFix = append(noFix, f.AdvisoryID)
			}
			malicious = malicious || f.Malicious
		}
		sort.Strings(item.Advisories)
		sort.Strings(noFix)
		if r.recommended == "" {
			item.Bump = model.BumpNoFix
			item.Advice = noFixAdvice(item.Package, malicious, noFix)
		} else {
			item.Recommended, item.Bump, item.Advice = r.recommended, r.bump, r.advice
			if len(noFix) > 0 {
				item.Advice += "; no fix yet for " + strings.Join(noFix, ", ")
			}
		}
		items = append(items, item)
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Package.Name != b.Package.Name {
			return a.Package.Name < b.Package.Name
		}
		return a.Manifest < b.Manifest
	})
	return items
}

// group collects dependency findings by (manifest, version-less package), in
// first-seen order.
func group(findings []model.Finding) [][]*model.Finding {
	idx := map[string]int{}
	var out [][]*model.Finding
	for i := range findings {
		f := &findings[i]
		if f.Kind != model.KindDependency && f.Kind != "" {
			continue
		}
		k := f.ManifestPath + "\x00" + f.Package.Key()
		j, ok := idx[k]
		if !ok {
			j = len(out)
			idx[k] = j
			out = append(out, nil)
		}
		out[j] = append(out[j], f)
	}
	return out
}

type groupResult struct {
	fixOf       map[*model.Finding]string // per-advisory minimal fix ("" = none)
	recommended string                    // display form, e.g. "v1.2.4"
	bump        model.BumpType
	advice      string
}

// recommendGroup picks, per finding (advisory), the smallest fixed version
// above the current one, then the maximum over the group.
func recommendGroup(g []*model.Finding, cmp version.Comparator) groupResult {
	r := groupResult{fixOf: map[*model.Finding]string{}}
	pkg := g[0].Package
	current := dedup.Version(pkg)
	best := ""
	for _, f := range g {
		fix := minFixAbove(cmp, f.FixedVersions, current)
		r.fixOf[f] = fix
		if fix != "" && (best == "" || greater(cmp, fix, best)) {
			best = fix
		}
	}
	if best == "" {
		return r
	}
	r.recommended = displayVersion(pkg, best)
	r.bump = model.BumpNone
	if cmp != nil {
		r.bump = cmp.Bump(current, best)
	}
	var parents []string
	direct := false
	for _, f := range g {
		direct = direct || f.Direct
		parents = append(parents, f.Parents...)
	}
	r.advice = upgradeAdvice(pkg, r.recommended, direct, uniqueSorted(parents))
	if r.bump == model.BumpMajor {
		r.advice += " (major upgrade: may break the build, needs testing)"
	}
	return r
}

// minFixAbove returns the smallest fixed version strictly above current.
// Without a comparator the ordering is unknown: the first candidate that is
// not the current version is used.
func minFixAbove(cmp version.Comparator, fixed []string, current string) string {
	best := ""
	for _, fx := range fixed {
		if cmp == nil {
			if fx != current {
				return fx
			}
			continue
		}
		if !cmp.Valid(fx) || cmp.Compare(fx, current) <= 0 {
			continue
		}
		if best == "" || cmp.Compare(fx, best) < 0 {
			best = fx
		}
	}
	return best
}

func greater(cmp version.Comparator, a, b string) bool {
	if cmp == nil {
		return a > b
	}
	return cmp.Compare(a, b) > 0
}

func isGoToolchain(p model.Package) bool {
	return p.Ecosystem == model.EcosystemGo && (p.Name == "stdlib" || p.Name == "toolchain")
}

// displayVersion renders a fixed version the way the ecosystem's tools expect
// it: Go modules need the "v" prefix OSV omits.
func displayVersion(p model.Package, v string) string {
	if p.Ecosystem == model.EcosystemGo && !isGoToolchain(p) && !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

func upgradeAdvice(p model.Package, ver string, direct bool, parents []string) string {
	var cmd string
	switch {
	case isGoToolchain(p):
		return fmt.Sprintf("build with Go %s or later (go get toolchain@go%s)", ver, ver)
	case p.Ecosystem == model.EcosystemGo:
		cmd = fmt.Sprintf("go get %s@%s", p.Name, ver)
	default:
		cmd = fmt.Sprintf("upgrade %s to %s", p.Name, ver)
	}
	if direct {
		return cmd
	}
	if len(parents) > 0 {
		return fmt.Sprintf("%s (transitive via %s: prefer bumping the parent to a release that requires %s >= %s)",
			cmd, strings.Join(parents, ", "), p.Name, ver)
	}
	return cmd + " (transitive dependency)"
}

func noFixAdvice(p model.Package, malicious bool, ids []string) string {
	if malicious {
		return fmt.Sprintf("malicious package: remove %s and rotate any credentials it could reach (%s)", p.Name, strings.Join(ids, ", "))
	}
	return fmt.Sprintf("no fixed version of %s available for %s: consider an alternative or a mitigation from the advisory", p.Name, strings.Join(ids, ", "))
}

// RuntimeAdvice is the advice for a runtime status: "migrate to <cycle>"
// when the cycle is EOL or reaches EOL soon, "upgrade to latest patch X"
// when behind in a supported cycle, "" otherwise.
func RuntimeAdvice(st model.RuntimeStatus) string {
	name := st.Runtime.Name
	target := name + " " + st.LatestCycle
	if st.LatestCycle == "" {
		target = "a supported " + name + " release"
	}
	when := ""
	if st.EOLDate != nil {
		when = " on " + st.EOLDate.Format("2006-01-02")
	}
	switch st.Status {
	case model.SupportEOL:
		return fmt.Sprintf("%s %s reached end-of-life%s: migrate to %s", name, st.Cycle, when, target)
	case model.SupportEOLSoon:
		return fmt.Sprintf("%s %s reaches end-of-life%s: migrate to %s", name, st.Cycle, when, target)
	case model.SupportSupported, model.SupportSecurityOnly:
		if st.LatestPatch != "" && compareDotted(trimRuntimeVersion(st.Runtime.Version), st.LatestPatch) < 0 {
			return fmt.Sprintf("upgrade %s to latest patch %s", name, st.LatestPatch)
		}
	}
	return ""
}

func trimRuntimeVersion(v string) string {
	return strings.TrimLeft(strings.TrimSpace(v), "^~<>=! vgo")
}

// compareDotted compares dotted numeric versions; missing parts count as 0
// and a non-numeric suffix in a part is ignored ("1.22rc1" ~ "1.22").
func compareDotted(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(as), len(bs)); i++ {
		x, y := leadingInt(as, i), leadingInt(bs, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func leadingInt(parts []string, i int) int {
	if i >= len(parts) {
		return 0
	}
	s := parts[i]
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(s[:end])
	return n
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
