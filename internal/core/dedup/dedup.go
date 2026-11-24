// Package dedup merges advisories reported by several sources into one record
// per vulnerability and turns them into findings ("trùng thì bỏ qua",
// PLAN §3.3). Everything here is a pure function.
package dedup

import (
	"slices"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// AgentSource is the source name of unconfirmed AI-agent submissions. An
// advisory reported only by it stays unverified.
const AgentSource = "agent"

// idRank orders ID namespaces for the canonical ID: GO- < GHSA- < CVE- < others.
func idRank(id string) int {
	switch {
	case strings.HasPrefix(id, "GO-"):
		return 0
	case strings.HasPrefix(id, "GHSA-"):
		return 1
	case strings.HasPrefix(id, "CVE-"):
		return 2
	}
	return 3
}

// lessID is the canonical preference: namespace rank first (GO- > GHSA- > CVE-
// > others), then the lexically smallest ID, which for GO-/CVE- IDs is also
// the oldest one. The tie-break only matters when one vulnerability carries
// two IDs of the same namespace; it makes the choice deterministic.
func lessID(a, b string) bool {
	if ra, rb := idRank(a), idRank(b); ra != rb {
		return ra < rb
	}
	return a < b
}

// Canonical returns the preferred ID among ids ("" for none).
func Canonical(ids []string) string {
	best := ""
	for _, id := range ids {
		if id != "" && (best == "" || lessID(id, best)) {
			best = id
		}
	}
	return best
}

// unionFind over advisory IDs.
type unionFind map[string]string

func (u unionFind) find(x string) string {
	if _, ok := u[x]; !ok {
		u[x] = x
	}
	for u[x] != x {
		u[x] = u[u[x]] // path halving
		x = u[x]
	}
	return x
}

func (u unionFind) union(a, b string) {
	if ra, rb := u.find(a), u.find(b); ra != rb {
		u[ra] = rb
	}
}

// Merge groups advisories that share an ID or alias (transitively: GHSA ↔ CVE
// ↔ GO-…) and merges each group into one advisory whose ID is the canonical
// ID (see Canonical) and whose Aliases are every other ID of the group.
// Withdrawn advisories are dropped. The result is sorted by ID.
//
// Merged fields: Sources, References and Affected are unions; Severity is the
// worst reported (or implied by the highest CVSS score); CVSSScore/Vector come
// from the highest-scoring record; Summary/Details from the record with the
// most preferred ID that has them; Published is the earliest, Modified the
// latest; Verified is true when any record is verified or any source other
// than "agent" reported it.
func Merge(advs []model.Advisory) []model.Advisory {
	uf := unionFind{}
	var live []model.Advisory
	for _, a := range advs {
		if a.Withdrawn != nil || a.ID == "" {
			continue
		}
		live = append(live, a)
		for _, id := range a.Aliases {
			if id != "" {
				uf.union(a.ID, id)
			}
		}
		uf.find(a.ID)
	}
	groups := map[string][]model.Advisory{}
	var roots []string
	for _, a := range live {
		r := uf.find(a.ID)
		if _, ok := groups[r]; !ok {
			roots = append(roots, r)
		}
		groups[r] = append(groups[r], a)
	}
	out := make([]model.Advisory, 0, len(roots))
	for _, r := range roots {
		out = append(out, mergeGroup(groups[r]))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func mergeGroup(g []model.Advisory) model.Advisory {
	// Most preferred record first so its text wins.
	sort.SliceStable(g, func(i, j int) bool { return lessID(g[i].ID, g[j].ID) })
	var ids []string
	for _, a := range g {
		ids = append(ids, a.IDs()...)
	}
	m := model.Advisory{ID: Canonical(ids)}
	m.Aliases = uniqueSorted(ids, m.ID)
	var sources, refs []string
	for _, a := range g {
		if m.Summary == "" {
			m.Summary = a.Summary
		}
		if m.Details == "" {
			m.Details = a.Details
		}
		if a.Severity.Rank() > m.Severity.Rank() {
			m.Severity = a.Severity
		}
		if a.CVSSScore > m.CVSSScore || (m.CVSSVector == "" && m.CVSSScore == 0 && a.CVSSVector != "") {
			m.CVSSScore, m.CVSSVector = a.CVSSScore, a.CVSSVector
		}
		if !a.Published.IsZero() && (m.Published.IsZero() || a.Published.Before(m.Published)) {
			m.Published = a.Published
		}
		if a.Modified.After(m.Modified) {
			m.Modified = a.Modified
		}
		sources = append(sources, a.Sources...)
		refs = append(refs, a.References...)
		m.Affected = mergeAffected(m.Affected, a.Affected)
		if a.Verified {
			m.Verified = true
		}
		for _, s := range a.Sources {
			if s != AgentSource {
				m.Verified = true
			}
		}
	}
	if s := model.SeverityFromCVSS(m.CVSSScore); s.Rank() > m.Severity.Rank() {
		m.Severity = s
	}
	if m.Severity == "" {
		m.Severity = model.SeverityUnknown
	}
	m.Sources = uniqueSorted(sources, "")
	m.References = uniqueOrdered(refs)
	return m
}

// mergeAffected unions b into a: one entry per (ecosystem, name), ranges and
// versions deduplicated, first-seen order kept.
func mergeAffected(a, b []model.Affected) []model.Affected {
	for _, nb := range b {
		i := slices.IndexFunc(a, func(x model.Affected) bool { return x.Ecosystem == nb.Ecosystem && x.Name == nb.Name })
		if i < 0 {
			a = append(a, model.Affected{Ecosystem: nb.Ecosystem, Name: nb.Name})
			i = len(a) - 1
		}
		for _, r := range nb.Ranges {
			if !slices.Contains(a[i].Ranges, r) {
				a[i].Ranges = append(a[i].Ranges, r)
			}
		}
		for _, v := range nb.Versions {
			if !slices.Contains(a[i].Versions, v) {
				a[i].Versions = append(a[i].Versions, v)
			}
		}
	}
	return a
}

// uniqueSorted returns the distinct non-empty values of in except skip, sorted.
func uniqueSorted(in []string, skip string) []string {
	seen := map[string]bool{skip: true, "": true}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func uniqueOrdered(in []string) []string {
	seen := map[string]bool{"": true}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
