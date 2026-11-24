package osv

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// ecosystems maps model ecosystems to OSV ecosystem names. Supports() only
// accepts ecosystems listed here.
var ecosystems = map[model.Ecosystem]string{
	model.EcosystemGo:       "Go",
	model.EcosystemNPM:      "npm",
	model.EcosystemRubyGems: "RubyGems",
}

// fromOSVEcosystem is the reverse of ecosystems.
var fromOSVEcosystem = func() map[string]model.Ecosystem {
	m := make(map[string]model.Ecosystem, len(ecosystems))
	for k, v := range ecosystems {
		m[v] = k
	}
	return m
}()

// Wire types of the OSV API (https://google.github.io/osv.dev/api/) and the
// OSV schema (https://ossf.github.io/osv-schema/). Only fields we use.

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchQuery struct {
	Package   osvPackage `json:"package"`
	Version   string     `json:"version"`
	PageToken string     `json:"page_token,omitempty"`
}

type batchRequest struct {
	Queries []batchQuery `json:"queries"`
}

type batchVuln struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

type batchResult struct {
	Vulns         []batchVuln `json:"vulns"`
	NextPageToken string      `json:"next_page_token"`
}

type batchResponse struct {
	Results []batchResult `json:"results"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvEvent struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

type osvRange struct {
	Type   string     `json:"type"`
	Events []osvEvent `json:"events"`
}

type dbSpecific struct {
	Severity json.RawMessage `json:"severity"` // usually a label; tolerate other shapes
}

type osvAffected struct {
	Package           osvPackage    `json:"package"`
	Severity          []osvSeverity `json:"severity"`
	Ranges            []osvRange    `json:"ranges"`
	Versions          []string      `json:"versions"`
	EcosystemSpecific dbSpecific    `json:"ecosystem_specific"`
	DatabaseSpecific  dbSpecific    `json:"database_specific"`
}

type osvReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvVuln struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Published        time.Time      `json:"published"`
	Modified         time.Time      `json:"modified"`
	Withdrawn        *time.Time     `json:"withdrawn"`
	References       []osvReference `json:"references"`
	Affected         []osvAffected  `json:"affected"`
	Severity         []osvSeverity  `json:"severity"`
	DatabaseSpecific dbSpecific     `json:"database_specific"`
}

// label returns database_specific/ecosystem_specific "severity" when it is a string.
func (d dbSpecific) label() string {
	var s string
	if len(d.Severity) > 0 && json.Unmarshal(d.Severity, &s) == nil {
		return s
	}
	return ""
}

// toAdvisory maps an OSV record to model.Advisory. Affected entries in
// ecosystems we do not map are dropped; ranges of type GIT are dropped
// (commit hashes carry no version ordering).
func toAdvisory(v osvVuln, sourceName string) model.Advisory {
	a := model.Advisory{
		ID:        v.ID,
		Aliases:   v.Aliases,
		Summary:   v.Summary,
		Details:   v.Details,
		Published: v.Published,
		Modified:  v.Modified,
		Withdrawn: v.Withdrawn,
		Sources:   []string{sourceName},
		Verified:  true,
	}
	for _, r := range v.References {
		if r.URL != "" {
			a.References = append(a.References, r.URL)
		}
	}
	severities := append([]osvSeverity(nil), v.Severity...)
	labels := []string{v.DatabaseSpecific.label()}
	for _, af := range v.Affected {
		eco, ok := fromOSVEcosystem[af.Package.Ecosystem]
		if !ok {
			continue
		}
		out := model.Affected{Ecosystem: eco, Name: af.Package.Name, Versions: af.Versions}
		for _, r := range af.Ranges {
			if r.Type == "SEMVER" || r.Type == "ECOSYSTEM" {
				out.Ranges = append(out.Ranges, eventsToRanges(r.Events)...)
			}
		}
		a.Affected = append(a.Affected, out)
		severities = append(severities, af.Severity...)
		labels = append(labels, af.DatabaseSpecific.label(), af.EcosystemSpecific.label())
	}
	a.CVSSVector, a.CVSSScore = pickCVSS(severities)
	a.Severity = model.SeverityFromCVSS(a.CVSSScore)
	if a.Severity == model.SeverityUnknown {
		for _, l := range labels {
			if s := model.ParseSeverity(l); s.Rank() > a.Severity.Rank() {
				a.Severity = s
			}
		}
	}
	return a
}

// severityOf scores a record from every severity it carries, whatever the
// ecosystem of its affected entries (alias records such as Bitnami's are
// about ecosystems Heimdall does not scan).
func severityOf(v osvVuln) model.Advisory {
	sev := append([]osvSeverity(nil), v.Severity...)
	labels := []string{v.DatabaseSpecific.label()}
	for _, af := range v.Affected {
		sev = append(sev, af.Severity...)
		labels = append(labels, af.DatabaseSpecific.label(), af.EcosystemSpecific.label())
	}
	var a model.Advisory
	a.CVSSVector, a.CVSSScore = pickCVSS(sev)
	a.Severity = model.SeverityFromCVSS(a.CVSSScore)
	if a.Severity == model.SeverityUnknown {
		for _, l := range labels {
			if s := model.ParseSeverity(l); s.Rank() > a.Severity.Rank() {
				a.Severity = s
			}
		}
	}
	return a
}

// eventsToRanges turns an ordered OSV event list into ranges: each
// "introduced" opens a range closed by the next "fixed" or "last_affected".
// A range left open at the end affects every later version.
func eventsToRanges(events []osvEvent) []model.VersionRange {
	var out []model.VersionRange
	var cur *model.VersionRange
	for _, e := range events {
		switch {
		case e.Introduced != "":
			if cur != nil {
				out = append(out, *cur)
			}
			cur = &model.VersionRange{Introduced: e.Introduced}
		case e.Fixed != "", e.LastAffected != "":
			if cur == nil { // malformed: no introduced → from the beginning
				cur = &model.VersionRange{Introduced: "0"}
			}
			cur.Fixed, cur.LastAffected = e.Fixed, e.LastAffected
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// pickCVSS returns the best vector and its base score: the highest-scoring
// CVSS v3 vector; else the first CVSS v4 vector with score 0 (no v4 scorer:
// severity then comes from the database_specific label).
func pickCVSS(sev []osvSeverity) (string, float64) {
	var vector string
	var score float64
	for _, s := range sev {
		if s.Type != "CVSS_V3" {
			continue
		}
		if x, err := CVSS3BaseScore(s.Score); err == nil && (vector == "" || x > score) {
			vector, score = s.Score, x
		}
	}
	if vector != "" {
		return vector, score
	}
	for _, s := range sev {
		if s.Type == "CVSS_V4" && strings.HasPrefix(s.Score, "CVSS:4") {
			return s.Score, 0
		}
	}
	return "", 0
}
