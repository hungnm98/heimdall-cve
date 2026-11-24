package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// osvRecord is the subset of the OSV schema (https://ossf.github.io/osv-schema/)
// agents submit. It is decoded here rather than by internal/source/osv, which
// is an adapter the service layer must not import.
type osvRecord struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Published        *time.Time     `json:"published"`
	Withdrawn        *time.Time     `json:"withdrawn"`
	References       []osvRef       `json:"references"`
	Affected         []osvAffected  `json:"affected"`
	Severity         []osvSeverity  `json:"severity"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

type osvRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges []struct {
		Type   string `json:"type"`
		Events []struct {
			Introduced   string `json:"introduced"`
			Fixed        string `json:"fixed"`
			LastAffected string `json:"last_affected"`
		} `json:"events"`
	} `json:"ranges"`
	Versions          []string       `json:"versions"`
	Severity          []osvSeverity  `json:"severity"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
	DatabaseSpecific  map[string]any `json:"database_specific"`
}

// maxOSVSize bounds a submitted record.
const maxOSVSize = 256 << 10

func decodeOSV(raw []byte) (*osvRecord, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, invalid("osv_json", "an OSV record (JSON object) is required")
	}
	if len(raw) > maxOSVSize {
		return nil, invalid("osv_json", fmt.Sprintf("too large (max %d KiB)", maxOSVSize>>10))
	}
	var r osvRecord
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, invalid("osv_json", "not a valid OSV JSON object: "+err.Error())
	}
	return &r, nil
}

// parseEcosystem accepts Heimdall names (go, npm, rubygems) and OSV names
// (Go, npm, RubyGems), case-insensitively.
func parseEcosystem(s string) (model.Ecosystem, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "go", "golang":
		return model.EcosystemGo, true
	case "npm":
		return model.EcosystemNPM, true
	case "rubygems", "gem":
		return model.EcosystemRubyGems, true
	}
	return "", false
}

// affected converts one OSV affected entry. GIT ranges are rejected: Heimdall
// matches package versions, not commits.
func (a osvAffected) toModel() (model.Affected, string) {
	eco, ok := parseEcosystem(a.Package.Ecosystem)
	if !ok {
		return model.Affected{}, fmt.Sprintf("unsupported ecosystem %q (supported: Go, npm, RubyGems)", a.Package.Ecosystem)
	}
	name := strings.TrimSpace(a.Package.Name)
	if name == "" {
		return model.Affected{}, "package.name is required"
	}
	out := model.Affected{Ecosystem: eco, Name: name}
	for _, r := range a.Ranges {
		if t := strings.ToUpper(r.Type); t != "SEMVER" && t != "ECOSYSTEM" {
			return model.Affected{}, fmt.Sprintf("range type %q is not supported (use SEMVER or ECOSYSTEM)", r.Type)
		}
		var cur *model.VersionRange
		for _, e := range r.Events {
			switch {
			case e.Introduced != "":
				if cur != nil {
					out.Ranges = append(out.Ranges, *cur)
				}
				cur = &model.VersionRange{Introduced: e.Introduced}
			case e.Fixed != "" || e.LastAffected != "":
				if cur == nil {
					cur = &model.VersionRange{Introduced: "0"}
				}
				cur.Fixed, cur.LastAffected = e.Fixed, e.LastAffected
				out.Ranges = append(out.Ranges, *cur)
				cur = nil
			}
		}
		if cur != nil {
			out.Ranges = append(out.Ranges, *cur)
		}
	}
	for _, v := range a.Versions {
		if v = strings.TrimSpace(v); v != "" {
			out.Versions = append(out.Versions, v)
		}
	}
	if len(out.Ranges) == 0 && len(out.Versions) == 0 {
		return model.Affected{}, "needs ranges (introduced/fixed events) or explicit versions"
	}
	return out, ""
}

// severity derives the severity from a CVSS v3 vector or numeric score, else
// from a database_specific / ecosystem_specific "severity" label.
func (r *osvRecord) severity() (model.Severity, string, float64) {
	sevs := append([]osvSeverity{}, r.Severity...)
	labels := []map[string]any{r.DatabaseSpecific}
	for _, a := range r.Affected {
		sevs = append(sevs, a.Severity...)
		labels = append(labels, a.DatabaseSpecific, a.EcosystemSpecific)
	}
	for _, s := range sevs {
		score := strings.TrimSpace(s.Score)
		if strings.HasPrefix(score, "CVSS:3.") {
			if n, err := cvss3BaseScore(score); err == nil {
				return model.SeverityFromCVSS(n), score, n
			}
		}
		if n, err := strconv.ParseFloat(score, 64); err == nil && n > 0 && n <= 10 {
			return model.SeverityFromCVSS(n), "", n
		}
	}
	for _, m := range labels {
		if l, ok := m["severity"].(string); ok {
			if sev := model.ParseSeverity(l); sev != model.SeverityUnknown {
				return sev, "", 0
			}
		}
	}
	return model.SeverityUnknown, "", 0
}

// cvss3Weights are the CVSS v3.1 base metric weights (FIRST spec §7.4).
var cvss3Weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// cvss3BaseScore computes the CVSS v3.x base score of a vector (same formula
// as the osv adapter, duplicated because the service may not import adapters).
func cvss3BaseScore(vector string) (float64, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("malformed CVSS metric %q", p)
		}
		m[k] = v
	}
	w := map[string]float64{}
	for metric, values := range cvss3Weights {
		x, ok := values[m[metric]]
		if !ok {
			return 0, fmt.Errorf("missing or invalid CVSS metric %s", metric)
		}
		w[metric] = x
	}
	var changed bool
	switch m["S"] {
	case "U":
	case "C":
		changed = true
	default:
		return 0, fmt.Errorf("missing or invalid CVSS metric S")
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, fmt.Errorf("missing or invalid CVSS metric PR")
	}
	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, nil
	}
	expl := 8.22 * w["AV"] * w["AC"] * pr * w["UI"]
	if changed {
		return cvssRoundup(math.Min(1.08*(impact+expl), 10)), nil
	}
	return cvssRoundup(math.Min(impact+expl, 10)), nil
}

func cvssRoundup(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
