package osv

import (
	"fmt"
	"math"
	"strings"
)

// cvss3Weights are the CVSS v3.1 base metric weights (FIRST spec §7.4).
var cvss3Weights = map[string]map[string]float64{
	"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
	"AC": {"L": 0.77, "H": 0.44},
	"UI": {"N": 0.85, "R": 0.62},
	"C":  {"H": 0.56, "L": 0.22, "N": 0},
	"I":  {"H": 0.56, "L": 0.22, "N": 0},
	"A":  {"H": 0.56, "L": 0.22, "N": 0},
}

// CVSS3BaseScore computes the base score of a CVSS v3.0/v3.1 vector such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" (9.8). It implements the v3.1
// formula, including its Roundup; v3.0 vectors are scored with the same
// formula (the two differ only in rare floating-point rounding edge cases).
// Temporal/environmental metrics in the vector are ignored.
func CVSS3BaseScore(vector string) (float64, error) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "CVSS:3.") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("malformed CVSS metric %q in %q", p, vector)
		}
		m[k] = v
	}
	w := map[string]float64{}
	for metric, values := range cvss3Weights {
		x, ok := values[m[metric]]
		if !ok {
			return 0, fmt.Errorf("CVSS vector %q: missing or invalid %s", vector, metric)
		}
		w[metric] = x
	}
	changed := false
	switch m["S"] {
	case "U":
	case "C":
		changed = true
	default:
		return 0, fmt.Errorf("CVSS vector %q: missing or invalid S", vector)
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
		return 0, fmt.Errorf("CVSS vector %q: missing or invalid PR", vector)
	}

	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, nil
	}
	exploitability := 8.22 * w["AV"] * w["AC"] * pr * w["UI"]
	if changed {
		return roundup(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return roundup(math.Min(impact+exploitability, 10)), nil
}

// roundup is the CVSS v3.1 Roundup: smallest one-decimal number >= x, computed
// on integers to avoid floating-point artefacts (spec Appendix A).
func roundup(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
