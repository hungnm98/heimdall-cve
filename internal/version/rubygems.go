package version

import (
	"regexp"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// RubyGems implements Comparator with Gem::Version semantics:
//
//   - A version is split on "." and at digit/letter boundaries:
//     "1.0.0.pre1" → 1, 0, 0, "pre", 1.
//   - "-" is read as ".pre." ("1.0.0-beta" == "1.0.0.pre.beta").
//   - Segments compare pairwise; a missing segment counts as 0; a string
//     segment marks a prerelease and sorts before any number
//     ("1.0.0.rc1" < "1.0.0"); strings compare bytewise, numbers numerically.
//   - Trailing zero segments are ignored ("1.0" == "1.0.0"), both at the end
//     of the release part and at the end of the prerelease part.
type RubyGems struct{}

var _ Comparator = RubyGems{}

// gemVersionRe is Gem::Version::ANCHORED_VERSION_PATTERN without the empty
// version (RubyGems reads "" as "0"; here it is junk).
var gemVersionRe = regexp.MustCompile(`^[0-9]+(\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

func (RubyGems) Valid(v string) bool { return gemVersionRe.MatchString(strings.TrimSpace(v)) }

// gemSegment is a numeric segment (digits without leading zeros) or a string one.
type gemSegment struct {
	num string // set for numeric segments ("0" for zero)
	str string // set for string segments
}

func (s gemSegment) numeric() bool { return s.str == "" }

// gemSegments splits a valid version into segments.
func gemSegments(v string) []gemSegment {
	v = strings.ReplaceAll(strings.TrimSpace(v), "-", ".pre.")
	var out []gemSegment
	for i := 0; i < len(v); {
		c := v[i]
		j := i + 1
		switch {
		case gemIsDigit(c):
			for j < len(v) && gemIsDigit(v[j]) {
				j++
			}
			n := strings.TrimLeft(v[i:j], "0")
			if n == "" {
				n = "0"
			}
			out = append(out, gemSegment{num: n})
		case gemIsLetter(c):
			for j < len(v) && gemIsLetter(v[j]) {
				j++
			}
			out = append(out, gemSegment{str: v[i:j]})
		}
		i = j
	}
	return out
}

// gemCanonical drops trailing zeros from the release part and from the
// prerelease part (Gem::Version#canonical_segments).
func gemCanonical(segs []gemSegment) []gemSegment {
	split := len(segs)
	for i, s := range segs {
		if !s.numeric() {
			split = i
			break
		}
	}
	trim := func(p []gemSegment) []gemSegment {
		for len(p) > 0 && p[len(p)-1].numeric() && p[len(p)-1].num == "0" {
			p = p[:len(p)-1]
		}
		return p
	}
	rel := trim(append([]gemSegment(nil), segs[:split]...))
	return append(rel, trim(segs[split:])...)
}

func (r RubyGems) Compare(a, b string) int {
	va, vb := r.Valid(a), r.Valid(b)
	switch {
	case !va && !vb:
		return 0
	case !va:
		return -1
	case !vb:
		return 1
	}
	sa, sb := gemCanonical(gemSegments(a)), gemCanonical(gemSegments(b))
	zero := gemSegment{num: "0"}
	for i := 0; i < max(len(sa), len(sb)); i++ {
		x, y := zero, zero
		if i < len(sa) {
			x = sa[i]
		}
		if i < len(sb) {
			y = sb[i]
		}
		if x == y {
			continue
		}
		switch {
		case !x.numeric() && y.numeric():
			return -1
		case x.numeric() && !y.numeric():
			return 1
		case !x.numeric():
			return strings.Compare(x.str, y.str)
		}
		if len(x.num) != len(y.num) {
			if len(x.num) < len(y.num) {
				return -1
			}
			return 1
		}
		return strings.Compare(x.num, y.num)
	}
	return 0
}

// Bump classifies by the first three numeric (release) segments, missing
// ones read as 0. Like Go and npm, a minor bump on 0.x is breaking. Any
// other upgrade (4th segment, prerelease → release) is a patch.
func (r RubyGems) Bump(from, to string) model.BumpType {
	if !r.Valid(from) || !r.Valid(to) || r.Compare(to, from) <= 0 {
		return model.BumpNone
	}
	f, t := gemRelease(from), gemRelease(to)
	switch {
	case f[0] != t[0]:
		return model.BumpMajor
	case f[1] != t[1]:
		if f[0] == "0" {
			return model.BumpMajor
		}
		return model.BumpMinor
	}
	return model.BumpPatch
}

// gemRelease returns the first three release segments, "0"-padded.
func gemRelease(v string) [3]string {
	out := [3]string{"0", "0", "0"}
	for i, s := range gemSegments(v) {
		if i == 3 || !s.numeric() {
			break
		}
		out[i] = s.num
	}
	return out
}

func gemIsDigit(c byte) bool  { return c >= '0' && c <= '9' }
func gemIsLetter(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }
