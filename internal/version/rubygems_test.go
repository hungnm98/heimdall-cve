package version

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

func TestRubyGemsValid(t *testing.T) {
	r := RubyGems{}
	for _, v := range []string{"1", "1.0", "1.0.0", "1.0.0.pre1", "2.0.0.rc1", "1.0.0-beta", "1.0.0-beta.2", "7.1.3.4", " 1.2.3 ", "1.a"} {
		if !r.Valid(v) {
			t.Errorf("Valid(%q) = false", v)
		}
	}
	for _, v := range []string{"", "junk", "~> 1.2", ">= 1.0", "1..2", "1.2.", ".1", "v1.2.3", "1.2.3 4", "1.2-", "1.16.2_x86"} {
		if r.Valid(v) {
			t.Errorf("Valid(%q) = true", v)
		}
	}
}

func TestRubyGemsCompare(t *testing.T) {
	r := RubyGems{}
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0.pre", "1.0.0", -1},
		{"1.0.0", "1.0.0.1", -1},
		{"1.0.0.pre", "1.0.0.1", -1},
		{"1.10", "1.9", 1},
		{"1.9.10", "1.9.9", 1},
		{"2.0.0.rc1", "2.0.0", -1},
		{"2.0.0.rc1", "2.0.0.rc2", -1},
		{"2.0.0.beta1", "2.0.0.rc1", -1},
		{"1.0", "1.0.0", 0},
		{"1", "1.0.0.0", 0},
		{"1.0.0-beta", "1.0.0.pre.beta", 0},
		{"1.0.0-beta", "1.0.0", -1},
		{"1.0.0-beta", "0.9.9", 1},
		{"1.0.0.pre1", "1.0.0.pre.1", 0},
		{"1.0.a", "1.a", 0},
		{"1.0.a.0", "1.0.a", 0},
		{"1.0.0.a", "1.0.0.b", -1},
		{"1.0.0.A", "1.0.0.a", -1}, // bytewise
		{"007.1", "7.1", 0},
		{"18446744073709551616", "18446744073709551615", 1},
		{"7.1.3.4", "7.1.3", 1},
		{"1.16.2", "1.16.10", -1},
		{"junk", "1.0", -1},
		{"1.0", "junk", 1},
		{"junk", "trash", 0},
	}
	for _, c := range cases {
		if got := r.Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := r.Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func TestRubyGemsBump(t *testing.T) {
	r := RubyGems{}
	cases := []struct {
		from, to string
		want     model.BumpType
	}{
		{"7.1.3", "7.1.3.4", model.BumpPatch},
		{"1.16.2", "1.16.5", model.BumpPatch},
		{"2.0.0.rc1", "2.0.0", model.BumpPatch},
		{"1.2", "1.3", model.BumpMinor},
		{"6.1.7", "7.0.8", model.BumpMajor},
		{"0.3.0", "0.4.0", model.BumpMajor},
		{"0.3.0", "0.3.1", model.BumpPatch},
		{"1", "1.0.1", model.BumpPatch},
		{"1.0.0", "1.0.0", model.BumpNone},
		{"2.0", "1.9", model.BumpNone},
		{"junk", "1.0", model.BumpNone},
	}
	for _, c := range cases {
		if got := r.Bump(c.from, c.to); got != c.want {
			t.Errorf("Bump(%q, %q) = %q, want %q", c.from, c.to, got, c.want)
		}
	}
}
