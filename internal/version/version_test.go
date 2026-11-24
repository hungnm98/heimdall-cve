package version

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

func TestGoCompare(t *testing.T) {
	g := Go{}
	cases := []struct {
		a, b string
		want int
	}{
		{"v1.2.3", "v1.2.4", -1},
		{"1.2.3", "v1.2.3", 0},
		{"v2.0.0+incompatible", "v1.9.9", 1},
		{"v0.0.0-20240101000000-abcdefabcdef", "v0.1.0", -1},
		{"v1.0.0-rc.1", "v1.0.0", -1},
	}
	for _, c := range cases {
		if got := g.Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
	if g.Valid("not-a-version") || !g.Valid("v1.2.3") {
		t.Error("Valid")
	}
}

func TestGoBump(t *testing.T) {
	g := Go{}
	cases := []struct {
		from, to string
		want     model.BumpType
	}{
		{"v1.2.3", "v1.2.9", model.BumpPatch},
		{"v1.2.3", "v1.3.0", model.BumpMinor},
		{"v1.2.3", "v2.0.0", model.BumpMajor},
		{"v0.3.1", "v0.4.0", model.BumpMajor},
		{"v0.3.1", "v0.3.2", model.BumpPatch},
		{"v1.2.3", "v1.2.3", model.BumpNone},
		{"v1.2.3", "v1.0.0", model.BumpNone},
	}
	for _, c := range cases {
		if got := g.Bump(c.from, c.to); got != c.want {
			t.Errorf("Bump(%s,%s) = %q, want %q", c.from, c.to, got, c.want)
		}
	}
}
