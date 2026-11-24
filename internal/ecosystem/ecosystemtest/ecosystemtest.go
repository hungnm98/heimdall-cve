// Package ecosystemtest is the contract test kit for ecosystem.Ecosystem.
package ecosystemtest

import (
	"context"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/model"
)

// Dep is an expected dependency.
type Dep struct {
	Manifest     string
	Name         string
	Version      string
	Direct       bool
	Private      bool
	Unresolvable bool
}

// Case is one fixture: repo files in, dependencies out.
type Case struct {
	Name   string
	Files  map[string]string
	Want   []Dep    // every listed dep must be present with these fields
	Absent []string // names that must not appear (e.g. replaced modules)
}

// Run executes the contract plus the given fixture cases.
func Run(t *testing.T, e ecosystem.Ecosystem, matches, nonMatches []string, cases []Case) {
	t.Helper()
	if e.Name() == "" || e.Versions() == nil {
		t.Fatal("Name() and Versions() must be set")
	}
	for _, p := range matches {
		if !e.Match(p) {
			t.Errorf("Match(%q) = false, want true", p)
		}
	}
	for _, p := range nonMatches {
		if e.Match(p) {
			t.Errorf("Match(%q) = true, want false", p)
		}
	}
	if gs, err := e.Parse(context.Background(), model.FileSet{}); err != nil || len(gs) != 0 {
		t.Errorf("Parse(empty) = %d graphs, %v; want none, nil", len(gs), err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			fs := model.FileSet{Files: map[string][]byte{}}
			for p, s := range c.Files {
				fs.Files[p] = []byte(s)
			}
			graphs, err := e.Parse(context.Background(), fs)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := map[string]model.Dependency{}
			for _, g := range graphs {
				if g.Ecosystem != e.Name() || g.ManifestPath == "" {
					t.Errorf("graph %q: Ecosystem/ManifestPath not set", g.ManifestPath)
				}
				for _, d := range g.Dependencies {
					if d.PURL == "" || d.PURL != model.BuildPURL(d.Ecosystem, d.Name, d.Version) {
						t.Errorf("%s: PURL %q not built with model.NewPackage", d.Name, d.PURL)
					}
					got[g.ManifestPath+"|"+d.Name] = d
				}
			}
			for _, w := range c.Want {
				d, ok := got[w.Manifest+"|"+w.Name]
				if !ok {
					t.Errorf("missing %s in %s", w.Name, w.Manifest)
					continue
				}
				if d.Version != w.Version || d.Direct != w.Direct || d.Private != w.Private || (d.Unresolvable != "") != w.Unresolvable {
					t.Errorf("%s: got version=%s direct=%v private=%v unresolvable=%q; want %+v",
						w.Name, d.Version, d.Direct, d.Private, d.Unresolvable, w)
				}
			}
			for _, name := range c.Absent {
				for k, d := range got {
					if d.Name == name {
						t.Errorf("%s must be absent, found %s", name, k)
					}
				}
			}
		})
	}
}
