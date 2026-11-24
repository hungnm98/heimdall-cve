// Package runtimetest is the contract test kit for runtime.Detector.
package runtimetest

import (
	"context"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/runtime"
)

// Case is one fixture.
type Case struct {
	Name  string
	Files map[string]string
	Want  []model.Runtime // compared on Name, Version, Origin, Via
}

// Run executes the contract plus the given cases.
func Run(t *testing.T, d runtime.Detector, cases []Case) {
	t.Helper()
	if d.Name() == "" || d.Runtime() == "" {
		t.Fatal("Name() and Runtime() must be set")
	}
	if rts, err := d.Detect(context.Background(), model.FileSet{}); err != nil || len(rts) != 0 {
		t.Errorf("Detect(empty) = %v, %v; want none", rts, err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			fs := model.FileSet{Files: map[string][]byte{}}
			for p, s := range c.Files {
				fs.Files[p] = []byte(s)
			}
			got, err := d.Detect(context.Background(), fs)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			have := map[model.Runtime]bool{}
			for _, r := range got {
				if r.Name != d.Runtime() || r.Origin == "" {
					t.Errorf("runtime %+v: Name must be %q and Origin set", r, d.Runtime())
				}
				have[r] = true
			}
			for _, w := range c.Want {
				if !have[w] {
					t.Errorf("missing %+v; got %+v", w, got)
				}
			}
			if len(got) != len(c.Want) {
				t.Errorf("got %d runtimes, want %d: %+v", len(got), len(c.Want), got)
			}
		})
	}
}
