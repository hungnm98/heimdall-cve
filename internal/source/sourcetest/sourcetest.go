// Package sourcetest is the contract test kit for sources. Source tests run
// against recorded responses (httptest), never the live network.
package sourcetest

import (
	"context"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/source"
)

// VulnCase is one query and the advisory IDs (or aliases) it must return.
type VulnCase struct {
	Name     string
	Packages []model.Package
	WantIDs  []string
}

// RunVuln executes the VulnSource contract plus cases.
func RunVuln(t *testing.T, s source.VulnSource, cases []VulnCase) {
	t.Helper()
	ctx := context.Background()
	if s.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
	if adv, err := s.Query(ctx, nil); err != nil || len(adv) != 0 {
		t.Errorf("Query(nil) = %d advisories, %v; want none, nil", len(adv), err)
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			for _, p := range c.Packages {
				if !s.Supports(p.Ecosystem) {
					t.Fatalf("Supports(%s) = false for a case package", p.Ecosystem)
				}
			}
			advs, err := s.Query(ctx, c.Packages)
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			queried := map[string]bool{}
			for _, p := range c.Packages {
				queried[string(p.Ecosystem)+"|"+p.Name] = true
			}
			found := map[string]bool{}
			for _, a := range advs {
				if a.ID == "" {
					t.Error("advisory without ID")
				}
				if len(a.Sources) == 0 {
					t.Errorf("%s: Sources must include the source name", a.ID)
				}
				matched := false
				for _, af := range a.Affected {
					matched = matched || queried[string(af.Ecosystem)+"|"+af.Name]
				}
				if !matched {
					t.Errorf("%s: Affected does not name any queried package", a.ID)
				}
				for _, id := range a.IDs() {
					found[id] = true
				}
			}
			for _, id := range c.WantIDs {
				if !found[id] {
					t.Errorf("missing advisory %s", id)
				}
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if len(cases) > 0 && len(cases[0].Packages) > 0 {
		if _, err := s.Query(canceled, cases[0].Packages); err == nil {
			t.Error("Query with a canceled context must fail")
		}
	}
}

// RuntimeCase is one runtime and its expected status.
type RuntimeCase struct {
	Name    string
	Runtime model.Runtime
	Want    model.SupportStatus
}

// RunRuntime executes the RuntimeSource contract plus cases.
func RunRuntime(t *testing.T, s source.RuntimeSource, cases []RuntimeCase) {
	t.Helper()
	if s.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			if !s.Supports(c.Runtime.Name) {
				t.Fatalf("Supports(%s) = false", c.Runtime.Name)
			}
			st, err := s.Evaluate(context.Background(), c.Runtime)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if st.Status != c.Want || st.Source == "" || st.Runtime != c.Runtime {
				t.Errorf("Evaluate = status %s source %q runtime %+v; want status %s, source set, runtime echoed",
					st.Status, st.Source, st.Runtime, c.Want)
			}
		})
	}
}
