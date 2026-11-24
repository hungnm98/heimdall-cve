package core

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

func TestPriority(t *testing.T) {
	dep := func(mod func(*model.Finding)) model.Finding {
		f := model.Finding{Kind: model.KindDependency, Direct: true, Scope: model.ScopeProd, Severity: model.SeverityCritical}
		mod(&f)
		return f
	}
	cases := []struct {
		name     string
		f        model.Finding
		min, max float64
	}{
		{"log4shell: KEV, CVSS 10", dep(func(f *model.Finding) { f.CVSSScore, f.InKEV, f.EPSS = 10, true, 0.94 }), 100, 100},
		{"malicious package without CVSS", dep(func(f *model.Finding) { f.Malicious = true }), 99, 100},
		{"KEV with a medium CVSS", dep(func(f *model.Finding) { f.CVSSScore, f.InKEV = 5, true }), 98, 98},
		{"likely exploited (EPSS 0.5)", dep(func(f *model.Finding) { f.CVSSScore, f.EPSS = 9.8, 0.5 }), 70, 89},
		{"critical, negligible EPSS", dep(func(f *model.Finding) { f.CVSSScore, f.EPSS = 9.8, 0.001 }), 60, 69},
		{"critical without CVSS", dep(func(f *model.Finding) {}), 60, 69},
		{"low", dep(func(f *model.Finding) { f.CVSSScore = 3.1 }), 15, 25},
		{"KEV but dev-only", dep(func(f *model.Finding) { f.CVSSScore, f.InKEV, f.Scope = 10, true, model.ScopeDev }), 50, 50},
		{"KEV, indirect: not scaled down", dep(func(f *model.Finding) { f.CVSSScore, f.InKEV, f.Direct = 10, true, false }), 100, 100},
		{"critical, indirect", dep(func(f *model.Finding) { f.CVSSScore, f.Direct = 9.8, false }), 55, 60},
	}
	for _, c := range cases {
		if got := priority(c.f); got < c.min || got > c.max {
			t.Errorf("%s: priority = %v, want [%v, %v]", c.name, got, c.min, c.max)
		}
	}
	// Every KEV finding outranks every non-KEV finding in the same context.
	if kev, top := priority(dep(func(f *model.Finding) { f.CVSSScore, f.InKEV = 0.1, true })),
		priority(dep(func(f *model.Finding) { f.CVSSScore, f.EPSS = 10, 1 })); kev <= top {
		t.Errorf("KEV %v must outrank non-KEV %v", kev, top)
	}
}
