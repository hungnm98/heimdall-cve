//go:build live

package osv

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/httpx"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/source/sourcetest"
)

// TestLive checks the query formats against api.osv.dev:
// go test -tags=live ./internal/source/osv/
func TestLive(t *testing.T) {
	s, err := New(plugin.Config{}, plugin.Deps{HTTP: httpx.New(httpx.Options{})})
	if err != nil {
		t.Fatal(err)
	}
	sourcetest.RunVuln(t, s, []sourcetest.VulnCase{
		{
			Name:     "go module with v prefix",
			Packages: []model.Package{model.NewPackage(model.EcosystemGo, "google.golang.org/protobuf", "v1.32.0")},
			WantIDs:  []string{"GO-2024-2611", "CVE-2024-24786"},
		},
		{
			Name:     "go stdlib with go prefix",
			Packages: []model.Package{model.NewPackage(model.EcosystemGo, "stdlib", "go1.22.1")},
			WantIDs:  []string{"GO-2024-2887"},
		},
		{
			Name:     "npm",
			Packages: []model.Package{model.NewPackage(model.EcosystemNPM, "lodash", "4.17.15")},
			WantIDs:  []string{"GHSA-p6mc-m468-83gw"},
		},
		{
			Name:     "rubygems",
			Packages: []model.Package{model.NewPackage(model.EcosystemRubyGems, "rack", "2.2.8")},
			WantIDs:  []string{"GHSA-22f2-v57c-j9cx"},
		},
	})
}
