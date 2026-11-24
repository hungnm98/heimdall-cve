package core

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

func TestStdlibGraphsOnePerVersion(t *testing.T) {
	rts := []model.Runtime{
		{Name: "go", Version: "1.26.2", Origin: ".circleci/actions/base/Dockerfile", Via: "Dockerfile FROM"},
		{Name: "go", Version: "1.26.2", Origin: "Dockerfile", Via: "Dockerfile FROM"},
		{Name: "go", Version: "1.26.2", Origin: ".tool-versions", Via: ".tool-versions"},
		{Name: "go", Version: "1.26.2", Origin: ".github/workflows/ci.yml", Via: "actions/setup-go"},
		{Name: "go", Version: "1.24.6", Origin: "tools/Dockerfile", Via: "Dockerfile FROM"},
		{Name: "go", Version: "1.26", Origin: "go.mod", Via: "go directive"}, // minimum only: skipped
		{Name: "go", Version: "1.25.3", Origin: "go.mod", Via: "toolchain"},
		{Name: "go", Version: "1.25.3", Origin: ".tool-versions", Via: ".tool-versions"},
		{Name: "node", Version: "20.1.0", Origin: ".nvmrc", Via: ".nvmrc"},
	}
	gs := stdlibGraphs(rts)
	got := map[string]string{}
	for _, g := range gs {
		if len(g.Dependencies) != 1 || g.Dependencies[0].Name != "stdlib" {
			t.Fatalf("graph %+v", g)
		}
		got[g.Dependencies[0].Version] = g.ManifestPath
	}
	want := map[string]string{"1.26.2": ".tool-versions", "1.24.6": "tools/Dockerfile", "1.25.3": "go.mod"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for v, origin := range want {
		if got[v] != origin {
			t.Errorf("stdlib %s reported at %q, want %q", v, got[v], origin)
		}
	}
}
