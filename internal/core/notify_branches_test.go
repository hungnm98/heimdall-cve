package core

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

func TestGroupAcrossBranches(t *testing.T) {
	mk := func(branch, adv string) model.Finding {
		f := model.Finding{Kind: model.KindDependency, Provider: "github", Repo: "acme/web", ManifestPath: "package.json",
			Package: model.NewPackage(model.EcosystemNPM, "lodash", "4.17.15"), AdvisoryID: adv, Branch: branch}
		f.ComputeID()
		return f
	}
	g := groupAcrossBranches([]model.Finding{mk("develop", "A"), mk("", "A"), mk("release/1", "A"), mk("develop", "B")})
	if len(g) != 2 || len(g[0]) != 3 || g[0][0].Branch != "" || len(g[1]) != 1 {
		t.Fatalf("groups = %+v", g)
	}
	if got := branchNote(g[0]); got != " (also on develop, release/1)" {
		t.Fatalf("note = %q", got)
	}
	if got := branchNote(g[1]); got != " (on develop)" {
		t.Fatalf("note = %q", got)
	}
	if baseID(g[1][0]) != mk("", "B").ID {
		t.Fatal("baseID must be the primary-branch ID")
	}
}
