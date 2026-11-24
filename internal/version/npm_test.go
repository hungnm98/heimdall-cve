package version

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

func TestNPM(t *testing.T) {
	n := NPM{}
	if n.Compare("4.17.15", "4.17.21") != -1 || n.Compare("1.0.0-beta.2", "1.0.0") != -1 || n.Compare("=1.2.3", "v1.2.3+build.5") != 0 {
		t.Fatal("Compare")
	}
	if !n.Valid("1.2.3-rc.1") || n.Valid("^1.2.3") || n.Valid("latest") {
		t.Fatal("Valid")
	}
	if n.Bump("4.17.15", "4.17.21") != model.BumpPatch || n.Bump("0.3.0", "0.4.0") != model.BumpMajor || n.Bump("1.2.0", "2.0.0") != model.BumpMajor {
		t.Fatal("Bump")
	}
}
