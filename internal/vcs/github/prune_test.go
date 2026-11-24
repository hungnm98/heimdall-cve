package github

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

func TestPrune(t *testing.T) {
	t.Parallel()
	p := setupSSH(t)
	ctx := context.Background()
	r := model.Repo{Provider: "github", Host: "github.com", Owner: "acme", Name: "api", Ref: "main"}
	sha, err := p.ResolveRef(ctx, r, "main")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.ReadFile(ctx, r, sha, "go.mod"); err != nil {
		t.Fatal(err)
	}
	dir := p.mirrorDir(r)
	again := func() { _ = os.Remove(filepath.Join(p.ws, pruneMarker)) } // lift the daily rate limit
	now := time.Now()

	// Recently used, recent commits: nothing to do.
	res, err := p.Prune(ctx, now.Add(-time.Hour))
	if err != nil || res.Mirrors != 0 || res.Refs != 0 {
		t.Fatalf("prune of a fresh workspace = %+v, %v", res, err)
	}
	// Rate limited: a second call the same day does nothing even with a cutoff in the future.
	if res, _ := p.Prune(ctx, now.Add(time.Hour)); res.Mirrors != 0 {
		t.Fatal("prune must run at most once per day")
	}

	// The mirror is in use but its commits are older than the cutoff: the
	// commit refs go, the mirror stays, and reading the commit again works.
	again()
	future := now.Add(2 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, usedMarker), future, future); err != nil {
		t.Fatal(err)
	}
	res, err = p.Prune(ctx, now.Add(time.Hour))
	if err != nil || res.Mirrors != 0 || res.Refs == 0 {
		t.Fatalf("old commits: %+v, %v", res, err)
	}
	if refs := git(t, dir, "for-each-ref", commitRefPrefix); strings.TrimSpace(refs) != "" {
		t.Fatalf("commit refs left: %s", refs)
	}
	if b, err := p.ReadFile(ctx, r, sha, "go.mod"); err != nil || len(b) == 0 {
		t.Fatalf("re-read after prune: %v", err)
	}

	// Unused mirror: deleted, and the next read clones it again.
	again()
	if res, err := p.Prune(ctx, now.Add(3*time.Hour)); err != nil || res.Mirrors != 1 {
		t.Fatalf("unused mirror: %+v, %v", res, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("mirror not deleted")
	}
	if _, err := p.ResolveRef(ctx, r, "main"); err != nil {
		t.Fatalf("resolve after mirror removal: %v", err)
	}
}
