// Package vcstest is the contract test kit for vcs.Provider. A provider test
// wires the provider to a fake server or local repo, then calls Run with what
// that fixture contains.
package vcstest

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/vcs"
)

// Fixture describes what the provider under test must return.
type Fixture struct {
	Target    model.Target      // target to list
	WantRepos []string          // full names expected from ListRepos (any order)
	Repo      string            // full name of the repo to inspect further
	WantRef   string            // expected Repo.Ref for Repo
	WantFiles map[string]string // path → content that must exist at HEAD of WantRef
}

// Run executes the contract.
func Run(t *testing.T, p vcs.Provider, fx Fixture) {
	t.Helper()
	ctx := context.Background()
	if p.Name() == "" {
		t.Fatal("Name() must not be empty")
	}
	repos, err := p.ListRepos(ctx, fx.Target)
	if err != nil {
		t.Fatalf("ListRepos: %v", err)
	}
	var got []string
	var repo *model.Repo
	for i, r := range repos {
		got = append(got, r.FullName())
		if r.Provider == "" || r.Owner == "" || r.Name == "" || r.Ref == "" {
			t.Errorf("repo %+v: Provider, Owner, Name and Ref must be set", r)
		}
		if r.FullName() == fx.Repo {
			repo = &repos[i]
		}
	}
	sort.Strings(got)
	want := append([]string(nil), fx.WantRepos...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("ListRepos = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("ListRepos = %v, want %v", got, want)
		}
	}
	if repo == nil {
		t.Fatalf("fixture repo %s not listed", fx.Repo)
	}
	if fx.WantRef != "" && repo.Ref != fx.WantRef {
		t.Errorf("Repo.Ref = %q, want %q", repo.Ref, fx.WantRef)
	}

	sha, err := p.ResolveRef(ctx, *repo, repo.Ref)
	if err != nil || sha == "" {
		t.Fatalf("ResolveRef(%s) = %q, %v", repo.Ref, sha, err)
	}
	if _, err := p.ResolveRef(ctx, *repo, "heimdall-no-such-branch"); !errors.Is(err, vcs.ErrNotFound) {
		t.Errorf("ResolveRef(missing) err = %v, want vcs.ErrNotFound", err)
	}
	files, err := p.ListFiles(ctx, *repo, sha)
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	have := map[string]bool{}
	for _, f := range files {
		have[f] = true
	}
	for path, content := range fx.WantFiles {
		if !have[path] {
			t.Errorf("ListFiles missing %s", path)
		}
		b, err := p.ReadFile(ctx, *repo, sha, path)
		if err != nil || string(b) != content {
			t.Errorf("ReadFile(%s) = %q, %v; want %q", path, b, err, content)
		}
	}
	if _, err := p.ReadFile(ctx, *repo, sha, "heimdall/no/such/file"); !errors.Is(err, vcs.ErrNotFound) {
		t.Errorf("ReadFile(missing) err = %v, want vcs.ErrNotFound", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := p.ListRepos(canceled, fx.Target); err == nil {
		t.Error("ListRepos with a canceled context must fail")
	}
}
