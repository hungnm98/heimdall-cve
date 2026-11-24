package gomod

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/ecosystem/ecosystemtest"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
)

// fixture loads testdata/<dir> as repo files keyed by slash path relative to it.
func fixture(t *testing.T, dir string) map[string]string {
	t.Helper()
	root := filepath.Join("testdata", dir)
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		out[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func newGoMod(t *testing.T, private ...string) ecosystem.Ecosystem {
	t.Helper()
	e, err := New(nil, ecosystem.Options{PrivatePatterns: private}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

type dep = ecosystemtest.Dep

func TestContract(t *testing.T) {
	matches := []string{"go.mod", "go.work", "services/api/go.mod", "a/b/c/go.work"}
	nonMatches := []string{
		"go.sum", "go.work.sum", "main.go", "go.mod.bak", "mygo.mod",
		"vendor/github.com/x/y/go.mod", "pkg/testdata/go.mod", "a/vendor/go.mod",
	}
	cases := []ecosystemtest.Case{
		{
			Name:  "plain",
			Files: fixture(t, "plain"),
			Want: []dep{
				{Manifest: "go.mod", Name: "github.com/google/uuid", Version: "v1.6.0", Direct: true},
				{Manifest: "go.mod", Name: "github.com/spf13/cobra", Version: "v1.8.0", Direct: true},
			},
		},
		{
			Name:  "indirect",
			Files: fixture(t, "indirect"),
			Want: []dep{
				{Manifest: "go.mod", Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Direct: true},
				{Manifest: "go.mod", Name: "github.com/stretchr/testify", Version: "v1.8.4", Direct: true},
				{Manifest: "go.mod", Name: "github.com/bytedance/sonic", Version: "v1.9.1"},
				{Manifest: "go.mod", Name: "github.com/go-playground/validator/v10", Version: "v10.14.0"},
				{Manifest: "go.mod", Name: "golang.org/x/crypto", Version: "v0.17.0"},
				{Manifest: "go.mod", Name: "gopkg.in/yaml.v3", Version: "v3.0.1"},
			},
		},
		{
			Name:  "replace",
			Files: fixture(t, "replace"),
			Want: []dep{
				{Manifest: "go.mod", Name: "github.com/new/lib", Version: "v1.3.1", Direct: true},
				{Manifest: "go.mod", Name: "github.com/local/thing", Version: "v0.3.0", Direct: true, Unresolvable: true},
				{Manifest: "go.mod", Name: "github.com/fork/ver", Version: "v1.5.1-patched", Direct: true},
				{Manifest: "go.mod", Name: "github.com/pinned/only", Version: "v1.1.0", Direct: true},
				{Manifest: "go.mod", Name: "gopkg.in/yaml.v2", Version: "v2.4.1"},
			},
			Absent: []string{"github.com/old/lib", "github.com/any/ver", "github.com/fork/only"},
		},
		{
			Name:  "exclude",
			Files: fixture(t, "exclude"),
			Want: []dep{
				{Manifest: "go.mod", Name: "github.com/kept/mod", Version: "v1.1.0", Direct: true},
			},
			Absent: []string{"github.com/excluded/mod"},
		},
		{
			Name:  "pseudo-and-incompatible",
			Files: fixture(t, "pseudo"),
			Want: []dep{
				{Manifest: "go.mod", Name: "github.com/docker/docker", Version: "v24.0.7+incompatible", Direct: true},
				{Manifest: "go.mod", Name: "golang.org/x/net", Version: "v0.0.0-20240108191215-35c4d3a8b2e3", Direct: true},
				{Manifest: "go.mod", Name: "github.com/pkg/errors", Version: "v0.9.2-0.20201214064552-5dd12d0cfe7f"},
			},
			Absent: []string{"github.com/dgrijalva/jwt-go"},
		},
		{
			Name:  "monorepo-go-work",
			Files: fixture(t, "monorepo"),
			Want: []dep{
				// go.work replace applies to every used module and wins over go.mod's own.
				{Manifest: "services/api/go.mod", Name: "github.com/acme/logrus", Version: "v1.9.4-acme.1", Direct: true},
				{Manifest: "services/api/go.mod", Name: "github.com/labstack/echo/v4", Version: "v4.11.4", Direct: true},
				{Manifest: "services/api/go.mod", Name: "github.com/acme/mono/libs/shared", Version: "v0.0.0-00010101000000-000000000000", Direct: true, Unresolvable: true},
				{Manifest: "services/worker/go.mod", Name: "github.com/acme/logrus", Version: "v1.9.4-acme.1", Direct: true},
				{Manifest: "services/worker/go.mod", Name: "github.com/hibiken/asynq", Version: "v0.24.1", Direct: true},
				{Manifest: "services/worker/go.mod", Name: "github.com/redis/go-redis/v9", Version: "v9.3.0"},
				{Manifest: "libs/shared/go.mod", Name: "golang.org/x/sync", Version: "v0.6.0", Direct: true},
			},
			Absent: []string{"github.com/sirupsen/logrus"},
		},
	}
	ecosystemtest.Run(t, newGoMod(t), matches, nonMatches, cases)
}

func TestPrivate(t *testing.T) {
	e := newGoMod(t, "github.com/acme/*", "*.corp.example.com")
	ecosystemtest.Run(t, e, []string{"go.mod"}, nil, []ecosystemtest.Case{{
		Name:  "private",
		Files: fixture(t, "private"),
		Want: []dep{
			{Manifest: "go.mod", Name: "github.com/acme/billing/v2", Version: "v2.1.0", Direct: true, Private: true},
			{Manifest: "go.mod", Name: "git.corp.example.com/team/auth", Version: "v1.0.0", Direct: true, Private: true},
			{Manifest: "go.mod", Name: "github.com/acmeinc/public", Version: "v1.0.0", Direct: true},
			{Manifest: "go.mod", Name: "github.com/acme/lib-fork", Version: "v1.2.0-acme.1", Private: true},
			{Manifest: "go.mod", Name: "github.com/google/uuid", Version: "v1.6.0", Direct: true},
		},
		Absent: []string{"github.com/public/lib"},
	}})
}

func TestNewRejectsBadPattern(t *testing.T) {
	for _, p := range []string{"github.com/[acme", "a,b"} {
		if _, err := New(nil, ecosystem.Options{PrivatePatterns: []string{p}}, plugin.Deps{}); err == nil {
			t.Errorf("pattern %q: want error", p)
		}
	}
	if _, err := New(plugin.Config{"unknown": 1}, ecosystem.Options{}, plugin.Deps{}); err == nil {
		t.Error("unknown config key: want error")
	}
}

func TestGraphShape(t *testing.T) {
	files := model.FileSet{Files: map[string][]byte{}}
	for p, s := range fixture(t, "monorepo") {
		files.Files[p] = []byte(s)
	}
	gs, err := newGoMod(t).Parse(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"libs/shared/go.mod", "services/api/go.mod", "services/worker/go.mod"}
	if len(gs) != len(want) {
		t.Fatalf("got %d graphs, want %d (go.work must not produce a graph)", len(gs), len(want))
	}
	for i, g := range gs {
		if g.ManifestPath != want[i] {
			t.Errorf("graph %d = %s, want %s (sorted)", i, g.ManifestPath, want[i])
		}
		for _, d := range g.Dependencies {
			if d.Scope != model.ScopeProd || d.Approximate {
				t.Errorf("%s: scope=%s approximate=%v, want prod/false", d.Name, d.Scope, d.Approximate)
			}
		}
	}
}

func TestParseErrorKeepsOtherGraphs(t *testing.T) {
	files := model.FileSet{Files: map[string][]byte{
		"ok/go.mod":  []byte("module example.com/ok\n\ngo 1.22\n\nrequire example.com/dep v1.0.0\n"),
		"bad/go.mod": []byte("module example.com/bad\n\nrequire example.com/dep not-a-version\n"),
	}}
	gs, err := newGoMod(t).Parse(context.Background(), files)
	if err == nil {
		t.Error("want an error for bad/go.mod")
	}
	if len(gs) != 1 || gs[0].ManifestPath != "ok/go.mod" || len(gs[0].Dependencies) != 1 {
		t.Errorf("want the ok/go.mod graph, got %+v", gs)
	}
}
