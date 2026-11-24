package npm

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func newNPM(t *testing.T, private ...string) ecosystem.Ecosystem {
	t.Helper()
	e, err := New(nil, ecosystem.Options{PrivatePatterns: private}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func parse(t *testing.T, e ecosystem.Ecosystem, files map[string]string) []*model.DependencyGraph {
	t.Helper()
	fs := model.FileSet{Files: map[string][]byte{}}
	for p, s := range files {
		fs.Files[p] = []byte(s)
	}
	gs, err := e.Parse(context.Background(), fs)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return gs
}

func manifests(gs []*model.DependencyGraph) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.ManifestPath)
	}
	return out
}

// find returns the dependency name@version of a manifest's graph.
func find(t *testing.T, gs []*model.DependencyGraph, manifest, name, version string) model.Dependency {
	t.Helper()
	for _, g := range gs {
		if g.ManifestPath != manifest {
			continue
		}
		for _, d := range g.Dependencies {
			if d.Name == name && d.Version == version {
				return d
			}
		}
	}
	t.Fatalf("%s@%s not found in %s", name, version, manifest)
	return model.Dependency{}
}

type dep = ecosystemtest.Dep

func TestContract(t *testing.T) {
	matches := []string{
		"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
		"apps/web/package.json", "packages/a/yarn.lock",
	}
	nonMatches := []string{
		"node_modules/lodash/package.json", "packages/a/node_modules/x/package.json",
		"node_modules/.package-lock.json", "package.json5", "bun.lockb", "pnpm-workspace.yaml",
		"tsconfig.json", "mypackage.json",
	}
	cases := []ecosystemtest.Case{
		{
			Name:  "package-lock v1",
			Files: fixture(t, "lock-v1"),
			Want: []dep{
				{Manifest: "package-lock.json", Name: "express", Version: "4.17.1", Direct: true},
				{Manifest: "package-lock.json", Name: "accepts", Version: "1.3.7"},
				{Manifest: "package-lock.json", Name: "mime-db", Version: "1.52.0"},
				{Manifest: "package-lock.json", Name: "mocha", Version: "10.2.0", Direct: true},
				{Manifest: "package-lock.json", Name: "fsevents", Version: "2.3.2", Direct: true},
				{Manifest: "package-lock.json", Name: "@acme/left-pad", Version: "1.3.0", Direct: true},
			},
			Absent: []string{"left-pad"},
		},
		{
			Name:  "package-lock v2",
			Files: fixture(t, "lock-v2"),
			Want: []dep{
				{Manifest: "package-lock.json", Name: "axios", Version: "1.6.2", Direct: true},
				{Manifest: "package-lock.json", Name: "follow-redirects", Version: "1.15.3"},
				{Manifest: "package-lock.json", Name: "asynckit", Version: "0.4.0"},
				{Manifest: "package-lock.json", Name: "typescript", Version: "5.3.3", Direct: true},
				{Manifest: "package-lock.json", Name: "forked-lib", Version: "1.0.1", Direct: true, Unresolvable: true},
				{Manifest: "package-lock.json", Name: "internal-utils", Version: "0.4.0", Direct: true, Unresolvable: true},
			},
		},
		{
			Name:  "package-lock v3",
			Files: fixture(t, "lock-v3"),
			Want: []dep{
				{Manifest: "package-lock.json", Name: "react", Version: "18.2.0", Direct: true},
				{Manifest: "package-lock.json", Name: "scheduler", Version: "0.23.0"},
				{Manifest: "package-lock.json", Name: "lodash", Version: "4.17.20", Direct: true},
				{Manifest: "package-lock.json", Name: "@esbuild/darwin-arm64", Version: "0.19.8"},
			},
			Absent: []string{"lodash-legacy", "dashboard"},
		},
		{
			Name:  "npm-shrinkwrap shadows package-lock",
			Files: fixture(t, "shrinkwrap"),
			Want: []dep{
				{Manifest: "npm-shrinkwrap.json", Name: "commander", Version: "11.1.0", Direct: true},
				{Manifest: "npm-shrinkwrap.json", Name: "color-convert", Version: "2.0.1"},
			},
		},
		{
			Name:  "yarn v1",
			Files: fixture(t, "yarn-v1"),
			Want: []dep{
				{Manifest: "yarn.lock", Name: "@babel/runtime", Version: "7.23.2", Direct: true},
				{Manifest: "yarn.lock", Name: "regenerator-runtime", Version: "0.14.0"},
				{Manifest: "yarn.lock", Name: "jest-util", Version: "29.7.0", Direct: true},
				{Manifest: "yarn.lock", Name: "ansi-styles", Version: "4.3.0"},
				{Manifest: "yarn.lock", Name: "color-picker", Version: "2.0.0", Direct: true, Unresolvable: true},
			},
			Absent: []string{"old-lodash"},
		},
		{
			Name:  "yarn berry workspaces",
			Files: fixture(t, "yarn-berry"),
			Want: []dep{
				{Manifest: "yarn.lock", Name: "semver", Version: "7.5.4", Direct: true},
				{Manifest: "yarn.lock", Name: "lru-cache", Version: "6.0.0"},
				{Manifest: "yarn.lock", Name: "yallist", Version: "4.0.0"},
				{Manifest: "yarn.lock", Name: "typescript", Version: "5.3.2", Direct: true},
				{Manifest: "yarn.lock", Name: "tslib", Version: "2.6.2", Direct: true},
				{Manifest: "yarn.lock", Name: "@acme/is-even", Version: "1.0.3", Direct: true},
				{Manifest: "yarn.lock", Name: "local-helpers", Version: "0.0.0-use.local", Direct: true, Unresolvable: true},
			},
			Absent: []string{"berry-app", "@acme/lib", "is-even"},
		},
		{
			Name:  "pnpm v6",
			Files: fixture(t, "pnpm-v6"),
			Want: []dep{
				{Manifest: "pnpm-lock.yaml", Name: "debug", Version: "4.3.4", Direct: true},
				{Manifest: "pnpm-lock.yaml", Name: "supports-color", Version: "8.1.1"},
				{Manifest: "pnpm-lock.yaml", Name: "has-flag", Version: "4.0.0"},
				{Manifest: "pnpm-lock.yaml", Name: "string-width", Version: "4.2.3", Direct: true},
				{Manifest: "pnpm-lock.yaml", Name: "ansi-regex", Version: "5.0.1"},
				{Manifest: "pnpm-lock.yaml", Name: "eslint-plugin-x", Version: "1.2.0", Direct: true},
				{Manifest: "pnpm-lock.yaml", Name: "my-utils", Version: "0.3.0", Direct: true, Unresolvable: true},
			},
			Absent: []string{"string-width-cjs"},
		},
		{
			Name:  "pnpm v9 workspace",
			Files: fixture(t, "pnpm-v9"),
			Want: []dep{
				{Manifest: "pnpm-lock.yaml", Name: "zod", Version: "3.22.4", Direct: true},
				{Manifest: "pnpm-lock.yaml", Name: "lodash-es", Version: "4.17.20", Direct: true},
				{Manifest: "pnpm-lock.yaml", Name: "vitest", Version: "1.0.4", Direct: true},
				{Manifest: "pnpm-lock.yaml", Name: "@types/node", Version: "20.10.4"},
				{Manifest: "pnpm-lock.yaml", Name: "undici-types", Version: "5.26.5"},
				{Manifest: "pnpm-lock.yaml", Name: "clsx", Version: "2.0.0", Direct: true},
				{Manifest: "pnpm-lock.yaml", Name: "react", Version: "18.2.0", Direct: true},
				{Manifest: "pnpm-lock.yaml", Name: "js-tokens", Version: "4.0.0"},
				{Manifest: "pnpm-lock.yaml", Name: "design-tokens", Version: "3.0.0", Direct: true, Unresolvable: true},
			},
			Absent: []string{"@acme/ui", "lodash-es-legacy", "pnpm-nine"},
		},
		{
			Name:  "npm workspaces monorepo",
			Files: fixture(t, "workspaces"),
			Want: []dep{
				{Manifest: "package-lock.json", Name: "prettier", Version: "3.1.0", Direct: true},
				{Manifest: "package-lock.json", Name: "ms", Version: "2.1.3"},
				{Manifest: "package-lock.json", Name: "lru-cache", Version: "6.0.0"},
				{Manifest: "package-lock.json", Name: "semver", Version: "7.5.4"},
				// not a workspace member, no lockfile of its own
				{Manifest: "tools/release/package.json", Name: "semver", Version: "7.5.0", Direct: true},
			},
			Absent: []string{"@acme/api", "@acme/web", "acme-monorepo"},
		},
		{
			Name:  "package.json only",
			Files: fixture(t, "approximate"),
			Want: []dep{
				{Manifest: "package.json", Name: "express", Version: "4.18.2", Direct: true},
				{Manifest: "package.json", Name: "lodash", Version: "4.17.21", Direct: true},
				{Manifest: "package.json", Name: "uuid", Version: "9.0.0", Direct: true},
				{Manifest: "package.json", Name: "dayjs", Version: "1.11.0", Direct: true},
				{Manifest: "package.json", Name: "left-pad", Version: "1.3.0", Direct: true},
				{Manifest: "package.json", Name: "fastify", Version: "4.24.0", Direct: true},
				{Manifest: "package.json", Name: "jest", Version: "29.7.0", Direct: true},
				{Manifest: "package.json", Name: "fsevents", Version: "2.3.3", Direct: true},
				{Manifest: "package.json", Name: "react-dom", Version: "18.2.0", Direct: true},
				{Manifest: "package.json", Name: "react", Direct: true, Unresolvable: true},
				{Manifest: "package.json", Name: "rimraf", Direct: true, Unresolvable: true},
				{Manifest: "package.json", Name: "next", Direct: true, Unresolvable: true},
				{Manifest: "package.json", Name: "shared", Direct: true, Unresolvable: true},
				{Manifest: "package.json", Name: "linked", Direct: true, Unresolvable: true},
				{Manifest: "package.json", Name: "from-git", Direct: true, Unresolvable: true},
				{Manifest: "package.json", Name: "gh-short", Direct: true, Unresolvable: true},
				{Manifest: "package.json", Name: "tarball", Direct: true, Unresolvable: true},
				{Manifest: "package.json", Name: "sibling", Direct: true, Unresolvable: true},
			},
			Absent: []string{"fast-alias"},
		},
	}
	ecosystemtest.Run(t, newNPM(t), matches, nonMatches, cases)
}

func TestPrivate(t *testing.T) {
	e := newNPM(t, "@acme/*", "acme-*", "github.com/acme/*")
	ecosystemtest.Run(t, e, []string{"package.json"}, nil, []ecosystemtest.Case{{
		Name:  "private",
		Files: fixture(t, "private"),
		Want: []dep{
			{Manifest: "package-lock.json", Name: "@acme/auth", Version: "2.1.4", Direct: true, Private: true},
			{Manifest: "package-lock.json", Name: "@acme/crypto", Version: "1.0.2", Private: true},
			{Manifest: "package-lock.json", Name: "acme-logger", Version: "1.2.0", Direct: true, Private: true},
			{Manifest: "package-lock.json", Name: "@acmeinc/public", Version: "1.0.0", Direct: true},
			{Manifest: "package-lock.json", Name: "chalk", Version: "5.3.0", Direct: true},
		},
	}})
	// Aliased private packages are matched on their real name.
	gs := parse(t, e, fixture(t, "lock-v1"))
	if d := find(t, gs, "package-lock.json", "@acme/left-pad", "1.3.0"); !d.Private {
		t.Error("@acme/left-pad (alias left-pad) must be private")
	}
}

func TestNew(t *testing.T) {
	if _, err := New(nil, ecosystem.Options{PrivatePatterns: []string{"@acme/[x"}}, plugin.Deps{}); err == nil {
		t.Error("bad pattern: want error")
	}
	if _, err := New(plugin.Config{"unknown": 1}, ecosystem.Options{}, plugin.Deps{}); err == nil {
		t.Error("unknown config key: want error")
	}
}

func TestScopes(t *testing.T) {
	e := newNPM(t)
	cases := []struct {
		fixture, manifest, name, version string
		want                             model.Scope
	}{
		// npm flags
		{"lock-v1", "package-lock.json", "express", "4.17.1", model.ScopeProd},
		{"lock-v1", "package-lock.json", "mocha", "10.2.0", model.ScopeDev},
		{"lock-v1", "package-lock.json", "ms", "2.1.2", model.ScopeDev},
		{"lock-v1", "package-lock.json", "fsevents", "2.3.2", model.ScopeOptional},
		{"lock-v3", "package-lock.json", "vite", "5.0.7", model.ScopeDev},
		{"lock-v3", "package-lock.json", "@esbuild/darwin-arm64", "0.19.8", model.ScopeDev},
		{"lock-v3", "package-lock.json", "nanoid", "3.3.6", model.ScopeDev}, // devOptional
		{"lock-v3", "package-lock.json", "bufferutil", "4.0.8", model.ScopeOptional},
		{"lock-v3", "package-lock.json", "node-gyp-build", "4.7.1", model.ScopeOptional},
		{"lock-v3", "package-lock.json", "loose-envify", "1.4.0", model.ScopeProd},
		// yarn: computed from package.json sections and edges
		{"yarn-v1", "yarn.lock", "jest-util", "29.7.0", model.ScopeDev},
		{"yarn-v1", "yarn.lock", "chalk", "4.1.2", model.ScopeDev},
		{"yarn-v1", "yarn.lock", "lodash", "4.17.21", model.ScopeProd},
		{"yarn-berry", "yarn.lock", "typescript", "5.3.2", model.ScopeDev},
		{"yarn-berry", "yarn.lock", "lru-cache", "6.0.0", model.ScopeProd},
		// pnpm v6 flags, v9 computed
		{"pnpm-v6", "pnpm-lock.yaml", "eslint-plugin-x", "1.2.0", model.ScopeDev},
		{"pnpm-v6", "pnpm-lock.yaml", "ms", "2.1.3", model.ScopeDev},
		{"pnpm-v6", "pnpm-lock.yaml", "fsevents", "2.3.3", model.ScopeOptional},
		{"pnpm-v6", "pnpm-lock.yaml", "debug", "4.3.4", model.ScopeProd},
		{"pnpm-v9", "pnpm-lock.yaml", "vitest", "1.0.4", model.ScopeDev},
		{"pnpm-v9", "pnpm-lock.yaml", "tinypool", "0.8.1", model.ScopeDev},
		{"pnpm-v9", "pnpm-lock.yaml", "@types/node", "20.10.4", model.ScopeDev},
		{"pnpm-v9", "pnpm-lock.yaml", "loose-envify", "1.4.0", model.ScopeProd},
		// package.json sections
		{"approximate", "package.json", "jest", "29.7.0", model.ScopeDev},
		{"approximate", "package.json", "lodash", "4.17.21", model.ScopeProd}, // dependencies wins over devDependencies
		{"approximate", "package.json", "fsevents", "2.3.3", model.ScopeOptional},
		{"approximate", "package.json", "react-dom", "18.2.0", model.ScopeProd},
	}
	graphs := map[string][]*model.DependencyGraph{}
	for _, c := range cases {
		if graphs[c.fixture] == nil {
			graphs[c.fixture] = parse(t, e, fixture(t, c.fixture))
		}
		if d := find(t, graphs[c.fixture], c.manifest, c.name, c.version); d.Scope != c.want {
			t.Errorf("%s %s@%s: scope %s, want %s", c.fixture, c.name, c.version, d.Scope, c.want)
		}
	}
}

func TestParents(t *testing.T) {
	e := newNPM(t)
	cases := []struct {
		fixture, manifest, name, version string
		want                             []string
	}{
		{"lock-v1", "package-lock.json", "mime-db", "1.52.0", []string{"express"}},
		{"lock-v1", "package-lock.json", "ms", "2.0.0", []string{"express"}},
		{"lock-v1", "package-lock.json", "ms", "2.1.2", []string{"mocha"}},
		{"lock-v1", "package-lock.json", "express", "4.17.1", nil}, // direct
		{"lock-v3", "package-lock.json", "loose-envify", "1.4.0", []string{"react", "react-dom"}},
		{"lock-v3", "package-lock.json", "nanoid", "3.3.7", []string{"vite"}},
		{"yarn-v1", "yarn.lock", "ansi-styles", "4.3.0", []string{"jest-util"}},
		{"yarn-berry", "yarn.lock", "yallist", "4.0.0", []string{"semver"}},
		{"pnpm-v6", "pnpm-lock.yaml", "ms", "2.1.2", []string{"debug", "my-utils"}},
		{"pnpm-v6", "pnpm-lock.yaml", "strip-ansi", "6.0.1", []string{"string-width"}},
		{"pnpm-v9", "pnpm-lock.yaml", "undici-types", "5.26.5", []string{"vitest"}},
		{"workspaces", "package-lock.json", "semver", "7.5.4", []string{"jsonwebtoken"}},
		{"workspaces", "package-lock.json", "semver", "5.7.2", []string{"jsonwebtoken"}},
	}
	graphs := map[string][]*model.DependencyGraph{}
	for _, c := range cases {
		if graphs[c.fixture] == nil {
			graphs[c.fixture] = parse(t, e, fixture(t, c.fixture))
		}
		if d := find(t, graphs[c.fixture], c.manifest, c.name, c.version); !slices.Equal(d.Parents, c.want) {
			t.Errorf("%s %s@%s: parents %v, want %v", c.fixture, c.name, c.version, d.Parents, c.want)
		}
	}
}

func TestWorkspaces(t *testing.T) {
	gs := parse(t, newNPM(t), fixture(t, "workspaces"))
	if got, want := manifests(gs), []string{"package-lock.json", "tools/release/package.json"}; !slices.Equal(got, want) {
		t.Fatalf("graphs = %v, want %v (members covered by the root lockfile)", got, want)
	}
	// Both member versions are direct (each is declared by a member package.json).
	for _, v := range []string{"9.0.2", "8.5.1"} {
		if d := find(t, gs, "package-lock.json", "jsonwebtoken", v); !d.Direct || d.Scope != model.ScopeProd {
			t.Errorf("jsonwebtoken@%s: direct=%v scope=%s", v, d.Direct, d.Scope)
		}
	}
	if d := find(t, gs, "tools/release/package.json", "semver", "7.5.0"); !d.Approximate {
		t.Error("uncovered package.json must be approximate")
	}

	// pnpm and berry members are covered through importers / workspace entries.
	for _, fx := range []string{"pnpm-v9", "yarn-berry"} {
		gs := parse(t, newNPM(t), fixture(t, fx))
		if got := manifests(gs); !slices.Equal(got, []string{fixtureLock(fx)}) {
			t.Errorf("%s: graphs = %v, want only the lockfile", fx, got)
		}
	}

	// Without "workspaces", a nested package.json is its own (approximate) project.
	files := fixture(t, "workspaces")
	files["package.json"] = `{"name": "root", "devDependencies": {"prettier": "^3.1.0"}}`
	files["package-lock.json"] = `{"lockfileVersion": 3, "packages": {"": {"devDependencies": {"prettier": "^3.1.0"}}, "node_modules/prettier": {"version": "3.1.0", "dev": true}}}`
	gs = parse(t, newNPM(t), files)
	want := []string{"package-lock.json", "packages/api/package.json", "packages/web/package.json", "tools/release/package.json"}
	if got := manifests(gs); !slices.Equal(got, want) {
		t.Errorf("graphs = %v, want %v", got, want)
	}
}

func fixtureLock(fx string) string {
	if strings.HasPrefix(fx, "pnpm") {
		return "pnpm-lock.yaml"
	}
	return "yarn.lock"
}

func TestShrinkwrapShadowsPackageLock(t *testing.T) {
	gs := parse(t, newNPM(t), fixture(t, "shrinkwrap"))
	if got := manifests(gs); !slices.Equal(got, []string{"npm-shrinkwrap.json"}) {
		t.Fatalf("graphs = %v", got)
	}
}

func TestApproximate(t *testing.T) {
	gs := parse(t, newNPM(t), fixture(t, "approximate"))
	for _, d := range gs[0].Dependencies {
		if !d.Approximate || !d.Direct {
			t.Errorf("%s: approximate=%v direct=%v", d.Name, d.Approximate, d.Direct)
		}
	}
	reasons := map[string]string{}
	for _, d := range gs[0].Dependencies {
		reasons[d.Name] = d.Unresolvable
	}
	for name, want := range map[string]string{
		"react":    "range ^18 || ^19",
		"rimraf":   "range *",
		"shared":   "local path dependency: file:../shared",
		"from-git": "git dependency: git+https://github.com/acme/from-git.git#main",
		"gh-short": "git dependency: acme/gh-short#v1",
		"tarball":  "tarball URL dependency: https://example.com/pkgs/tarball-1.0.0.tgz",
		"sibling":  "workspace dependency: workspace:*",
	} {
		if reasons[name] != want {
			t.Errorf("%s: reason %q, want %q", name, reasons[name], want)
		}
	}
}

func TestLockfileUnresolvableReasons(t *testing.T) {
	e := newNPM(t)
	for _, c := range []struct{ fixture, manifest, name, version, prefix string }{
		{"lock-v2", "package-lock.json", "forked-lib", "1.0.1", "git dependency: "},
		{"lock-v2", "package-lock.json", "internal-utils", "0.4.0", "local path dependency: "},
		{"yarn-v1", "yarn.lock", "color-picker", "2.0.0", "git dependency: github:"},
		{"yarn-berry", "yarn.lock", "local-helpers", "0.0.0-use.local", "local portal dependency: portal:../../helpers"},
		{"pnpm-v6", "pnpm-lock.yaml", "my-utils", "0.3.0", "local path dependency: "},
		{"pnpm-v9", "pnpm-lock.yaml", "design-tokens", "3.0.0", "tarball URL dependency: "},
	} {
		d := find(t, parse(t, e, fixture(t, c.fixture)), c.manifest, c.name, c.version)
		if !strings.HasPrefix(d.Unresolvable, c.prefix) {
			t.Errorf("%s %s: reason %q, want prefix %q", c.fixture, c.name, d.Unresolvable, c.prefix)
		}
	}
}

func TestMinVersion(t *testing.T) {
	for in, want := range map[string]string{
		"^1.2.3": "1.2.3", "~1.2.3": "1.2.3", ">=1.2.3": "1.2.3", "=1.2.3": "1.2.3", "1.2.3": "1.2.3",
		"v1.2.3": "1.2.3", "1.2.x": "1.2.0", "1.x": "1.0.0", "^1.2": "1.2.0", "1": "1.0.0", "1.2.*": "1.2.0",
		"^1.0.0-beta.2": "1.0.0-beta.2", ">= 2.0.0": "2.0.0",
		"*": "", "x": "", "latest": "", "^1 || ^2": "", ">=1 <2": "", "1.2.3 - 2.0.0": "", "<2.0.0": "", "": "",
	} {
		got, ok := minVersion(in)
		if got != want || ok != (want != "") {
			t.Errorf("minVersion(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
}

func TestWorkspaceGlobs(t *testing.T) {
	for _, c := range []struct {
		pats []string
		rel  string
		want bool
	}{
		{[]string{"packages/*"}, "packages/a", true},
		{[]string{"packages/*"}, "packages/a/b", false},
		{[]string{"./packages/*/"}, "packages/a", true},
		{[]string{"apps/**"}, "apps/x/y", true},
		{[]string{"packages/*", "!packages/legacy"}, "packages/legacy", false},
		{[]string{"tools/cli"}, "tools/cli", true},
		{nil, "packages/a", false},
	} {
		if got := matchWorkspace(c.pats, c.rel); got != c.want {
			t.Errorf("matchWorkspace(%v, %q) = %v", c.pats, c.rel, got)
		}
	}
}

func TestParseErrorKeepsOtherGraphs(t *testing.T) {
	files := model.FileSet{Files: map[string][]byte{
		"ok/package.json":        []byte(`{"dependencies": {"a": "1.0.0"}}`),
		"bad/package.json":       []byte(`{"dependencies": `),
		"broken/package.json":    []byte(`{"dependencies": {"left-pad": "^1.3.0"}}`),
		"broken/yarn.lock":       []byte("  orphan field\n"),
		"broken2/pnpm-lock.yaml": []byte("packages: [\n"),
	}}
	gs, err := newNPM(t).Parse(context.Background(), files)
	if err == nil {
		t.Fatal("want an error")
	}
	for _, p := range []string{"bad/package.json", "broken/yarn.lock", "broken2/pnpm-lock.yaml"} {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("error %q does not name %s", err, p)
		}
	}
	// The broken lockfile leaves its package.json uncovered: approximate graph.
	if got, want := manifests(gs), []string{"broken/package.json", "ok/package.json"}; !slices.Equal(got, want) {
		t.Errorf("graphs = %v, want %v", got, want)
	}
}

func TestNoPackageJSONFallsBackToTopLevelRoots(t *testing.T) {
	files := fixture(t, "yarn-v1")
	delete(files, "package.json")
	gs := parse(t, newNPM(t), files)
	if d := find(t, gs, "yarn.lock", "@babel/runtime", "7.23.2"); !d.Direct {
		t.Error("@babel/runtime: nothing depends on it, want direct")
	}
	if d := find(t, gs, "yarn.lock", "regenerator-runtime", "0.14.0"); d.Direct {
		t.Error("regenerator-runtime: want transitive")
	}
}
