package rubygems

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
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

func fileSet(files map[string]string) model.FileSet {
	fs := model.FileSet{Files: map[string][]byte{}}
	for p, s := range files {
		fs.Files[p] = []byte(s)
	}
	return fs
}

func newRubyGems(t *testing.T, private ...string) ecosystem.Ecosystem {
	t.Helper()
	e, err := New(nil, ecosystem.Options{PrivatePatterns: private}, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// parse returns the dependencies of every graph keyed by "manifest|name".
func parse(t *testing.T, e ecosystem.Ecosystem, files map[string]string) map[string]model.Dependency {
	t.Helper()
	gs, err := e.Parse(context.Background(), fileSet(files))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]model.Dependency{}
	for _, g := range gs {
		for _, d := range g.Dependencies {
			out[g.ManifestPath+"|"+d.Name] = d
		}
	}
	return out
}

type dep = ecosystemtest.Dep

const railsLock = "Gemfile.lock"

func TestContract(t *testing.T) {
	matches := []string{
		"Gemfile", "Gemfile.lock", "gems.rb", "gems.locked",
		"services/api/Gemfile.lock", "engines/admin/Gemfile", "vendor/engines/x/Gemfile",
	}
	nonMatches := []string{
		"Gemfile.next", "Gemfile.lock.bak", "foo.gemspec", "Rakefile", "gemfile",
		"vendor/bundle/ruby/3.2.0/gems/rack-3.0.9/Gemfile",
		"app/vendor/bundle/x/Gemfile.lock",
	}
	cases := []ecosystemtest.Case{
		{
			Name:  "rails lockfile",
			Files: fixture(t, "rails"),
			Want: []dep{
				{Manifest: railsLock, Name: "rails", Version: "7.1.3", Direct: true},
				{Manifest: railsLock, Name: "pg", Version: "1.5.5", Direct: true},
				// three platform variants → one dependency, suffix stripped
				{Manifest: railsLock, Name: "nokogiri", Version: "1.16.2", Direct: true},
				{Manifest: railsLock, Name: "debug", Version: "1.9.1", Direct: true},
				// "!" dependency from a second GEM remote: resolvable
				{Manifest: railsLock, Name: "acme-auth", Version: "2.3.1", Direct: true},
				// GIT and PATH sources
				{Manifest: railsLock, Name: "acme-billing", Version: "0.4.2", Direct: true, Unresolvable: true},
				{Manifest: railsLock, Name: "admin_engine", Version: "0.1.0", Direct: true, Unresolvable: true},
				// transitive
				{Manifest: railsLock, Name: "racc", Version: "1.7.3"},
				{Manifest: railsLock, Name: "faraday", Version: "2.9.0"},
				{Manifest: railsLock, Name: "activesupport", Version: "7.1.3"},
				{Manifest: railsLock, Name: "jwt", Version: "2.8.1"},
			},
			Absent: []string{"ruby", "bundler", "x86_64-linux", "arm64-darwin"},
		},
		{
			Name:  "gemfile only",
			Files: fixture(t, "approx"),
			Want: []dep{
				{Manifest: "Gemfile", Name: "rails", Version: "7.0.8", Direct: true},
				{Manifest: "Gemfile", Name: "pg", Version: "1.2.3", Direct: true},
				{Manifest: "Gemfile", Name: "redis", Version: "5.0.8", Direct: true},
				{Manifest: "Gemfile", Name: "sidekiq", Version: "6.5.12", Direct: true},
				{Manifest: "Gemfile", Name: "puma", Version: "6.4.1", Direct: true},
				{Manifest: "Gemfile", Name: "bcrypt", Version: "3.1.7", Direct: true},
				{Manifest: "Gemfile", Name: "kaminari", Version: "1.2", Direct: true},
				{Manifest: "Gemfile", Name: "nio4r", Version: "2.5", Direct: true},
				{Manifest: "Gemfile", Name: "bootsnap", Version: "1.4.4", Direct: true},
				{Manifest: "Gemfile", Name: "rack-mini-profiler", Version: "3.3", Direct: true},
				{Manifest: "Gemfile", Name: "rspec-rails", Version: "6.0", Direct: true},
				{Manifest: "Gemfile", Name: "jbuilder", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "devise", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "rack", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "faraday", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "oj", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "simplecov", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "my_engine", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "rubocop-acme", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "pundit", Direct: true, Unresolvable: true},
				{Manifest: "Gemfile", Name: "activestorage", Direct: true, Unresolvable: true},
			},
			Absent: []string{"ruby"},
		},
		{
			Name:  "monorepo with gems.locked",
			Files: fixture(t, "monorepo"),
			Want: []dep{
				{Manifest: "services/billing/gems.locked", Name: "sinatra", Version: "3.2.0", Direct: true},
				{Manifest: "services/billing/gems.locked", Name: "rack-test", Version: "2.1.0", Direct: true},
				{Manifest: "services/billing/gems.locked", Name: "rack", Version: "2.2.8.1"},
				{Manifest: "services/billing/gems.locked", Name: "ruby2_keywords", Version: "0.0.5"},
				{Manifest: "services/api/Gemfile.lock", Name: "ffi", Version: "1.16.3", Direct: true},
				{Manifest: "services/api/Gemfile.lock", Name: "json", Version: "2.7.1", Direct: true},
				{Manifest: "services/api/Gemfile.lock", Name: "rack", Version: "3.0.9.1", Direct: true},
			},
			Absent: []string{"vendored-dep", "bundler"},
		},
	}
	ecosystemtest.Run(t, newRubyGems(t), matches, nonMatches, cases)
}

func TestPrivate(t *testing.T) {
	e := newRubyGems(t, "acme-*", "internal_?ools")
	files := fixture(t, "rails")
	files["Gemfile.lock"] = strings.Replace(files["Gemfile.lock"], "    pg (1.5.5)\n", "    internal_tools (0.3.0)\n    pg (1.5.5)\n", 1)
	files["Gemfile.lock"] = strings.Replace(files["Gemfile.lock"], "  pg (~> 1.5)\n", "  internal_tools\n  pg (~> 1.5)\n", 1)
	ecosystemtest.Run(t, e, []string{"Gemfile"}, nil, []ecosystemtest.Case{{
		Name:  "private",
		Files: files,
		Want: []dep{
			{Manifest: railsLock, Name: "acme-auth", Version: "2.3.1", Direct: true, Private: true},
			{Manifest: railsLock, Name: "acme-billing", Version: "0.4.2", Direct: true, Private: true, Unresolvable: true},
			{Manifest: railsLock, Name: "internal_tools", Version: "0.3.0", Direct: true, Private: true},
			{Manifest: railsLock, Name: "admin_engine", Version: "0.1.0", Direct: true, Unresolvable: true},
			{Manifest: railsLock, Name: "rails", Version: "7.1.3", Direct: true},
			{Manifest: railsLock, Name: "jwt", Version: "2.8.1"},
		},
	}})
	approx := parse(t, e, fixture(t, "approx"))
	if d := approx["Gemfile|rubocop-acme"]; d.Private {
		t.Errorf("rubocop-acme: want public (a pattern matches the whole name only): %+v", d)
	}
}

func TestParentsAndScopes(t *testing.T) {
	deps := parse(t, newRubyGems(t), fixture(t, "rails"))
	parents := map[string][]string{
		"racc":            {"admin_engine", "capybara", "nokogiri", "rails", "rspec-rails"},
		"faraday":         {"acme-billing"},
		"jwt":             {"acme-auth"},
		"base64":          {"acme-auth"},
		"xpath":           {"capybara"},
		"bindex":          {"web-console"},
		"irb":             {"debug"},
		"rspec-core":      {"rspec-rails"},
		"nio4r":           {"puma"},
		"redis-client":    {"sidekiq"},
		"concurrent-ruby": {"admin_engine", "rails", "rspec-rails", "sidekiq", "web-console"},
	}
	for name, want := range parents {
		if got := deps[railsLock+"|"+name].Parents; !reflect.DeepEqual(got, want) {
			t.Errorf("%s parents = %v, want %v", name, got, want)
		}
	}
	if p := deps[railsLock+"|rails"].Parents; p != nil {
		t.Errorf("direct gem rails has parents %v", p)
	}
	scopes := map[string]model.Scope{
		"rails": model.ScopeProd, "pg": model.ScopeProd, "rack-attack": model.ScopeProd,
		"acme-auth": model.ScopeProd, "bootsnap": model.ScopeProd,
		"debug": model.ScopeDev, "rspec-rails": model.ScopeDev, "web-console": model.ScopeDev, "capybara": model.ScopeDev,
		// transitive: dev only when every parent is dev
		"xpath": model.ScopeDev, "bindex": model.ScopeDev, "irb": model.ScopeDev, "rspec-core": model.ScopeDev,
		"racc": model.ScopeProd, "actionview": model.ScopeProd, "faraday": model.ScopeProd,
	}
	for name, want := range scopes {
		d := deps[railsLock+"|"+name]
		if d.Scope != want || d.Approximate {
			t.Errorf("%s: scope=%s approximate=%v, want %s/false", name, d.Scope, d.Approximate, want)
		}
	}
	if r := deps[railsLock+"|acme-billing"].Unresolvable; r != "git source" {
		t.Errorf("acme-billing unresolvable = %q", r)
	}
	if r := deps[railsLock+"|admin_engine"].Unresolvable; r != "path source" {
		t.Errorf("admin_engine unresolvable = %q", r)
	}
	if d := deps[railsLock+"|nokogiri"]; d.PURL != "pkg:gem/nokogiri@1.16.2" {
		t.Errorf("nokogiri PURL = %q", d.PURL)
	}

	// Without the Gemfile everything is prod.
	files := fixture(t, "rails")
	delete(files, "Gemfile")
	for k, d := range parse(t, newRubyGems(t), files) {
		if d.Scope != model.ScopeProd {
			t.Errorf("%s: scope %s without Gemfile, want prod", k, d.Scope)
		}
	}

	billing := parse(t, newRubyGems(t), fixture(t, "monorepo"))
	for name, want := range map[string]model.Scope{
		"sinatra": model.ScopeProd, "rack-test": model.ScopeDev, "rack": model.ScopeProd, "tilt": model.ScopeProd,
	} {
		if got := billing["services/billing/gems.locked|"+name].Scope; got != want {
			t.Errorf("billing %s scope = %s, want %s", name, got, want)
		}
	}
}

func TestApproximate(t *testing.T) {
	deps := parse(t, newRubyGems(t), fixture(t, "approx"))
	for k, d := range deps {
		if !d.Approximate || !d.Direct {
			t.Errorf("%s: approximate=%v direct=%v, want both", k, d.Approximate, d.Direct)
		}
	}
	reasons := map[string]string{
		"jbuilder":      "no version constraint",
		"my_engine":     "path source",
		"rubocop-acme":  "git source",
		"pundit":        "git source",
		"activestorage": "git source",
		"oj":            "non-literal requirement",
		"rails":         "",
	}
	for name, want := range reasons {
		if got := deps["Gemfile|"+name].Unresolvable; got != want {
			t.Errorf("%s unresolvable = %q, want %q", name, got, want)
		}
	}
	for name, want := range map[string]model.Scope{
		"rspec-rails": model.ScopeDev, "simplecov": model.ScopeDev, "rails": model.ScopeProd, "rack-mini-profiler": model.ScopeProd,
	} {
		if got := deps["Gemfile|"+name].Scope; got != want {
			t.Errorf("%s scope = %s, want %s", name, got, want)
		}
	}
}

func TestMinVersion(t *testing.T) {
	cases := []struct {
		reqs []string
		want string
	}{
		{[]string{"~> 1.2"}, "1.2"},
		{[]string{"~> 1.2.3"}, "1.2.3"},
		{[]string{">= 1.2.3"}, "1.2.3"},
		{[]string{"= 1.0"}, "1.0"},
		{[]string{"1.0"}, "1.0"},
		{[]string{">= 1.0, < 2"}, "1.0"},
		{[]string{"~> 1.2", ">= 1.2.5"}, "1.2.5"},
		{[]string{"~> 1.2.3", ">= 1.3"}, ""},
		{[]string{"~> 1", ">= 1.9"}, "1.9"},
		{[]string{"~> 9.9", ">= 10.0"}, ""},
		{[]string{">= 1.0", "!= 1.0"}, ""},
		{[]string{"> 1.0"}, ""},
		{[]string{"<= 1.0"}, ""},
		{[]string{"~> latest"}, ""},
		{[]string{"=> 1.0"}, ""},
		{nil, ""},
	}
	for _, c := range cases {
		got, why := minVersion(c.reqs)
		if got != c.want || (got == "") == (why == "") {
			t.Errorf("minVersion(%q) = %q, %q; want %q", c.reqs, got, why, c.want)
		}
	}
	for v, want := range map[string]string{"1.2.3": "1.3", "1.2": "2", "1": "2", "1.9.9": "1.10", "0.9": "1", "2.0.0.rc1": "2.1"} {
		if got := pessimisticUpper(v); got != want {
			t.Errorf("pessimisticUpper(%q) = %q, want %q", v, got, want)
		}
	}
}

func TestGraphShape(t *testing.T) {
	files := fixture(t, "monorepo")
	for p, s := range fixture(t, "rails") {
		files["apps/web/"+p] = s
	}
	files["tools/Gemfile"] = "source \"https://rubygems.org\"\ngem \"rake\", \"~> 13.0\"\n"
	gs, err := newRubyGems(t).Parse(context.Background(), fileSet(files))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"apps/web/Gemfile.lock", "services/api/Gemfile.lock", "services/billing/gems.locked", "tools/Gemfile"}
	var got []string
	for _, g := range gs {
		got = append(got, g.ManifestPath)
		for i := 1; i < len(g.Dependencies); i++ {
			if g.Dependencies[i-1].Name >= g.Dependencies[i].Name {
				t.Errorf("%s: dependencies not sorted at %s", g.ManifestPath, g.Dependencies[i].Name)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("graphs = %v, want %v (sorted, one per lockfile, Gemfile only without lockfile)", got, want)
	}
}

func TestParseErrorKeepsOtherGraphs(t *testing.T) {
	files := fileSet(map[string]string{
		"ok/Gemfile.lock":   "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.9)\n\nDEPENDENCIES\n  rack\n",
		"bad/Gemfile.lock":  "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack 3.0.9\n",
		"junk/Gemfile.lock": "<<<<<<< HEAD\n=======\n>>>>>>> main\n",
		"bad/Gemfile":       "gem \"rack\"\n", // has a (broken) lockfile: no approximate graph
	})
	gs, err := newRubyGems(t).Parse(context.Background(), files)
	if err == nil || !strings.Contains(err.Error(), "bad/Gemfile.lock") || !strings.Contains(err.Error(), "junk/Gemfile.lock") {
		t.Errorf("want an error naming bad/ and junk/Gemfile.lock, got %v", err)
	}
	if len(gs) != 1 || gs[0].ManifestPath != "ok/Gemfile.lock" || len(gs[0].Dependencies) != 1 {
		t.Errorf("want the ok/Gemfile.lock graph only, got %+v", gs)
	}
}

func TestNewRejectsBadConfig(t *testing.T) {
	if _, err := New(nil, ecosystem.Options{PrivatePatterns: []string{"acme-[x"}}, plugin.Deps{}); err == nil {
		t.Error("bad pattern: want error")
	}
	if _, err := New(plugin.Config{"unknown": 1}, ecosystem.Options{}, plugin.Deps{}); err == nil {
		t.Error("unknown config key: want error")
	}
}

func TestRegistered(t *testing.T) {
	f, err := ecosystem.Registry.Get("rubygems")
	if err != nil {
		t.Fatal(err)
	}
	e, err := f(nil, ecosystem.Options{}, plugin.Deps{})
	if err != nil || e.Name() != model.EcosystemRubyGems {
		t.Fatalf("factory: %v, %v", e, err)
	}
}
