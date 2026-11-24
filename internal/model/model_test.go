package model

import "testing"

func TestParseRepoURL(t *testing.T) {
	cases := []struct {
		in    string
		want  RepoURL
		isErr bool
	}{
		{in: "https://github.com/remitano/foo", want: RepoURL{Host: "github.com", Owner: "remitano", Name: "foo"}},
		{in: "https://github.com/remitano/foo.git/", want: RepoURL{Host: "github.com", Owner: "remitano", Name: "foo"}},
		{in: "git@github.com:remitano/foo.git", want: RepoURL{Host: "github.com", Owner: "remitano", Name: "foo", SSH: true}},
		{in: "ssh://git@ghe.example.com:2222/team/bar.git", want: RepoURL{Host: "ghe.example.com", Owner: "team", Name: "bar", SSH: true}},
		{in: "ftp://github.com/a/b", isErr: true},
		{in: "https://github.com/onlyowner", isErr: true},
		{in: "remitano/foo", isErr: true},
	}
	for _, c := range cases {
		got, err := ParseRepoURL(c.in)
		if c.isErr {
			if err == nil {
				t.Errorf("%q: want error, got %+v", c.in, got)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%q: got %+v, %v; want %+v", c.in, got, err, c.want)
		}
	}
}

func TestBuildPURL(t *testing.T) {
	cases := []struct {
		eco           Ecosystem
		name, version string
		want          string
	}{
		{EcosystemGo, "github.com/foo/bar", "v1.2.3", "pkg:golang/github.com/foo/bar@v1.2.3"},
		{EcosystemGo, "stdlib", "1.22.1", "pkg:golang/stdlib@1.22.1"},
		{EcosystemNPM, "@scope/name", "1.0.0", "pkg:npm/%40scope/name@1.0.0"},
		{EcosystemRubyGems, "rails", "7.1.3", "pkg:gem/rails@7.1.3"},
		{EcosystemGo, "github.com/foo/bar", "", "pkg:golang/github.com/foo/bar"},
	}
	for _, c := range cases {
		if got := BuildPURL(c.eco, c.name, c.version); got != c.want {
			t.Errorf("BuildPURL(%s,%s,%s) = %s, want %s", c.eco, c.name, c.version, got, c.want)
		}
	}
}

func TestFindingIDStableAcrossVersions(t *testing.T) {
	f1 := Finding{Provider: "github", Repo: "o/r", ManifestPath: "go.mod", AdvisoryID: "GO-2024-0001",
		Package: NewPackage(EcosystemGo, "github.com/foo/bar", "v1.2.3")}
	f2 := f1
	f2.Package = NewPackage(EcosystemGo, "github.com/foo/bar", "v1.2.4")
	if f1.ComputeID() != f2.ComputeID() {
		t.Fatal("finding ID must not depend on version")
	}
	f3 := f1
	f3.ManifestPath = "sub/go.mod"
	if f3.ComputeID() == f1.ID {
		t.Fatal("finding ID must depend on manifest path")
	}
}

func TestSeverity(t *testing.T) {
	if ParseSeverity("moderate") != SeverityMedium || ParseSeverity("x") != SeverityUnknown {
		t.Fatal("ParseSeverity")
	}
	if SeverityFromCVSS(9.8) != SeverityCritical || SeverityFromCVSS(0) != SeverityUnknown {
		t.Fatal("SeverityFromCVSS")
	}
	if !SeverityHigh.AtLeast(SeverityMedium) || SeverityLow.AtLeast(SeverityHigh) {
		t.Fatal("AtLeast")
	}
}
