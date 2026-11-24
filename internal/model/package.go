package model

import (
	"strings"

	"github.com/package-url/packageurl-go"
)

// Ecosystem identifies a package ecosystem. Values match OSV ecosystem names
// lower-cased so sources can map them trivially.
type Ecosystem string

const (
	EcosystemGo       Ecosystem = "go"
	EcosystemNPM      Ecosystem = "npm"
	EcosystemRubyGems Ecosystem = "rubygems"
)

// purlType maps an ecosystem to its PURL type.
var purlType = map[Ecosystem]string{
	EcosystemGo:       packageurl.TypeGolang,
	EcosystemNPM:      packageurl.TypeNPM,
	EcosystemRubyGems: packageurl.TypeGem,
}

// Package is one package at one version. PURL is its identity everywhere.
type Package struct {
	Ecosystem Ecosystem
	Name      string // full name: "github.com/foo/bar", "@scope/name", "rails"
	Version   string
	PURL      string
}

// NewPackage builds a Package and its PURL.
func NewPackage(eco Ecosystem, name, version string) Package {
	return Package{Ecosystem: eco, Name: name, Version: version, PURL: BuildPURL(eco, name, version)}
}

// Key is the PURL without version: identifies "the same library" across bumps.
func (p Package) Key() string { return BuildPURL(p.Ecosystem, p.Name, "") }

// BuildPURL renders pkg:<type>/<namespace>/<name>@<version>.
func BuildPURL(eco Ecosystem, name, version string) string {
	typ, ok := purlType[eco]
	if !ok {
		typ = string(eco)
	}
	ns, n := "", name
	switch eco {
	case EcosystemGo:
		if i := strings.LastIndex(name, "/"); i >= 0 {
			ns, n = name[:i], name[i+1:]
		}
	case EcosystemNPM:
		if strings.HasPrefix(name, "@") {
			if i := strings.Index(name, "/"); i >= 0 {
				ns, n = name[:i], name[i+1:]
			}
		}
	}
	return packageurl.NewPackageURL(typ, ns, n, version, nil, "").ToString()
}

// Scope is how a dependency is used.
type Scope string

const (
	ScopeProd     Scope = "prod"
	ScopeDev      Scope = "dev"
	ScopeOptional Scope = "optional"
)

// Dependency is a package as it appears in one manifest.
type Dependency struct {
	Package
	Direct       bool
	Scope        Scope
	Approximate  bool     // version taken from a range, not a lockfile
	Private      bool     // matches private_modules: never sent to public sources
	Unresolvable string   // non-empty reason when it cannot be checked (local path, git source...)
	Parents      []string // names of direct deps that pull this one in (transitive only)
}

// DependencyGraph is everything one manifest declares.
type DependencyGraph struct {
	Ecosystem    Ecosystem
	ManifestPath string // repo-relative, e.g. "services/api/go.mod"
	Dependencies []Dependency
}

// FileSet carries repo files to parsers and detectors: repo-relative path → content.
type FileSet struct {
	Files map[string][]byte
}

// Paths returns the keys of the set.
func (f FileSet) Paths() []string {
	out := make([]string, 0, len(f.Files))
	for p := range f.Files {
		out = append(out, p)
	}
	return out
}
