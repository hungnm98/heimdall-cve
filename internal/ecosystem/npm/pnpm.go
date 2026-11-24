package npm

import (
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

// pnpmLock covers pnpm-lock.yaml v5 ("/name/1.0.0"), v6 ("/name@1.0.0") and
// v9 ("name@1.0.0" in packages, peer-qualified keys in snapshots).
type pnpmLock struct {
	Importers            map[string]pnpmImporter `yaml:"importers"`
	Dependencies         map[string]pnpmRef      `yaml:"dependencies"` // single project, v5/v6
	DevDependencies      map[string]pnpmRef      `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmRef      `yaml:"optionalDependencies"`
	Packages             map[string]pnpmPkg      `yaml:"packages"`
	Snapshots            map[string]pnpmPkg      `yaml:"snapshots"`
}

type pnpmImporter struct {
	Dependencies         map[string]pnpmRef `yaml:"dependencies"`
	DevDependencies      map[string]pnpmRef `yaml:"devDependencies"`
	OptionalDependencies map[string]pnpmRef `yaml:"optionalDependencies"`
}

// pnpmRef is {specifier, version} (v6+) or a bare version string (v5).
type pnpmRef struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

func (r *pnpmRef) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		r.Version = n.Value
		return nil
	}
	type plain pnpmRef
	return n.Decode((*plain)(r))
}

type pnpmPkg struct {
	Resolution struct {
		Integrity string `yaml:"integrity"`
		Tarball   string `yaml:"tarball"`
		Directory string `yaml:"directory"`
		Repo      string `yaml:"repo"`
		Commit    string `yaml:"commit"`
		Type      string `yaml:"type"`
	} `yaml:"resolution"`
	Name                 string            `yaml:"name"`
	Version              string            `yaml:"version"`
	Dev                  *bool             `yaml:"dev"`
	Optional             bool              `yaml:"optional"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

func parsePnpm(data []byte) (*lockData, error) {
	var lf pnpmLock
	if err := yaml.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	nodesSrc := lf.Packages
	if len(lf.Snapshots) > 0 {
		// v9: snapshots carry the edges; a package without any snapshot
		// (hand-edited or truncated lockfile) is still reported.
		nodesSrc = map[string]pnpmPkg{}
		snapped := map[string]bool{}
		for k, v := range lf.Snapshots {
			nodesSrc[k] = v
			snapped[stripPeers(k)] = true
		}
		for k := range lf.Packages {
			if !snapped[k] {
				nodesSrc[k] = pnpmPkg{}
			}
		}
	}
	ld := newLockData()
	resolve := func(name, ref string) string {
		if ref == "" || strings.HasPrefix(ref, "link:") {
			return ""
		}
		for _, c := range []string{ref, "/" + name + "@" + ref, "/" + name + "/" + ref, name + "@" + ref} {
			if _, ok := nodesSrc[c]; ok {
				return c
			}
		}
		return ""
	}

	for key, snap := range nodesSrc {
		info := snap
		if len(lf.Snapshots) > 0 {
			info = lf.Packages[stripPeers(key)]
		}
		name, ver := pnpmKey(key)
		keyVer := ver
		if info.Name != "" {
			name = info.Name
		}
		if info.Version != "" && !isSemver(ver) {
			ver = info.Version
		}
		nd := &node{name: name, version: ver, optional: snap.Optional || info.Optional}
		if d := snap.Dev; d != nil {
			if *d {
				nd.scope = model.ScopeDev
			} else if nd.optional {
				nd.scope = model.ScopeOptional
			} else {
				nd.scope = model.ScopeProd
			}
		}
		switch r := info.Resolution; {
		case r.Directory != "":
			nd.unresolvable = "local path dependency: file:" + r.Directory
		case r.Repo != "" || r.Type == "git":
			nd.unresolvable = "git dependency: " + strings.TrimSuffix(r.Repo+"#"+r.Commit, "#")
		case r.Tarball != "" && !isSemver(keyVer):
			nd.unresolvable = "tarball URL dependency: " + r.Tarball
		}
		for _, deps := range []map[string]string{snap.Dependencies, snap.OptionalDependencies} {
			for _, dn := range sortedKeys(deps) {
				if id := resolve(dn, deps[dn]); id != "" && id != key {
					nd.edges = append(nd.edges, id)
				}
			}
		}
		ld.nodes[key] = nd
	}

	importers := lf.Importers
	if len(importers) == 0 {
		importers = map[string]pnpmImporter{".": {
			Dependencies:         lf.Dependencies,
			DevDependencies:      lf.DevDependencies,
			OptionalDependencies: lf.OptionalDependencies,
		}}
	}
	dirs := make([]string, 0, len(importers))
	for d := range importers {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		imp := importers[dir]
		if dir != "." {
			ld.members = append(ld.members, dir)
		}
		for _, sec := range []struct {
			deps  map[string]pnpmRef
			scope model.Scope
		}{
			{imp.Dependencies, model.ScopeProd},
			{imp.OptionalDependencies, model.ScopeOptional},
			{imp.DevDependencies, model.ScopeDev},
		} {
			names := make([]string, 0, len(sec.deps))
			for n := range sec.deps {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				ref := sec.deps[n]
				if id := resolve(n, ref.Version); id != "" {
					ld.roots = append(ld.roots, rootRef{id: id, key: n, scope: sec.scope})
				}
			}
		}
	}
	return ld, nil
}

// isSemver reports whether v is a valid npm version.
func isSemver(v string) bool { return version.NPM{}.Valid(v) }

// stripPeers drops the peer suffix: "a@1.0.0(b@2.0.0)" → "a@1.0.0".
func stripPeers(k string) string {
	if i := strings.IndexByte(k, '('); i > 0 {
		return k[:i]
	}
	return k
}

// pnpmKey splits a package key into name and version:
// "/a@1.0.0(peer@1)" (v6), "/@s/a/1.0.0_peer@1" (v5), "@s/a@1.0.0" (v9).
func pnpmKey(key string) (string, string) {
	s := strings.TrimPrefix(stripPeers(key), "/")
	start := 1
	if strings.HasPrefix(s, "@") {
		if i := strings.IndexByte(s, '/'); i >= 0 {
			start = i + 1
		}
	}
	if start > len(s) {
		return s, ""
	}
	i := strings.IndexAny(s[start:], "@/")
	if i < 0 {
		return s, ""
	}
	i += start
	name, ver := s[:i], s[i+1:]
	if s[i] == '/' { // v5: peers follow "_"
		if j := strings.IndexByte(ver, '_'); j > 0 {
			ver = ver[:j]
		}
	}
	return name, ver
}
