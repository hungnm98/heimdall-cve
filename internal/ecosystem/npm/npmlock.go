package npm

import (
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// npmLock is package-lock.json / npm-shrinkwrap.json, any lockfileVersion.
type npmLock struct {
	LockfileVersion int                  `json:"lockfileVersion"`
	Packages        map[string]*npmPkg   `json:"packages"`     // v2, v3
	Dependencies    map[string]*npmV1Dep `json:"dependencies"` // v1 (v2 keeps both)
}

type npmPkg struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Link                 bool              `json:"link"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	DevOptional          bool              `json:"devOptional"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
}

type npmV1Dep struct {
	Version      string               `json:"version"`
	Resolved     string               `json:"resolved"`
	Dev          bool                 `json:"dev"`
	Optional     bool                 `json:"optional"`
	Requires     map[string]string    `json:"requires"`
	Dependencies map[string]*npmV1Dep `json:"dependencies"`
}

func parseNPMLock(data []byte, decls []decl) (*lockData, error) {
	var lf npmLock
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, err
	}
	if len(lf.Packages) > 0 {
		return npmV2(lf.Packages), nil
	}
	if lf.LockfileVersion > 1 && lf.Dependencies == nil {
		return nil, errors.New("lockfile has neither packages nor dependencies")
	}
	return npmV1(lf.Dependencies, decls), nil
}

// resolveNM finds the node_modules entry a package at from sees for name,
// walking up the nested node_modules directories like Node's resolver.
func resolveNM(exists func(string) bool, from, name string) string {
	base := from
	for {
		cand := "node_modules/" + name
		if base != "" {
			cand = base + "/" + cand
		}
		if exists(cand) {
			return cand
		}
		if base == "" {
			return ""
		}
		if i := strings.LastIndex(base, "node_modules/"); i >= 0 {
			base = strings.TrimSuffix(base[:i], "/")
		} else {
			base = ""
		}
	}
}

func nmName(key string) string {
	if i := strings.LastIndex(key, "node_modules/"); i >= 0 {
		return key[i+len("node_modules/"):]
	}
	return path.Base(key)
}

func npmScope(dev, optional, devOptional bool) model.Scope {
	switch {
	case dev, devOptional:
		return model.ScopeDev
	case optional:
		return model.ScopeOptional
	}
	return model.ScopeProd
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// npmV2 reads the "packages" map of lockfileVersion 2/3.
func npmV2(pkgs map[string]*npmPkg) *lockData {
	ld := newLockData()
	exists := func(k string) bool { _, ok := pkgs[k]; return ok }
	follow := func(id string) string {
		for range 8 {
			p := pkgs[id]
			if p == nil || !p.Link {
				return id
			}
			id = path.Clean(p.Resolved)
		}
		return id
	}
	resolve := func(from, name string) string {
		if id := resolveNM(exists, from, name); id != "" {
			return follow(id)
		}
		return ""
	}
	isNM := func(k string) bool {
		return strings.HasPrefix(k, "node_modules/") || strings.Contains(k, "/node_modules/")
	}

	for key, p := range pkgs {
		if p == nil || p.Link {
			continue
		}
		project := key == "" || (!isNM(key) && !strings.HasPrefix(key, ".."))
		var edges []string
		addEdges := func(deps map[string]string, scope model.Scope, asRoot bool) {
			for _, name := range sortedKeys(deps) {
				id := resolve(key, name)
				if id == "" || id == key {
					continue
				}
				edges = append(edges, id)
				if asRoot {
					ld.roots = append(ld.roots, rootRef{id: id, key: name, scope: scope})
				}
			}
		}
		addEdges(p.Dependencies, model.ScopeProd, project)
		addEdges(p.OptionalDependencies, model.ScopeOptional, project)
		addEdges(p.PeerDependencies, model.ScopeProd, project)
		if project {
			addEdges(p.DevDependencies, model.ScopeDev, true)
		}

		switch {
		case project:
			ld.nodes[key] = &node{name: p.Name, skip: true, edges: edges}
			if key != "" {
				ld.members = append(ld.members, key)
			}
		case strings.HasPrefix(key, ".."): // file: dependency outside the project
			name := p.Name
			if name == "" {
				name = path.Base(key)
			}
			ld.nodes[key] = &node{
				name: name, version: p.Version, edges: edges,
				unresolvable: "local path dependency: file:" + key,
				scope:        npmScope(p.Dev, p.Optional, p.DevOptional),
			}
		default:
			name := p.Name
			if name == "" {
				name = nmName(key)
			}
			ld.nodes[key] = &node{
				name: name, version: p.Version, edges: edges,
				unresolvable: lockSourceReason(p.Resolved),
				scope:        npmScope(p.Dev, p.Optional, p.DevOptional),
			}
		}
	}
	return ld
}

// npmV1 reads the nested "dependencies" tree of lockfileVersion 1. Nodes get
// the same node_modules keys as v2 so resolution is shared.
func npmV1(deps map[string]*npmV1Dep, decls []decl) *lockData {
	flat := map[string]*npmV1Dep{}
	var walk func(prefix string, deps map[string]*npmV1Dep)
	walk = func(prefix string, deps map[string]*npmV1Dep) {
		for name, d := range deps {
			if d == nil {
				continue
			}
			key := "node_modules/" + name
			if prefix != "" {
				key = prefix + "/" + key
			}
			flat[key] = d
			walk(key, d.Dependencies)
		}
	}
	walk("", deps)
	exists := func(k string) bool { _, ok := flat[k]; return ok }

	ld := newLockData()
	for key, d := range flat {
		nd := &node{name: nmName(key), version: d.Version, scope: npmScope(d.Dev, d.Optional, false)}
		if real, v, ok := alias(d.Version); ok {
			nd.name, nd.version = real, v
		} else if reason := lockSourceReason(d.Version); reason != "" {
			nd.version, nd.unresolvable = "", reason
		}
		if nd.unresolvable == "" {
			nd.unresolvable = lockSourceReason(d.Resolved)
		}
		for _, name := range sortedKeys(d.Requires) {
			if id := resolveNM(exists, key, name); id != "" && id != key {
				nd.edges = append(nd.edges, id)
			}
		}
		ld.nodes[key] = nd
	}
	for _, dc := range decls {
		if id := resolveNM(exists, "", dc.key); id != "" {
			ld.roots = append(ld.roots, rootRef{id: id, key: dc.key, scope: dc.scope})
		}
	}
	return ld
}
