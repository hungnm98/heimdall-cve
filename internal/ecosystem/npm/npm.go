// Package npm is the "npm" ecosystem: it reads package.json and the npm,
// Yarn and pnpm lockfiles.
//
// Rules:
//   - Files: package.json, package-lock.json, npm-shrinkwrap.json, yarn.lock
//     (v1 and Berry) and pnpm-lock.yaml (v5/v6/v9), anywhere outside
//     node_modules/.
//   - Lockfiles win. Every lockfile produces one graph (ManifestPath = the
//     lockfile) with exact versions and the full transitive set, except that
//     npm-shrinkwrap.json shadows a package-lock.json in the same directory
//     (as npm does). Two different lockfiles in one directory (e.g. a stale
//     yarn.lock next to package-lock.json) each produce a graph.
//   - Workspaces: a lockfile covers the package.json of its own directory
//     and of every workspace member: directories matched by the root
//     package.json "workspaces" globs (array or {packages: [...]}), pnpm
//     importers, Yarn Berry workspace entries and npm lock v2+ "packages"
//     keys outside node_modules. Covered package.json files produce no graph
//     of their own. Members' own packages are first-party and not reported.
//   - A package.json no lockfile covers produces a graph whose dependencies
//     are all Direct and Approximate, at the minimum version of a simple
//     range (^1.2.3, ~1.2.3, >=1.2.3, =1.2.3, 1.2.3, 1.2.x → 1.2.0); other
//     ranges are Unresolvable ("range <r>"). Sections are read in the order
//     dependencies, optionalDependencies, devDependencies, peerDependencies;
//     the first declaration of a name wins.
//   - Direct: declared by the owning package.json (any of the four sections),
//     by a pnpm importer, by the root/workspace entries of a lock v2+ or by a
//     Yarn Berry workspace entry. When neither the lockfile nor a package.json
//     says (lock v1 / yarn v1 without package.json), packages nothing else
//     depends on are taken as direct.
//   - Scope: npm lock flags (dev → dev, devOptional → dev, optional →
//     optional, else prod) and pnpm v6 dev/optional flags. Otherwise it is
//     computed from the lockfile edges: reachable from a prod root → prod,
//     else from an optional root → optional, else dev.
//   - Parents (transitive dependencies only): names of the direct
//     dependencies whose subtree contains the package, from the lockfile
//     edges. The walk is bounded (maxParentWork edge visits per lockfile), so
//     Parents may be incomplete or empty on huge graphs.
//   - Aliases ("npm:real@range") report the real package name.
//   - file:, link:, portal:, workspace:, git (git+, git:, github:, ...,
//     user/repo), http(s) tarball and exec: sources are Unresolvable with the
//     reason; so is any lockfile version that is not valid semver.
//   - Private: a dependency is private when its full name matches one of
//     ecosystem.Options.PrivatePatterns with path.Match: "@acme/*" matches
//     "@acme/ui" (and every package of the scope), "acme-*" matches
//     "acme-utils". Patterns written for other ecosystems simply never match.
package npm

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

func init() { ecosystem.Registry.Register("npm", New) }

// File names this ecosystem reads.
const (
	fPackageJSON = "package.json"
	fPackageLock = "package-lock.json"
	fShrinkwrap  = "npm-shrinkwrap.json"
	fYarnLock    = "yarn.lock"
	fPnpmLock    = "pnpm-lock.yaml"
)

// maxParentWork bounds the edge visits spent computing Parents per lockfile.
const maxParentWork = 2_000_000

// NPM implements ecosystem.Ecosystem for npm packages.
type NPM struct {
	private []string
}

var _ ecosystem.Ecosystem = (*NPM)(nil)

// New builds the ecosystem. It takes no plugin config.
func New(cfg plugin.Config, opts ecosystem.Options, _ plugin.Deps) (ecosystem.Ecosystem, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, fmt.Errorf("npm: %w", err)
	}
	var pats []string
	for _, p := range opts.PrivatePatterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("npm: private pattern %q: %w", p, err)
		}
		pats = append(pats, p)
	}
	return &NPM{private: pats}, nil
}

func (*NPM) Name() model.Ecosystem        { return model.EcosystemNPM }
func (*NPM) Versions() version.Comparator { return version.NPM{} }

// Match accepts package.json and the supported lockfiles outside node_modules/.
func (*NPM) Match(p string) bool {
	switch path.Base(p) {
	case fPackageJSON, fPackageLock, fShrinkwrap, fYarnLock, fPnpmLock:
	default:
		return false
	}
	return !slices.Contains(strings.Split(path.Dir(p), "/"), "node_modules")
}

// Parse returns one graph per lockfile plus one per package.json no lockfile
// covers, sorted by path. A file that fails to parse is skipped (a broken
// lockfile leaves its package.json uncovered, so it falls back to an
// approximate graph); the other graphs are returned together with an error
// naming every skipped file.
func (n *NPM) Parse(ctx context.Context, files model.FileSet) ([]*model.DependencyGraph, error) {
	var errs []error
	manifests := map[string]*manifest{} // dir → package.json
	locks := map[string][]string{}      // dir → lockfile paths
	for p, data := range files.Files {
		if !n.Match(p) {
			continue
		}
		dir := path.Dir(p)
		if path.Base(p) == fPackageJSON {
			m, err := parseManifest(p, data)
			if err != nil {
				errs = append(errs, fmt.Errorf("npm: %s: %w", p, err))
				continue
			}
			manifests[dir] = m
			continue
		}
		locks[dir] = append(locks[dir], p)
	}

	var lockPaths []string
	for dir, ps := range locks {
		shrink := slices.Contains(ps, path.Join(dir, fShrinkwrap))
		for _, p := range ps {
			if shrink && path.Base(p) == fPackageLock {
				continue
			}
			lockPaths = append(lockPaths, p)
		}
	}
	sort.Strings(lockPaths)

	var graphs []*model.DependencyGraph
	covered := map[string]bool{}
	for _, lp := range lockPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		g, dirs, err := n.lockGraph(lp, files.Files[lp], manifests)
		if err != nil {
			errs = append(errs, fmt.Errorf("npm: %s: %w", lp, err))
			continue
		}
		for _, d := range dirs {
			covered[d] = true
		}
		graphs = append(graphs, g)
	}
	for dir, m := range manifests {
		if !covered[dir] {
			graphs = append(graphs, n.approximate(m))
		}
	}
	sort.Slice(graphs, func(i, j int) bool { return graphs[i].ManifestPath < graphs[j].ManifestPath })
	return graphs, errors.Join(errs...)
}

// node is one package instance of a lockfile.
type node struct {
	name, version string
	unresolvable  string
	scope         model.Scope // "" when the lockfile does not say
	optional      bool        // flagged optional: a computed prod scope becomes optional
	skip          bool        // workspace member or link: traversed, never reported
	edges         []string    // ids of the nodes it depends on
}

// rootRef is a direct dependency: a node id plus the name it is declared under.
type rootRef struct {
	id    string
	key   string
	scope model.Scope // "" → taken from package.json
}

// lockData is a parsed lockfile in a format-neutral shape.
type lockData struct {
	nodes   map[string]*node
	roots   []rootRef
	members []string // workspace member dirs relative to the lockfile dir
}

func newLockData() *lockData { return &lockData{nodes: map[string]*node{}} }

// lockGraph parses one lockfile and returns its graph plus the manifest
// directories it covers.
func (n *NPM) lockGraph(lp string, data []byte, manifests map[string]*manifest) (*model.DependencyGraph, []string, error) {
	dir := path.Dir(lp)
	root := manifests[dir]
	memberDirs := map[string]bool{}
	if root != nil {
		for md := range manifests {
			if rel, ok := relTo(dir, md); ok && matchWorkspace(root.workspaces(), rel) {
				memberDirs[md] = true
			}
		}
	}
	owners := func() []*manifest {
		out := []*manifest{}
		if root != nil {
			out = append(out, root)
		}
		ds := make([]string, 0, len(memberDirs))
		for d := range memberDirs {
			ds = append(ds, d)
		}
		sort.Strings(ds)
		for _, d := range ds {
			if m := manifests[d]; m != nil && m != root {
				out = append(out, m)
			}
		}
		return out
	}

	var ld *lockData
	var err error
	switch path.Base(lp) {
	case fPackageLock, fShrinkwrap:
		ld, err = parseNPMLock(data, declsOf(owners()))
	case fYarnLock:
		if isBerry(data) {
			ld, err = parseBerry(data)
		} else {
			ld, err = parseYarnV1(data, declsOf(owners()))
		}
	case fPnpmLock:
		ld, err = parsePnpm(data)
	}
	if err != nil {
		return nil, nil, err
	}
	for _, rel := range ld.members {
		if md := path.Join(dir, rel); md != dir && !strings.HasPrefix(md, "..") {
			memberDirs[md] = true
		}
	}
	all := owners()
	internal := map[string]bool{}
	for _, m := range all {
		if m.Name != "" {
			internal[m.Name] = true
		}
	}
	finishRoots(ld, declsOf(all), internal)

	dirs := []string{dir}
	for d := range memberDirs {
		dirs = append(dirs, d)
	}
	return n.build(lp, ld), dirs, nil
}

// finishRoots fills root scopes from package.json declarations, records
// non-registry declarations the lockfile does not resolve, and falls back to
// "nothing depends on it" roots when nothing declares any.
func finishRoots(ld *lockData, decls []decl, internal map[string]bool) {
	byKey := map[string]model.Scope{}
	for _, d := range decls {
		byKey[d.key] = better(byKey[d.key], d.scope)
	}
	for i := range ld.roots {
		if ld.roots[i].scope == "" {
			ld.roots[i].scope = byKey[ld.roots[i].key]
			if ld.roots[i].scope == "" {
				ld.roots[i].scope = model.ScopeProd
			}
		}
	}
	for _, d := range decls {
		reason := sourceReason(d.spec)
		if reason == "" || strings.HasPrefix(d.spec, "workspace:") || internal[d.name] {
			continue
		}
		found := false
		for _, r := range ld.roots {
			nd := ld.nodes[r.id]
			if nd == nil || (r.key != d.key && nd.name != d.name) {
				continue
			}
			found = true
			if !nd.skip && nd.unresolvable == "" {
				nd.unresolvable = reason
			}
		}
		if !found {
			id := "declared:" + d.key
			if ld.nodes[id] == nil {
				ld.nodes[id] = &node{name: d.name, unresolvable: reason, scope: d.scope}
				ld.roots = append(ld.roots, rootRef{id: id, key: d.key, scope: d.scope})
			}
		}
	}
	if len(ld.roots) > 0 {
		return
	}
	incoming := map[string]bool{}
	for _, nd := range ld.nodes {
		for _, e := range nd.edges {
			incoming[e] = true
		}
	}
	for id, nd := range ld.nodes {
		if !incoming[id] && !nd.skip {
			ld.roots = append(ld.roots, rootRef{id: id, key: nd.name, scope: model.ScopeProd})
		}
	}
}

func scopeRank(s model.Scope) int {
	switch s {
	case model.ScopeProd:
		return 3
	case model.ScopeOptional:
		return 2
	case model.ScopeDev:
		return 1
	}
	return 0
}

// better returns the wider of two scopes (prod > optional > dev > "").
func better(a, b model.Scope) model.Scope {
	if scopeRank(b) > scopeRank(a) {
		return b
	}
	return a
}

// build turns parsed lockfile data into a graph.
func (n *NPM) build(manifest string, ld *lockData) *model.DependencyGraph {
	rootScope := map[string]model.Scope{}
	for _, r := range ld.roots {
		if ld.nodes[r.id] != nil {
			rootScope[r.id] = better(rootScope[r.id], r.scope)
		}
	}
	rootIDs := make([]string, 0, len(rootScope))
	for id := range rootScope {
		rootIDs = append(rootIDs, id)
	}
	sort.Strings(rootIDs)

	// Computed scope: widest scope of a root the node is reachable from.
	computed := map[string]model.Scope{}
	for _, sc := range []model.Scope{model.ScopeProd, model.ScopeOptional, model.ScopeDev} {
		var queue []string
		for _, id := range rootIDs {
			if rootScope[id] == sc && computed[id] == "" {
				computed[id] = sc
				queue = append(queue, id)
			}
		}
		for len(queue) > 0 {
			id := queue[0]
			queue = queue[1:]
			for _, e := range ld.nodes[id].edges {
				if computed[e] == "" && ld.nodes[e] != nil {
					computed[e] = sc
					queue = append(queue, e)
				}
			}
		}
	}

	// Parents: bounded BFS from every reported root.
	parents := map[string]map[string]bool{}
	budget := maxParentWork
	for _, rid := range rootIDs {
		rn := ld.nodes[rid]
		if rn.skip {
			continue
		}
		seen := map[string]bool{rid: true}
		queue := append([]string(nil), rn.edges...)
		for len(queue) > 0 && budget > 0 {
			id := queue[0]
			queue = queue[1:]
			budget--
			nd := ld.nodes[id]
			if seen[id] || nd == nil {
				continue
			}
			seen[id] = true
			if _, isRoot := rootScope[id]; !isRoot && !nd.skip {
				if parents[id] == nil {
					parents[id] = map[string]bool{}
				}
				parents[id][rn.name] = true
			}
			queue = append(queue, nd.edges...)
		}
	}

	ids := make([]string, 0, len(ld.nodes))
	for id := range ld.nodes {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	type key struct{ name, version string }
	merged := map[key]*model.Dependency{}
	pset := map[key]map[string]bool{}
	var order []key
	for _, id := range ids {
		nd := ld.nodes[id]
		if nd.skip || nd.name == "" {
			continue
		}
		scope := nd.scope
		if scope == "" {
			scope = computed[id]
		}
		// Unreached nodes keep "" until merged (prod at the end) so they
		// do not widen the scope of a reached copy of the same version.
		if nd.optional && scope == model.ScopeProd {
			scope = model.ScopeOptional
		}
		unres := nd.unresolvable
		if unres == "" {
			switch {
			case nd.version == "":
				unres = "no version in lockfile"
			case !(version.NPM{}).Valid(nd.version):
				unres = "unrecognized version " + nd.version
			}
		}
		_, direct := rootScope[id]
		k := key{nd.name, nd.version}
		if prev, ok := merged[k]; ok {
			prev.Direct = prev.Direct || direct
			prev.Scope = better(prev.Scope, scope)
			if prev.Unresolvable == "" {
				prev.Unresolvable = unres
			}
		} else {
			merged[k] = &model.Dependency{
				Package:      model.NewPackage(model.EcosystemNPM, nd.name, nd.version),
				Direct:       direct,
				Scope:        scope,
				Private:      n.isPrivate(nd.name),
				Unresolvable: unres,
			}
			pset[k] = map[string]bool{}
			order = append(order, k)
		}
		for p := range parents[id] {
			pset[k][p] = true
		}
	}
	g := &model.DependencyGraph{Ecosystem: model.EcosystemNPM, ManifestPath: manifest}
	for _, k := range order {
		d := merged[k]
		if d.Scope == "" {
			d.Scope = model.ScopeProd
		}
		if !d.Direct {
			for p := range pset[k] {
				d.Parents = append(d.Parents, p)
			}
			sort.Strings(d.Parents)
		}
		g.Dependencies = append(g.Dependencies, *d)
	}
	sortDeps(g.Dependencies)
	return g
}

// approximate builds the graph of a package.json without lockfile.
func (n *NPM) approximate(m *manifest) *model.DependencyGraph {
	g := &model.DependencyGraph{Ecosystem: model.EcosystemNPM, ManifestPath: m.path}
	for _, d := range m.decls() {
		ver, unres := "", sourceReason(d.spec)
		if unres == "" {
			if v, ok := minVersion(d.spec); ok {
				ver = v
			} else {
				unres = "range " + d.spec
			}
		}
		g.Dependencies = append(g.Dependencies, model.Dependency{
			Package:      model.NewPackage(model.EcosystemNPM, d.name, ver),
			Direct:       true,
			Scope:        d.scope,
			Approximate:  true,
			Private:      n.isPrivate(d.name),
			Unresolvable: unres,
		})
	}
	sortDeps(g.Dependencies)
	return g
}

func sortDeps(ds []model.Dependency) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Name != ds[j].Name {
			return ds[i].Name < ds[j].Name
		}
		return ds[i].Version < ds[j].Version
	})
}

func (n *NPM) isPrivate(name string) bool {
	for _, p := range n.private {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}
