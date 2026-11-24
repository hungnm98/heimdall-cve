// Package rubygems is the "rubygems" ecosystem: it reads Bundler lockfiles
// (Gemfile.lock, gems.locked) and, when a directory has no lockfile, its
// Gemfile / gems.rb.
//
// Rules:
//   - One graph per lockfile (ManifestPath = the lockfile). A Gemfile with a
//     sibling lockfile (Gemfile ↔ Gemfile.lock, gems.rb ↔ gems.locked) produces
//     no graph of its own; it only refines scopes (see below).
//   - Lockfile sources: gems listed under GEM specs are resolvable; gems under
//     GIT, PATH and PLUGIN SOURCE are Unresolvable ("git source", "path
//     source", "plugin source") and keep the version the lockfile records.
//     Platform suffixes are stripped ("1.16.2-x86_64-linux" → "1.16.2", as
//     Bundler does: everything after the first "-"); a gem locked for several
//     platforms is one dependency (highest version if they differ).
//   - Direct = listed in DEPENDENCIES (a trailing "!" only says the gem has an
//     explicit source; the source sections decide resolvability). A direct
//     gem without a spec (e.g. "bundler") is skipped. Transitive gems get as
//     Parents every direct gem whose spec dependency closure reaches them.
//   - Scope: the lockfile has no group information, so everything is prod.
//     When the sibling Gemfile is present, a direct gem whose every
//     declaration sits only in development/test groups (group blocks or
//     group:/groups: options) is dev, and a transitive gem is dev when all of
//     its parents are dev. The Gemfile reader is a best-effort line parser:
//     it understands literal gem/group/git/path/github statements and do/end
//     and if/unless/case/begin/def blocks; gems added by gemspec, eval_gemfile,
//     loops or other dynamic Ruby are invisible to it and stay prod.
//   - Gemfile without a lockfile → Approximate, Direct dependencies. The
//     version is the minimum one satisfying the literal requirements when it
//     can be computed (~> 1.2 → 1.2, >= 1.2.3 → 1.2.3, = 1.2 → 1.2; the
//     highest lower bound among =, >=, ~> that also satisfies every other
//     requirement); otherwise the gem is Unresolvable ("no version
//     constraint", "unsupported constraint ..."). git:, github:, gist:,
//     bitbucket: and path: options, and gems inside git/github/path blocks,
//     are Unresolvable.
//   - Private: a gem is private when its name matches one of
//     ecosystem.Options.PrivatePatterns with path.Match ("acme-*" matches
//     "acme-billing"; matching is case-sensitive and on the whole name).
//   - vendor/bundle trees are ignored.
package rubygems

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

func init() { ecosystem.Registry.Register("rubygems", New) }

// RubyGems implements ecosystem.Ecosystem for Bundler projects.
type RubyGems struct {
	private []string
}

var _ ecosystem.Ecosystem = (*RubyGems)(nil)

// New builds the ecosystem. It takes no plugin config.
func New(cfg plugin.Config, opts ecosystem.Options, _ plugin.Deps) (ecosystem.Ecosystem, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, fmt.Errorf("rubygems: %w", err)
	}
	var pats []string
	for _, p := range opts.PrivatePatterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("rubygems: private pattern %q: %w", p, err)
		}
		pats = append(pats, p)
	}
	return &RubyGems{private: pats}, nil
}

func (*RubyGems) Name() model.Ecosystem        { return model.EcosystemRubyGems }
func (*RubyGems) Versions() version.Comparator { return version.RubyGems{} }

// lockOf maps a Gemfile name to its lockfile name, and back.
var (
	lockOf    = map[string]string{"Gemfile": "Gemfile.lock", "gems.rb": "gems.locked"}
	gemfileOf = map[string]string{"Gemfile.lock": "Gemfile", "gems.locked": "gems.rb"}
)

// Match accepts Gemfile, Gemfile.lock, gems.rb and gems.locked anywhere
// outside vendor/bundle.
func (*RubyGems) Match(p string) bool {
	b := path.Base(p)
	if lockOf[b] == "" && gemfileOf[b] == "" {
		return false
	}
	segs := strings.Split(path.Dir(p), "/")
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == "vendor" && segs[i+1] == "bundle" {
			return false
		}
	}
	return true
}

// Parse returns one graph per lockfile and per Gemfile without a lockfile,
// sorted by path. A lockfile that fails to parse is skipped; the other graphs
// are returned together with an error naming every skipped file.
func (r *RubyGems) Parse(ctx context.Context, files model.FileSet) ([]*model.DependencyGraph, error) {
	var paths []string
	for p := range files.Files {
		if r.Match(p) {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	var errs []error
	graphs := make([]*model.DependencyGraph, 0, len(paths))
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		dir, base := path.Split(p)
		if gf, isLock := gemfileOf[base]; isLock {
			lf, err := parseLockfile(files.Files[p])
			if err != nil {
				errs = append(errs, fmt.Errorf("rubygems: %s: %w", p, err))
				continue
			}
			var decls []gemDecl
			if data, ok := files.Files[dir+gf]; ok {
				decls = parseGemfile(data)
			}
			graphs = append(graphs, r.lockGraph(p, lf, decls))
			continue
		}
		if _, hasLock := files.Files[dir+lockOf[base]]; hasLock {
			continue
		}
		graphs = append(graphs, r.gemfileGraph(p, parseGemfile(files.Files[p])))
	}
	return graphs, errors.Join(errs...)
}

var unresolvableSource = map[string]string{
	srcGit:    "git source",
	srcPath:   "path source",
	srcPlugin: "plugin source",
}

func (r *RubyGems) lockGraph(manifest string, lf *lockfile, decls []gemDecl) *model.DependencyGraph {
	g := &model.DependencyGraph{Ecosystem: model.EcosystemRubyGems, ManifestPath: manifest}

	// Parents: BFS from each direct gem over spec dependency edges.
	parents := map[string][]string{}
	for _, d := range sortedKeys(lf.direct) {
		if lf.specs[d] == nil {
			continue
		}
		seen := map[string]bool{d: true}
		queue := []string{d}
		for len(queue) > 0 {
			s := lf.specs[queue[0]]
			queue = queue[1:]
			if s == nil {
				continue
			}
			for _, dep := range s.deps {
				if seen[dep] {
					continue
				}
				seen[dep] = true
				queue = append(queue, dep)
				if !lf.direct[dep] {
					parents[dep] = append(parents[dep], d)
				}
			}
		}
	}

	dev := devGems(decls)
	for _, name := range sortedKeys(lf.specs) {
		s := lf.specs[name]
		d := model.Dependency{
			Package:      model.NewPackage(model.EcosystemRubyGems, name, s.version),
			Direct:       lf.direct[name],
			Scope:        model.ScopeProd,
			Private:      r.isPrivate(name),
			Unresolvable: unresolvableSource[s.source],
		}
		if d.Direct {
			if dev[name] {
				d.Scope = model.ScopeDev
			}
		} else if ps := parents[name]; len(ps) > 0 {
			d.Parents = ps
			allDev := true
			for _, p := range ps {
				allDev = allDev && dev[p]
			}
			if allDev {
				d.Scope = model.ScopeDev
			}
		}
		g.Dependencies = append(g.Dependencies, d)
	}
	return g
}

func (r *RubyGems) gemfileGraph(manifest string, decls []gemDecl) *model.DependencyGraph {
	g := &model.DependencyGraph{Ecosystem: model.EcosystemRubyGems, ManifestPath: manifest}
	dev := devGems(decls)
	seen := map[string]bool{}
	for _, decl := range decls {
		if seen[decl.name] {
			continue // first declaration decides the version
		}
		seen[decl.name] = true
		ver, reason := minVersion(decl.reqs)
		if decl.dynamic {
			ver, reason = "", "non-literal requirement"
		}
		if why := unresolvableSource[decl.source]; why != "" {
			reason = why
		}
		d := model.Dependency{
			Package:      model.NewPackage(model.EcosystemRubyGems, decl.name, ver),
			Direct:       true,
			Scope:        model.ScopeProd,
			Approximate:  true,
			Private:      r.isPrivate(decl.name),
			Unresolvable: reason,
		}
		if dev[decl.name] {
			d.Scope = model.ScopeDev
		}
		g.Dependencies = append(g.Dependencies, d)
	}
	sort.Slice(g.Dependencies, func(i, j int) bool { return g.Dependencies[i].Name < g.Dependencies[j].Name })
	return g
}

func (r *RubyGems) isPrivate(name string) bool {
	for _, p := range r.private {
		if ok, _ := path.Match(p, name); ok {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
