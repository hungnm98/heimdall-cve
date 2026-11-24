// Package gomod is the "go" ecosystem: it reads go.mod and go.work files with
// golang.org/x/mod/modfile.
//
// Rules:
//   - One graph per go.mod. go.work produces no graph; its replace directives
//     are applied to the graphs of the modules it uses, and requirements on
//     modules of the same workspace are marked unresolvable.
//   - require: Direct = !indirect. Scope is always prod.
//   - replace: a module→module replacement swaps name and version; a
//     replacement by a local path keeps the original package and marks it
//     unresolvable ("local replace: <path>"). A versioned replace wins over a
//     versionless one; go.work replaces win over go.mod replaces.
//   - exclude: a requirement on an excluded version is dropped (the version
//     the go command would pick instead is not knowable offline).
//   - Versions are kept as written (pseudo-versions, "+incompatible");
//     comparisons go through version.Go, which ignores "+incompatible".
//   - Private: GOPRIVATE semantics (module.MatchPrefixPatterns): a pattern
//     matches a module path when it matches, segment by segment with
//     path.Match, a leading run of the path's segments. "github.com/acme/*"
//     matches "github.com/acme/x" and "github.com/acme/x/y". A dependency is
//     private when its original or replacement path matches.
package gomod

import (
	"context"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"

	"github.com/hungnm98/heimdall-cve/internal/ecosystem"
	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/version"
)

func init() { ecosystem.Registry.Register("go", New) }

// GoMod implements ecosystem.Ecosystem for Go modules.
type GoMod struct {
	private string // comma-joined patterns for module.MatchPrefixPatterns
}

var _ ecosystem.Ecosystem = (*GoMod)(nil)

// New builds the ecosystem. It takes no plugin config.
func New(cfg plugin.Config, opts ecosystem.Options, _ plugin.Deps) (ecosystem.Ecosystem, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, fmt.Errorf("gomod: %w", err)
	}
	pats := make([]string, 0, len(opts.PrivatePatterns))
	for _, p := range opts.PrivatePatterns {
		p = strings.Trim(strings.TrimSpace(p), "/")
		if p == "" {
			continue
		}
		if strings.Contains(p, ",") {
			return nil, fmt.Errorf("gomod: private pattern %q: must not contain ','", p)
		}
		for _, seg := range strings.Split(p, "/") {
			if _, err := path.Match(seg, ""); err != nil {
				return nil, fmt.Errorf("gomod: private pattern %q: %w", p, err)
			}
		}
		pats = append(pats, p)
	}
	return &GoMod{private: strings.Join(pats, ",")}, nil
}

func (*GoMod) Name() model.Ecosystem        { return model.EcosystemGo }
func (*GoMod) Versions() version.Comparator { return version.Go{} }

// Match accepts go.mod and go.work anywhere outside vendor/ and testdata/.
func (*GoMod) Match(p string) bool {
	if b := path.Base(p); b != "go.mod" && b != "go.work" {
		return false
	}
	for _, seg := range strings.Split(path.Dir(p), "/") {
		if seg == "vendor" || seg == "testdata" {
			return false
		}
	}
	return true
}

// Parse returns one graph per go.mod, sorted by path. A file that fails to
// parse is skipped; the graphs of the other files are returned together with
// an error naming every skipped file.
func (g *GoMod) Parse(ctx context.Context, files model.FileSet) ([]*model.DependencyGraph, error) {
	var errs []error
	mods := map[string]*modfile.File{}
	var works []string
	for p, data := range files.Files {
		if !g.Match(p) {
			continue
		}
		if path.Base(p) == "go.work" {
			works = append(works, p)
			continue
		}
		f, err := modfile.Parse(p, data, nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("gomod: %w", err))
			continue
		}
		mods[p] = f
	}
	sort.Strings(works)

	// Workspace context per go.mod: replaces and sibling modules from go.work.
	type wsInfo struct {
		replaces []*modfile.Replace
		members  map[string]string // module path → dir of its go.mod
	}
	ws := map[string]*wsInfo{}
	for _, wp := range works {
		w, err := modfile.ParseWork(wp, files.Files[wp], nil)
		if err != nil {
			errs = append(errs, fmt.Errorf("gomod: %w", err))
			continue
		}
		info := &wsInfo{replaces: w.Replace, members: map[string]string{}}
		var used []string
		for _, u := range w.Use {
			if path.IsAbs(u.Path) {
				continue
			}
			mp := path.Join(path.Dir(wp), u.Path, "go.mod")
			if f, ok := mods[mp]; ok {
				used = append(used, mp)
				if f.Module != nil {
					info.members[f.Module.Mod.Path] = path.Dir(mp)
				}
			}
		}
		for _, mp := range used {
			if _, taken := ws[mp]; !taken { // first go.work (sorted) wins
				ws[mp] = info
			}
		}
	}

	paths := make([]string, 0, len(mods))
	for p := range mods {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	graphs := make([]*model.DependencyGraph, 0, len(paths))
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		f := mods[p]
		var workRep []*modfile.Replace
		var members map[string]string
		if info := ws[p]; info != nil {
			workRep, members = info.replaces, info.members
		}
		graphs = append(graphs, g.graph(p, f, workRep, members))
	}
	return graphs, errors.Join(errs...)
}

func (g *GoMod) graph(manifest string, f *modfile.File, workRep []*modfile.Replace, members map[string]string) *model.DependencyGraph {
	gr := &model.DependencyGraph{Ecosystem: model.EcosystemGo, ManifestPath: manifest}
	self := ""
	if f.Module != nil {
		self = f.Module.Mod.Path
	}
	index := map[string]int{} // resulting name → position in Dependencies
	for _, r := range f.Require {
		mod := r.Mod
		if excluded(f.Exclude, mod) {
			continue
		}
		name, ver := mod.Path, mod.Version
		unresolvable := ""
		rep := findReplace(workRep, mod)
		if rep == nil {
			rep = findReplace(f.Replace, mod)
		}
		if rep != nil {
			if rep.New.Version == "" {
				unresolvable = "local replace: " + rep.New.Path
			} else {
				name, ver = rep.New.Path, rep.New.Version
			}
		} else if dir, ok := members[mod.Path]; ok && mod.Path != self {
			unresolvable = "workspace module: " + dir
		}
		d := model.Dependency{
			Package:      model.NewPackage(model.EcosystemGo, name, ver),
			Direct:       !r.Indirect,
			Scope:        model.ScopeProd,
			Private:      g.isPrivate(mod.Path) || g.isPrivate(name),
			Unresolvable: unresolvable,
		}
		if i, dup := index[name]; dup {
			// Duplicate requirement (or two modules replaced by the same one):
			// the go command uses the highest version.
			prev := &gr.Dependencies[i]
			direct, private := d.Direct || prev.Direct, d.Private || prev.Private
			if (version.Go{}).Compare(d.Version, prev.Version) > 0 {
				*prev = d
			}
			prev.Direct, prev.Private = direct, private
			continue
		}
		index[name] = len(gr.Dependencies)
		gr.Dependencies = append(gr.Dependencies, d)
	}
	return gr
}

// findReplace returns the replace directive applying to m: an exact version
// match first, then a versionless one. Nil when none applies.
func findReplace(reps []*modfile.Replace, m module.Version) *modfile.Replace {
	var anyVer *modfile.Replace
	for _, r := range reps {
		if r.Old.Path != m.Path {
			continue
		}
		if r.Old.Version == "" {
			if anyVer == nil {
				anyVer = r
			}
			continue
		}
		if sameVersion(r.Old.Version, m.Version) {
			return r
		}
	}
	return anyVer
}

func excluded(ex []*modfile.Exclude, m module.Version) bool {
	for _, e := range ex {
		if e.Mod.Path == m.Path && sameVersion(e.Mod.Version, m.Version) {
			return true
		}
	}
	return false
}

// sameVersion compares as written, then via version.Go (which ignores
// "+incompatible").
func sameVersion(a, b string) bool {
	v := version.Go{}
	return a == b || (v.Valid(a) && v.Valid(b) && v.Canonical(a) == v.Canonical(b))
}

func (g *GoMod) isPrivate(name string) bool {
	return g.private != "" && module.MatchPrefixPatterns(g.private, name)
}
