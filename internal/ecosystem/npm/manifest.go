package npm

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

// manifest is the part of a package.json this ecosystem reads.
type manifest struct {
	path                 string
	Name                 string            `json:"name"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	Workspaces           json.RawMessage   `json:"workspaces"`
}

func parseManifest(p string, data []byte) (*manifest, error) {
	m := &manifest{path: p}
	if err := json.Unmarshal(data, m); err != nil {
		return nil, err
	}
	return m, nil
}

// workspaces returns the workspace globs: "workspaces": [...] or
// "workspaces": {"packages": [...]}.
func (m *manifest) workspaces() []string {
	if len(m.Workspaces) == 0 {
		return nil
	}
	var list []string
	if json.Unmarshal(m.Workspaces, &list) == nil {
		return list
	}
	var obj struct {
		Packages []string `json:"packages"`
	}
	if json.Unmarshal(m.Workspaces, &obj) == nil {
		return obj.Packages
	}
	return nil
}

// decl is one dependency declared in a package.json.
type decl struct {
	key   string      // name it is declared under (the alias for "npm:" aliases)
	name  string      // real package name
	raw   string      // spec as written
	spec  string      // range, alias prefix removed
	scope model.Scope // section it is declared in
}

// decls returns the declarations in section order (dependencies,
// optionalDependencies, devDependencies, peerDependencies); the first
// declaration of a name wins.
func (m *manifest) decls() []decl {
	seen := map[string]bool{}
	var out []decl
	for _, sec := range []struct {
		deps  map[string]string
		scope model.Scope
	}{
		{m.Dependencies, model.ScopeProd},
		{m.OptionalDependencies, model.ScopeOptional},
		{m.DevDependencies, model.ScopeDev},
		{m.PeerDependencies, model.ScopeProd},
	} {
		keys := make([]string, 0, len(sec.deps))
		for k := range sec.deps {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if seen[k] {
				continue
			}
			seen[k] = true
			raw := strings.TrimSpace(sec.deps[k])
			name, spec := k, raw
			if real, r, ok := alias(raw); ok {
				name, spec = real, r
			}
			out = append(out, decl{key: k, name: name, raw: raw, spec: spec, scope: sec.scope})
		}
	}
	return out
}

func declsOf(ms []*manifest) []decl {
	var out []decl
	for _, m := range ms {
		out = append(out, m.decls()...)
	}
	return out
}

// alias splits "npm:real@range" into ("real", "range"). A missing range is "*".
func alias(spec string) (name, rng string, ok bool) {
	rest, ok := strings.CutPrefix(spec, "npm:")
	if !ok {
		return "", "", false
	}
	if at := strings.LastIndex(rest, "@"); at > 0 {
		return rest[:at], rest[at+1:], true
	}
	return rest, "*", true
}

// splitSpec splits "name@range" (name may be scoped) at the "@" after the name.
func splitSpec(s string) (name, rng string) {
	if len(s) > 1 {
		if i := strings.IndexByte(s[1:], '@'); i >= 0 {
			return s[:i+1], s[i+2:]
		}
	}
	return s, ""
}

var (
	ghShorthandRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?$`)
	sourcePrefix  = []struct{ prefix, kind string }{
		{"file:", "local path"}, {"link:", "local link"}, {"portal:", "local portal"},
		{"workspace:", "workspace"}, {"exec:", "exec"},
		{"git+", "git"}, {"git:", "git"}, {"github:", "git"}, {"gitlab:", "git"},
		{"bitbucket:", "git"}, {"gist:", "git"},
		{"http://", "tarball URL"}, {"https://", "tarball URL"},
	}
)

// sourceReason returns why a package.json spec cannot be checked against
// public sources (a non-registry source), or "".
func sourceReason(spec string) string {
	s := strings.TrimSpace(spec)
	lower := strings.ToLower(s)
	for _, p := range sourcePrefix {
		if strings.HasPrefix(lower, p.prefix) {
			return p.kind + " dependency: " + s
		}
	}
	switch {
	case strings.HasPrefix(s, "./"), strings.HasPrefix(s, "../"), strings.HasPrefix(s, "/"), strings.HasPrefix(s, "~/"):
		return "local path dependency: " + s
	case ghShorthandRe.MatchString(s):
		return "git dependency: " + s
	}
	return ""
}

// lockSourceReason checks a lockfile "resolved"/version value. HTTP URLs are
// not flagged: registry tarballs are URLs too.
func lockSourceReason(s string) string {
	if s == "" || strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return ""
	}
	return sourceReason(s)
}

// simpleRangeRe is a single comparator-free or ^ ~ >= = range.
var simpleRangeRe = regexp.MustCompile(`^(?:\^|~|>=|=)?\s*v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

// minVersion returns the lowest version a simple range allows:
// ^1.2.3, ~1.2.3, >=1.2.3, =1.2.3, 1.2.3 → 1.2.3; 1.2.x, ^1.2 → 1.2.0; 1 → 1.0.0.
// Anything else (unions, upper bounds, *, tags) is not simple.
func minVersion(r string) (string, bool) {
	m := simpleRangeRe.FindStringSubmatch(strings.TrimSpace(r))
	if m == nil {
		return "", false
	}
	num := func(s string) string {
		if s == "" || s == "x" || s == "X" || s == "*" {
			return "0"
		}
		return s
	}
	v := m[1] + "." + num(m[2]) + "." + num(m[3])
	if m[4] != "" {
		if num(m[2]) != m[2] || num(m[3]) != m[3] {
			return "", false // "1.x-beta" is not a version
		}
		v += m[4]
	}
	return v, true
}

// relTo returns p relative to dir when p is strictly below dir.
func relTo(dir, p string) (string, bool) {
	if dir == "." {
		return p, p != "."
	}
	rel, ok := strings.CutPrefix(p, dir+"/")
	return rel, ok
}

// matchWorkspace reports whether rel matches the workspace globs ("*" within
// a segment, "**" across segments, "!" negates; later patterns win).
func matchWorkspace(patterns []string, rel string) bool {
	in := false
	for _, p := range patterns {
		neg := strings.HasPrefix(p, "!")
		p = strings.Trim(strings.TrimPrefix(strings.TrimPrefix(p, "!"), "./"), "/")
		if p == "" {
			continue
		}
		if segMatch(strings.Split(p, "/"), strings.Split(rel, "/")) {
			in = !neg
		}
	}
	return in
}

func segMatch(pat, name []string) bool {
	if len(pat) == 0 {
		return len(name) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(name); i++ {
			if segMatch(pat[1:], name[i:]) {
				return true
			}
		}
		return false
	}
	if len(name) == 0 {
		return false
	}
	ok, _ := path.Match(pat[0], name[0])
	return ok && segMatch(pat[1:], name[1:])
}
