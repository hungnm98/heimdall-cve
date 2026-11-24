package npm

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// isBerry reports whether a yarn.lock is Yarn 2+ (YAML with __metadata).
func isBerry(data []byte) bool { return berryRe.Match(data) }

var berryRe = regexp.MustCompile(`(?m)^"?__metadata"?:`)

// yarnEntry is one block of a yarn v1 lockfile.
type yarnEntry struct {
	specs    []string
	version  string
	resolved string
	deps     map[string]string
}

// parseYarnV1 reads the custom yarn v1 format:
//
//	"@scope/a@^1.0.0", "@scope/a@^1.1.0":
//	  version "1.2.0"
//	  resolved "https://registry.yarnpkg.com/..."
//	  dependencies:
//	    b "^2.0.0"
func parseYarnV1(data []byte, decls []decl) (*lockData, error) {
	var entries []*yarnEntry
	var cur *yarnEntry
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimRight(sc.Text(), " \t\r")
		trimmed := strings.TrimLeft(raw, " ")
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(trimmed)
		switch {
		case indent == 0:
			if !strings.HasSuffix(trimmed, ":") {
				return nil, fmt.Errorf("line %d: expected an entry header", lineNo)
			}
			cur = &yarnEntry{deps: map[string]string{}}
			for _, s := range strings.Split(strings.TrimSuffix(trimmed, ":"), ",") {
				if s = unquote(strings.TrimSpace(s)); s != "" {
					cur.specs = append(cur.specs, s)
				}
			}
			entries = append(entries, cur)
			section = ""
		case cur == nil:
			return nil, fmt.Errorf("line %d: field outside an entry", lineNo)
		case indent <= 2:
			k, v := yarnKV(trimmed)
			section = ""
			switch {
			case v == "" && strings.HasSuffix(k, ":"):
				section = strings.TrimSuffix(k, ":")
			case k == "version":
				cur.version = v
			case k == "resolved":
				cur.resolved = v
			}
		default:
			if section == "dependencies" || section == "optionalDependencies" {
				k, v := yarnKV(trimmed)
				cur.deps[k] = v
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	ld := newLockData()
	bySpec := map[string]string{}
	for _, e := range entries {
		if len(e.specs) == 0 {
			continue
		}
		id := e.specs[0]
		for _, s := range e.specs {
			bySpec[s] = id
		}
	}
	for _, e := range entries {
		if len(e.specs) == 0 {
			continue
		}
		name, rng := splitSpec(e.specs[0])
		nd := &node{name: name, version: e.version}
		if real, r, ok := alias(rng); ok {
			name, rng = real, r
			nd.name = real
		}
		if reason := sourceReason(rng); reason != "" {
			nd.unresolvable = reason
		} else {
			nd.unresolvable = lockSourceReason(e.resolved)
		}
		for _, dn := range sortedKeys(e.deps) {
			if id, ok := bySpec[dn+"@"+e.deps[dn]]; ok && id != e.specs[0] {
				nd.edges = append(nd.edges, id)
			}
		}
		ld.nodes[e.specs[0]] = nd
	}
	for _, d := range decls {
		if id, ok := bySpec[d.key+"@"+d.raw]; ok {
			ld.roots = append(ld.roots, rootRef{id: id, key: d.key, scope: d.scope})
		}
	}
	return ld, nil
}

// yarnKV splits `key value` / `"key" "value"` / `key:` lines.
func yarnKV(s string) (string, string) {
	var k, rest string
	if strings.HasPrefix(s, `"`) {
		if end := strings.Index(s[1:], `"`); end >= 0 {
			k, rest = s[1:end+1], s[end+2:]
			if strings.HasPrefix(rest, ":") { // "key":
				k, rest = k+":", rest[1:]
			}
		} else {
			k = s
		}
	} else if i := strings.IndexAny(s, " \t"); i >= 0 {
		k, rest = s[:i], s[i+1:]
	} else {
		k = s
	}
	return k, unquote(strings.TrimSpace(rest))
}

func unquote(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		if u, err := strconv.Unquote(s); err == nil {
			return u
		}
		return s[1 : len(s)-1]
	}
	return s
}

// berryEntry is one entry of a Yarn 2+ lockfile.
type berryEntry struct {
	Version              string            `yaml:"version"`
	Resolution           string            `yaml:"resolution"`
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

var protocolRe = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:`)

// parseBerry reads a Yarn 2+ lockfile. Keys are comma-joined descriptors
// ("lodash@npm:^4.17.0, lodash@npm:^4.17.21"); resolutions are
// "name@protocol:reference". Workspace entries ("app@workspace:.") are the
// project and its members: their dependencies are the direct ones.
func parseBerry(data []byte) (*lockData, error) {
	var raw map[string]yaml.Node
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	ld := newLockData()
	byDesc := map[string]string{}
	entries := map[string]*berryEntry{}
	keys := make([]string, 0, len(raw))
	for k := range raw {
		if k == "__metadata" {
			continue
		}
		n := raw[k]
		var e berryEntry
		if err := n.Decode(&e); err != nil {
			return nil, fmt.Errorf("entry %q: %w", k, err)
		}
		entries[k] = &e
		keys = append(keys, k)
		for _, d := range strings.Split(k, ",") {
			byDesc[strings.TrimSpace(d)] = k
		}
	}
	sort.Strings(keys)
	lookup := func(name, rng string) string {
		if id, ok := byDesc[name+"@"+rng]; ok {
			return id
		}
		if !protocolRe.MatchString(rng) {
			return byDesc[name+"@npm:"+rng]
		}
		return ""
	}
	for _, k := range keys {
		e := entries[k]
		res := e.Resolution
		if res == "" {
			res = strings.TrimSpace(strings.Split(k, ",")[0])
		}
		name, ref := splitSpec(res)
		proto := ""
		if m := protocolRe.FindString(ref); m != "" {
			proto = strings.TrimSuffix(m, ":")
		}
		nd := &node{name: name, version: e.Version}
		var edges []string
		for _, deps := range []map[string]string{e.Dependencies, e.OptionalDependencies} {
			for _, dn := range sortedKeys(deps) {
				if id := lookup(dn, deps[dn]); id != "" && id != k {
					edges = append(edges, id)
					if proto == "workspace" {
						ld.roots = append(ld.roots, rootRef{id: id, key: dn})
					}
				}
			}
		}
		nd.edges = edges
		switch proto {
		case "npm", "patch", "virtual":
		case "workspace":
			nd.skip = true
			if dir := strings.TrimPrefix(ref, "workspace:"); dir != "." {
				ld.members = append(ld.members, dir)
			}
		default:
			nd.unresolvable = berryReason(proto, ref)
		}
		ld.nodes[k] = nd
	}
	return ld, nil
}

func berryReason(proto, ref string) string {
	ref, _, _ = strings.Cut(ref, "::")
	switch proto {
	case "file", "link", "portal", "exec":
		return sourceReason(ref)
	case "git", "git+ssh", "git+https", "github":
		return "git dependency: " + ref
	case "http", "https":
		if strings.Contains(ref, ".git#") || strings.Contains(ref, "#commit=") {
			return "git dependency: " + ref
		}
		return "tarball URL dependency: " + ref
	}
	return "unsupported source: " + ref
}
