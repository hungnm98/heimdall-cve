package rubygems

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hungnm98/heimdall-cve/internal/version"
)

// Spec sources.
const (
	srcGem    = "gem"
	srcGit    = "git"
	srcPath   = "path"
	srcPlugin = "plugin"
)

var sectionSource = map[string]string{
	"GEM":           srcGem,
	"GIT":           srcGit,
	"PATH":          srcPath,
	"PLUGIN SOURCE": srcPlugin,
}

// spec is one locked gem.
type spec struct {
	version string // platform suffix stripped
	source  string // srcGem, srcGit, srcPath, srcPlugin
	deps    []string
}

// lockfile is what Heimdall needs from a Gemfile.lock.
type lockfile struct {
	specs       map[string]*spec
	direct      map[string]bool
	platforms   []string
	rubyVersion string // "ruby 3.2.2p53" as written
	bundledWith string
}

var (
	// specRe is a 4-space spec line: "name (version[-platform])".
	specRe = regexp.MustCompile(`^([^\s(]+) \(([^)\s]+)\)$`)
	// depRe is a 6-space spec dependency or a DEPENDENCIES line:
	// "name", "name!", "name (>= 1, < 2)", "name (= 1.0)!" (Bundler writes
	// the "!" after the requirement; older files put it after the name).
	depRe = regexp.MustCompile(`^([^\s(!]+)!?(?: \([^)]*\))?!?$`)
)

// parseLockfile reads the sections of a Bundler lockfile. Unknown sections
// (CHECKSUMS, future ones) are ignored; a malformed spec or dependency line,
// or a file without any source or DEPENDENCIES section, is an error.
func parseLockfile(data []byte) (*lockfile, error) {
	lf := &lockfile{specs: map[string]*spec{}, direct: map[string]bool{}}
	section, inSpecs, known := "", false, false
	var cur *spec
	for i, raw := range strings.Split(string(data), "\n") {
		l := strings.TrimRight(raw, " \r\t")
		text := strings.TrimLeft(l, " ")
		if text == "" {
			continue
		}
		indent := len(l) - len(text)
		if indent == 0 {
			section, inSpecs, cur = text, false, nil
			if sectionSource[section] != "" || section == "DEPENDENCIES" {
				known = true
			}
			continue
		}
		bad := func() error { return fmt.Errorf("line %d: malformed %s entry %q", i+1, section, text) }
		switch section {
		case "GEM", "GIT", "PATH", "PLUGIN SOURCE":
			switch {
			case indent == 2:
				inSpecs, cur = text == "specs:", nil
			case indent == 4 && inSpecs:
				m := specRe.FindStringSubmatch(text)
				if m == nil {
					return nil, bad()
				}
				cur = lf.add(m[1], stripPlatform(m[2]), sectionSource[section])
			case indent == 6 && inSpecs:
				m := depRe.FindStringSubmatch(text)
				if m == nil || cur == nil {
					return nil, bad()
				}
				cur.deps = appendUnique(cur.deps, m[1])
			}
		case "DEPENDENCIES":
			if indent == 2 {
				m := depRe.FindStringSubmatch(text)
				if m == nil {
					return nil, bad()
				}
				lf.direct[m[1]] = true
			}
		case "PLATFORMS":
			lf.platforms = append(lf.platforms, text)
		case "RUBY VERSION":
			lf.rubyVersion = text
		case "BUNDLED WITH":
			lf.bundledWith = text
		}
	}
	if !known {
		return nil, errors.New("no GEM, GIT, PATH or DEPENDENCIES section")
	}
	return lf, nil
}

// add records a spec. A gem seen again (another platform, another source)
// stays one entry: an unresolvable source wins over GEM, otherwise the
// highest version wins; dependency lists are merged.
func (lf *lockfile) add(name, ver, source string) *spec {
	s := lf.specs[name]
	if s == nil {
		s = &spec{version: ver, source: source}
		lf.specs[name] = s
		return s
	}
	switch {
	case s.source == srcGem && source != srcGem:
		s.version, s.source = ver, source
	case s.source == source && (version.RubyGems{}).Compare(ver, s.version) > 0:
		s.version = ver
	}
	return s
}

// stripPlatform drops a platform suffix: Bundler writes "version-platform"
// and gem versions never contain "-" there ("1.16.2-x86_64-linux-musl").
func stripPlatform(v string) string {
	v, _, _ = strings.Cut(v, "-")
	return v
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
