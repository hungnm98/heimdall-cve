// Package ruby is the "ruby" runtime detector. It reports every Ruby (MRI)
// version a repo declares:
//
//   - .ruby-version: first line, "ruby-" prefix stripped (Via ".ruby-version");
//     other engines (jruby-9.4, truffleruby-23) are ignored
//   - .tool-versions "ruby" line, first version (Via ".tool-versions")
//   - Gemfile / gems.rb: ruby "3.2.2" (Via "Gemfile ruby"). Requirements
//     (~> 3.2.0), file: references (the file is detected on its own), other
//     engines (engine: "jruby") and non-literal values are ignored.
//   - Gemfile.lock / gems.locked: the RUBY VERSION section, patch level
//     dropped: "ruby 3.2.2p53" → "3.2.2" (Via "Gemfile.lock RUBY VERSION")
//   - Dockerfile*, *.Dockerfile: FROM [registry/][namespace/]ruby:<tag>, with
//     --platform flags skipped, AS names ignored and global ARG defaults
//     substituted (Via "Dockerfile FROM"). 3.2, 3.2.2-slim-bookworm,
//     3.3-alpine give 3.2 / 3.2.2 / 3.3; latest, variant-only tags (slim,
//     alpine), major-only tags (3) and digest-only references are ignored.
//   - .github/workflows/*.y*ml: ruby/setup-ruby with.ruby-version literal
//     versions (Via "ruby/setup-ruby"). Expressions (${{ ... }}), aliases
//     (head, ruby, jruby), and ".ruby-version"/".tool-versions" references
//     (read from the file, detected on its own) are ignored.
//
// Files under vendor/bundle are ignored. Files that cannot be parsed are
// logged and skipped so one broken file does not hide the others.
package ruby

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/runtime"
)

func init() { runtime.Registry.Register("ruby", New) }

// Via values.
const (
	ViaRubyVersion = ".ruby-version"
	ViaToolVersion = ".tool-versions"
	ViaGemfile     = "Gemfile ruby"
	ViaLockfile    = "Gemfile.lock RUBY VERSION"
	ViaDockerfile  = "Dockerfile FROM"
	ViaSetupRuby   = "ruby/setup-ruby"
)

// Detector implements runtime.Detector for Ruby.
type Detector struct {
	log *slog.Logger
}

var _ runtime.Detector = (*Detector)(nil)

// New builds the detector. It takes no plugin config.
func New(cfg plugin.Config, deps plugin.Deps) (runtime.Detector, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	log := deps.Logger
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Detector{log: log.With("component", "runtime", "plugin", "ruby")}, nil
}

func (*Detector) Name() string    { return "ruby" }
func (*Detector) Runtime() string { return "ruby" }

type kind int

const (
	kindNone kind = iota
	kindRubyVersion
	kindToolVersions
	kindGemfile
	kindLockfile
	kindDockerfile
	kindWorkflow
)

func kindOf(p string) kind {
	segs := strings.Split(path.Dir(p), "/")
	for i := 0; i+1 < len(segs); i++ {
		if segs[i] == "vendor" && segs[i+1] == "bundle" {
			return kindNone
		}
	}
	base := path.Base(p)
	lower := strings.ToLower(base)
	switch {
	case base == ".ruby-version":
		return kindRubyVersion
	case base == ".tool-versions":
		return kindToolVersions
	case base == "Gemfile" || base == "gems.rb":
		return kindGemfile
	case base == "Gemfile.lock" || base == "gems.locked":
		return kindLockfile
	case strings.HasPrefix(lower, "dockerfile") || strings.HasSuffix(lower, ".dockerfile"):
		return kindDockerfile
	case path.Dir(p) == ".github/workflows" && (path.Ext(p) == ".yml" || path.Ext(p) == ".yaml"):
		return kindWorkflow
	}
	return kindNone
}

// Match reports whether p may declare a Ruby version.
func (*Detector) Match(p string) bool { return kindOf(p) != kindNone }

// Detect returns every declaration, deduplicated and sorted by origin.
func (d *Detector) Detect(ctx context.Context, files model.FileSet) ([]model.Runtime, error) {
	seen := map[model.Runtime]bool{}
	var out []model.Runtime
	add := func(origin, via, v string) {
		r := model.Runtime{Name: "ruby", Version: v, Origin: origin, Via: via}
		if v != "" && !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	for p, data := range files.Files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch kindOf(p) {
		case kindRubyVersion:
			add(p, ViaRubyVersion, rubyVersionFile(data))
		case kindToolVersions:
			add(p, ViaToolVersion, toolVersions(data))
		case kindGemfile:
			add(p, ViaGemfile, gemfile(data))
		case kindLockfile:
			add(p, ViaLockfile, lockfile(data))
		case kindDockerfile:
			for _, v := range dockerfile(data) {
				add(p, ViaDockerfile, v)
			}
		case kindWorkflow:
			vs, err := workflow(data)
			if err != nil {
				d.log.Warn("skipping unparsable file", "file", p, "err", err)
				continue
			}
			for _, v := range vs {
				add(p, ViaSetupRuby, v)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Origin != b.Origin {
			return a.Origin < b.Origin
		}
		if a.Via != b.Via {
			return a.Via < b.Via
		}
		return a.Version < b.Version
	})
	return out, nil
}

// rubyVersionRe is an MRI release: 3.2, 3.2.2, 3.4.0-preview1, 3.3.0.rc1.
var rubyVersionRe = regexp.MustCompile(`^\d+\.\d+(\.\d+)?([.-]?(preview|rc)\d+)?$`)

// literal returns v without a "ruby-" prefix if it is an MRI release, else "".
func literal(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "ruby-")
	if rubyVersionRe.MatchString(v) {
		return v
	}
	return ""
}

func lines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := sc.Text()
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func rubyVersionFile(data []byte) string {
	if ls := lines(data); len(ls) > 0 {
		return literal(ls[0])
	}
	return ""
}

// toolVersions reads the first version of ruby in an asdf/mise
// .tool-versions file ("ruby 3.2.2 3.1.4": 3.2.2 is the active one).
func toolVersions(data []byte) string {
	for _, l := range lines(data) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "ruby" {
			return literal(f[1])
		}
	}
	return ""
}

// gemfileRubyRe is a `ruby "3.2.2"` statement, with optional parentheses and
// trailing options.
var gemfileRubyRe = regexp.MustCompile(`^ruby\s*\(?\s*(?:"([^"]*)"|'([^']*)')\s*(.*)$`)

// gemfile returns the version of a literal ruby statement of a Gemfile.
func gemfile(data []byte) string {
	for _, l := range lines(data) {
		m := gemfileRubyRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if opts := m[3]; strings.Contains(opts, "engine") {
			return "" // jruby, truffleruby...
		}
		return literal(m[1] + m[2])
	}
	return ""
}

var patchLevelRe = regexp.MustCompile(`p\d+$`)

// lockfile reads the RUBY VERSION section: "   ruby 3.2.2p53" → "3.2.2".
func lockfile(data []byte) string {
	in := false
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), " \r")
		if l == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			in = l == "RUBY VERSION"
			continue
		}
		if in {
			f := strings.Fields(l)
			if len(f) == 2 && f[0] == "ruby" {
				return literal(patchLevelRe.ReplaceAllString(f[1], ""))
			}
			return ""
		}
	}
	return ""
}

// dockerTagRe takes the Ruby version out of an official ruby image tag:
// "3.2.2-slim-bookworm" → "3.2.2", "3.3-alpine3.19" → "3.3".
var dockerTagRe = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?(?:-(?:preview|rc)\d+)?)(?:-[A-Za-z0-9._-]+)?$`)

// dockerfile returns the Ruby versions of every FROM ruby:<tag> stage.
func dockerfile(data []byte) []string {
	args := map[string]string{} // global ARG defaults (declared before the first FROM)
	seenFrom := false
	var out []string
	for _, l := range dockerLines(data) {
		f := strings.Fields(l)
		switch strings.ToUpper(f[0]) {
		case "ARG":
			if seenFrom {
				continue
			}
			for _, a := range f[1:] {
				if k, v, ok := strings.Cut(a, "="); ok {
					args[k] = strings.Trim(v, `"'`)
				}
			}
		case "FROM":
			seenFrom = true
			var image string
			for _, a := range f[1:] {
				if !strings.HasPrefix(a, "--") {
					image = a
					break
				}
			}
			if v := rubyImageVersion(expand(image, args)); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// dockerLines returns instructions with continuation lines joined and
// comments dropped.
func dockerLines(data []byte) []string {
	var out []string
	var cur strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.HasSuffix(l, `\`) {
			cur.WriteString(strings.TrimSuffix(l, `\`) + " ")
			continue
		}
		cur.WriteString(l)
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	return out
}

// expand substitutes $VAR, ${VAR} and ${VAR:-default}; "" if a variable is unknown.
func expand(s string, args map[string]string) string {
	unknown := false
	r := os.Expand(s, func(k string) string {
		k, def, hasDef := strings.Cut(k, ":-")
		if v, ok := args[k]; ok && v != "" {
			return v
		}
		if hasDef {
			return def
		}
		unknown = true
		return ""
	})
	if unknown {
		return ""
	}
	return r
}

// rubyImageVersion returns the Ruby version of a ruby image reference, or "".
func rubyImageVersion(ref string) string {
	ref, _, _ = strings.Cut(ref, "@") // drop digest; a digest alone has no tag
	repo, tag := ref, ""
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		repo, tag = ref[:i], ref[i+1:]
	}
	if path.Base(repo) != "ruby" {
		return ""
	}
	if m := dockerTagRe.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	return ""
}

// workflow returns literal ruby-version values of ruby/setup-ruby steps.
func workflow(data []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	var out []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			if uses := mapValue(n, "uses"); uses != nil && uses.Kind == yaml.ScalarNode {
				action, _, _ := strings.Cut(strings.TrimSpace(uses.Value), "@")
				if action == "ruby/setup-ruby" {
					if with := mapValue(n, "with"); with != nil {
						if rv := mapValue(with, "ruby-version"); rv != nil && rv.Kind == yaml.ScalarNode {
							if v := literal(rv.Value); v != "" {
								out = append(out, v)
							}
						}
					}
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&doc)
	return out, nil
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
