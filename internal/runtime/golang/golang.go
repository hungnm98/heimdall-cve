// Package golang is the "go" runtime detector. It reports every Go version a
// repo declares:
//
//   - go.mod / go.work: the go directive (Via "go directive") and the
//     toolchain directive (Via "toolchain", without the "go" prefix)
//   - .go-version (Via ".go-version")
//   - .tool-versions "golang" or "go" lines, first version (Via ".tool-versions")
//   - Dockerfile*, *.Dockerfile: FROM [registry/][namespace/]golang:<tag>, with
//     global ARG defaults substituted (Via "Dockerfile FROM"). Tags like 1.22,
//     1.22.5-alpine, 1.22-bookworm give 1.22 / 1.22.5 / 1.22; latest, bare
//     variants (alpine) and digest-only references are ignored.
//   - .github/workflows/*.y*ml: actions/setup-go with.go-version literal
//     versions (Via "actions/setup-go"); "1.22.x" gives "1.22". Expressions
//     (${{ ... }}), aliases (stable) and ranges are ignored, as is
//     go-version-file (that file is detected on its own).
//
// Files that cannot be parsed are logged and skipped so one broken file does
// not hide the others.
package golang

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
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/runtime"
)

func init() { runtime.Registry.Register("go", New) }

// Via values.
const (
	ViaGoDirective = "go directive"
	ViaToolchain   = "toolchain"
	ViaGoVersion   = ".go-version"
	ViaToolVersion = ".tool-versions"
	ViaDockerfile  = "Dockerfile FROM"
	ViaSetupGo     = "actions/setup-go"
)

// Detector implements runtime.Detector for Go.
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
	return &Detector{log: log.With("component", "runtime", "plugin", "go")}, nil
}

func (*Detector) Name() string    { return "go" }
func (*Detector) Runtime() string { return "go" }

type kind int

const (
	kindNone kind = iota
	kindGoMod
	kindGoWork
	kindGoVersion
	kindToolVersions
	kindDockerfile
	kindWorkflow
)

func kindOf(p string) kind {
	base := path.Base(p)
	lower := strings.ToLower(base)
	switch {
	case base == "go.mod":
		return kindGoMod
	case base == "go.work":
		return kindGoWork
	case base == ".go-version":
		return kindGoVersion
	case base == ".tool-versions":
		return kindToolVersions
	case strings.HasPrefix(lower, "dockerfile") || strings.HasSuffix(lower, ".dockerfile"):
		return kindDockerfile
	case path.Dir(p) == ".github/workflows" && (path.Ext(p) == ".yml" || path.Ext(p) == ".yaml"):
		return kindWorkflow
	}
	return kindNone
}

// Match reports whether p may declare a Go version.
func (*Detector) Match(p string) bool { return kindOf(p) != kindNone }

// Detect returns every declaration, deduplicated and sorted by origin.
func (d *Detector) Detect(ctx context.Context, files model.FileSet) ([]model.Runtime, error) {
	seen := map[model.Runtime]bool{}
	var out []model.Runtime
	add := func(origin, via, v string) {
		r := model.Runtime{Name: "go", Version: v, Origin: origin, Via: via}
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
		case kindGoMod:
			f, err := modfile.Parse(p, data, nil)
			if err != nil {
				// ParseLax tolerates errors elsewhere in the file but drops
				// the toolchain directive.
				f, err = modfile.ParseLax(p, data, nil)
			}
			if err != nil {
				d.skip(p, err)
				continue
			}
			if f.Go != nil {
				add(p, ViaGoDirective, f.Go.Version)
			}
			if f.Toolchain != nil {
				add(p, ViaToolchain, toolchainVersion(f.Toolchain.Name))
			}
		case kindGoWork:
			f, err := modfile.ParseWork(p, data, nil)
			if err != nil {
				d.skip(p, err)
				continue
			}
			if f.Go != nil {
				add(p, ViaGoDirective, f.Go.Version)
			}
			if f.Toolchain != nil {
				add(p, ViaToolchain, toolchainVersion(f.Toolchain.Name))
			}
		case kindGoVersion:
			add(p, ViaGoVersion, goVersionFile(data))
		case kindToolVersions:
			add(p, ViaToolVersion, toolVersions(data))
		case kindDockerfile:
			for _, v := range dockerfile(data) {
				add(p, ViaDockerfile, v)
			}
		case kindWorkflow:
			vs, err := workflow(data)
			if err != nil {
				d.skip(p, err)
				continue
			}
			for _, v := range vs {
				add(p, ViaSetupGo, v)
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

func (d *Detector) skip(p string, err error) {
	d.log.Warn("skipping unparsable file", "file", p, "err", err)
}

// goVersionRe is a Go release: 1.22, 1.22.5, 1.22rc1, 1.21beta2.
var goVersionRe = regexp.MustCompile(`^\d+\.\d+(\.\d+)?((rc|beta)\d+)?$`)

// literal returns v without a "go"/"v" prefix if it is a Go release, else "".
func literal(v string) string {
	v = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(v), "go"), "v")
	if goVersionRe.MatchString(v) {
		return v
	}
	return ""
}

// toolchainVersion maps "go1.22.5" (or "go1.22.5-custom") to "1.22.5".
func toolchainVersion(name string) string {
	if !strings.HasPrefix(name, "go") {
		return "" // "default", "local"
	}
	v, _, _ := strings.Cut(name, "-")
	return literal(v)
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

func goVersionFile(data []byte) string {
	if ls := lines(data); len(ls) > 0 {
		return literal(ls[0])
	}
	return ""
}

// toolVersions reads the first version of the golang/go tool in an asdf/mise
// .tool-versions file ("golang 1.22.5 1.21.0": 1.22.5 is the active one).
func toolVersions(data []byte) string {
	for _, l := range lines(data) {
		f := strings.Fields(l)
		if len(f) >= 2 && (f[0] == "golang" || f[0] == "go") {
			return literal(f[1])
		}
	}
	return ""
}

// dockerTagRe takes the Go version out of an official golang image tag:
// "1.22.5-alpine3.20" → "1.22.5", "1.22-bookworm" → "1.22".
var dockerTagRe = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?(?:(?:rc|beta)\d+)?)(?:-[A-Za-z0-9._-]+)?$`)

// dockerfile returns the Go versions of every FROM golang:<tag> stage.
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
			if v := golangImageVersion(expand(image, args)); v != "" {
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

// golangImageVersion returns the Go version of a golang image reference, or "".
func golangImageVersion(ref string) string {
	ref, _, _ = strings.Cut(ref, "@") // drop digest; a digest alone has no tag
	repo, tag := ref, ""
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		repo, tag = ref[:i], ref[i+1:]
	}
	if path.Base(repo) != "golang" {
		return ""
	}
	if m := dockerTagRe.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	return ""
}

// setupGoVersionRe accepts literal setup-go versions: 1.22, 1.22.5, v1.22, 1.22.x.
var setupGoVersionRe = regexp.MustCompile(`^v?(\d+\.\d+(?:\.\d+)?(?:(?:rc|beta)\d+)?)(?:\.x)?$`)

// workflow returns literal go-version values of actions/setup-go steps.
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
				if action == "actions/setup-go" {
					if with := mapValue(n, "with"); with != nil {
						if gv := mapValue(with, "go-version"); gv != nil && gv.Kind == yaml.ScalarNode {
							if m := setupGoVersionRe.FindStringSubmatch(strings.TrimSpace(gv.Value)); m != nil {
								out = append(out, m[1])
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

// Cycle returns the major.minor release cycle of a Go version
// ("1.22.5" → "1.22", "1.23rc1" → "1.23"), or "" if v is not a Go version.
func Cycle(v string) string { return cycleRe.FindString(literal(v)) }

var cycleRe = regexp.MustCompile(`^\d+\.\d+`)

// CycleGroup is the declarations naming one release cycle.
type CycleGroup struct {
	Cycle    string
	Runtimes []model.Runtime
}

// Inconsistencies groups Go declarations by release cycle and returns the
// groups (oldest cycle first) when they name more than one cycle; nil when
// consistent.
//
// The go directive is left out: it is the minimum language version, not the
// toolchain that builds the code, so "go 1.21" next to "FROM golang:1.22" is
// normal. Declarations of other runtimes and unparsable versions are ignored.
func Inconsistencies(rts []model.Runtime) []CycleGroup {
	by := map[string][]model.Runtime{}
	for _, r := range rts {
		if r.Name != "go" || r.Via == ViaGoDirective {
			continue
		}
		if c := Cycle(r.Version); c != "" {
			by[c] = append(by[c], r)
		}
	}
	if len(by) < 2 {
		return nil
	}
	out := make([]CycleGroup, 0, len(by))
	for c, rs := range by {
		out = append(out, CycleGroup{Cycle: c, Runtimes: rs})
	}
	sort.Slice(out, func(i, j int) bool {
		return semver.Compare("v"+out[i].Cycle, "v"+out[j].Cycle) < 0
	})
	return out
}
