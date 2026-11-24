// Package node is the "node" runtime detector. It reports every Node.js
// version a repo declares (files under node_modules/ are ignored):
//
//   - .nvmrc (Via ".nvmrc") and .node-version (Via ".node-version"): first
//     line, "v" prefix stripped; "20", "20.11", "20.11.1" and "20.x" (→ "20")
//     are kept. Aliases (lts/*, lts/iron, node, stable, latest, system) and
//     ranges are ignored.
//   - .tool-versions "nodejs" or "node" lines, first version (Via ".tool-versions").
//   - package.json engines.node, kept literally as a range (Via "engines.node"),
//     and volta.node (Via "volta.node").
//   - Dockerfile*, *.Dockerfile: FROM [registry/][namespace/]node:<tag>, with
//     global ARG defaults substituted (Via "Dockerfile FROM"). Tags like 20,
//     20.11.1-alpine3.19, 20-bookworm-slim give 20 / 20.11.1 / 20; latest,
//     lts, current, codenames (iron-alpine), bare variants (alpine) and
//     digest-only references are ignored.
//   - .github/workflows/*.y*ml: actions/setup-node with.node-version literal
//     versions (Via "actions/setup-node"); "20.x" gives "20". Expressions
//     (${{ ... }}), aliases (lts/*) and ranges are ignored, as is
//     node-version-file (that file is detected on its own).
//
// Files that cannot be parsed are logged and skipped so one broken file does
// not hide the others.
package node

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/runtime"
)

func init() { runtime.Registry.Register("node", New) }

// Via values.
const (
	ViaNvmrc       = ".nvmrc"
	ViaNodeVersion = ".node-version"
	ViaToolVersion = ".tool-versions"
	ViaEngines     = "engines.node"
	ViaVolta       = "volta.node"
	ViaDockerfile  = "Dockerfile FROM"
	ViaSetupNode   = "actions/setup-node"
)

// Detector implements runtime.Detector for Node.js.
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
	return &Detector{log: log.With("component", "runtime", "plugin", "node")}, nil
}

func (*Detector) Name() string    { return "node" }
func (*Detector) Runtime() string { return "node" }

type kind int

const (
	kindNone kind = iota
	kindNvmrc
	kindNodeVersion
	kindToolVersions
	kindPackageJSON
	kindDockerfile
	kindWorkflow
)

func kindOf(p string) kind {
	if slices.Contains(strings.Split(path.Dir(p), "/"), "node_modules") {
		return kindNone
	}
	base := path.Base(p)
	lower := strings.ToLower(base)
	switch {
	case base == ".nvmrc":
		return kindNvmrc
	case base == ".node-version":
		return kindNodeVersion
	case base == ".tool-versions":
		return kindToolVersions
	case base == "package.json":
		return kindPackageJSON
	case strings.HasPrefix(lower, "dockerfile") || strings.HasSuffix(lower, ".dockerfile"):
		return kindDockerfile
	case path.Dir(p) == ".github/workflows" && (path.Ext(p) == ".yml" || path.Ext(p) == ".yaml"):
		return kindWorkflow
	}
	return kindNone
}

// Match reports whether p may declare a Node.js version.
func (*Detector) Match(p string) bool { return kindOf(p) != kindNone }

// Detect returns every declaration, deduplicated and sorted by origin.
func (d *Detector) Detect(ctx context.Context, files model.FileSet) ([]model.Runtime, error) {
	seen := map[model.Runtime]bool{}
	var out []model.Runtime
	add := func(origin, via, v string) {
		r := model.Runtime{Name: "node", Version: v, Origin: origin, Via: via}
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
		case kindNvmrc:
			add(p, ViaNvmrc, versionFile(data))
		case kindNodeVersion:
			add(p, ViaNodeVersion, versionFile(data))
		case kindToolVersions:
			add(p, ViaToolVersion, toolVersions(data))
		case kindPackageJSON:
			engines, volta, err := packageJSON(data)
			if err != nil {
				d.skip(p, err)
				continue
			}
			add(p, ViaEngines, engines)
			add(p, ViaVolta, volta)
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
				add(p, ViaSetupNode, v)
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

// nodeVersionRe is a literal Node.js version: 20, 20.11, 20.11.1, 20.x, 20.11.x.
var nodeVersionRe = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,2})(?:\.[xX*])?$`)

// literal returns v without a "v" prefix or ".x" suffix if it is a literal
// Node.js version, else "".
func literal(v string) string {
	if m := nodeVersionRe.FindStringSubmatch(strings.TrimSpace(v)); m != nil {
		return m[1]
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

// versionFile reads .nvmrc / .node-version: the first non-comment line.
func versionFile(data []byte) string {
	if ls := lines(data); len(ls) > 0 {
		return literal(ls[0])
	}
	return ""
}

// toolVersions reads the first version of the nodejs/node tool in an
// asdf/mise .tool-versions file.
func toolVersions(data []byte) string {
	for _, l := range lines(data) {
		f := strings.Fields(l)
		if len(f) >= 2 && (f[0] == "nodejs" || f[0] == "node") {
			return literal(f[1])
		}
	}
	return ""
}

// packageJSON returns engines.node (kept literally, it is usually a range)
// and volta.node.
func packageJSON(data []byte) (engines, volta string, err error) {
	var pj struct {
		Engines json.RawMessage `json:"engines"`
		Volta   json.RawMessage `json:"volta"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return "", "", err
	}
	return stringField(pj.Engines, "node"), literal(stringField(pj.Volta, "node")), nil
}

// stringField returns obj[key] when obj is a JSON object and the value a
// string; "" otherwise (some packages write "engines": ["node >= 0.4"]).
func stringField(obj json.RawMessage, key string) string {
	var m map[string]json.RawMessage
	if len(obj) == 0 || json.Unmarshal(obj, &m) != nil {
		return ""
	}
	var s string
	if json.Unmarshal(m[key], &s) != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// dockerTagRe takes the Node.js version out of an official node image tag:
// "20.11.1-alpine3.19" → "20.11.1", "20-bookworm-slim" → "20".
var dockerTagRe = regexp.MustCompile(`^(\d+(?:\.\d+){0,2})(?:-[A-Za-z0-9._-]+)?$`)

// dockerfile returns the Node.js versions of every FROM node:<tag> stage.
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
			if v := nodeImageVersion(expand(image, args)); v != "" {
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

// nodeImageVersion returns the Node.js version of a node image reference, or "".
func nodeImageVersion(ref string) string {
	ref, _, _ = strings.Cut(ref, "@") // drop digest; a digest alone has no tag
	repo, tag := ref, ""
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		repo, tag = ref[:i], ref[i+1:]
	}
	if path.Base(repo) != "node" {
		return ""
	}
	if m := dockerTagRe.FindStringSubmatch(tag); m != nil {
		return m[1]
	}
	return ""
}

// workflow returns literal node-version values of actions/setup-node steps.
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
				if action == "actions/setup-node" {
					if with := mapValue(n, "with"); with != nil {
						if nv := mapValue(with, "node-version"); nv != nil && nv.Kind == yaml.ScalarNode {
							if v := literal(nv.Value); v != "" {
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
