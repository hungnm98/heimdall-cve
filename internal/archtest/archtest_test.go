// Package archtest enforces the dependency rule of docs/ARCHITECTURE.md on
// every non-test Go file under internal/ and cmd/.
package archtest

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/hungnm98/heimdall-cve/"

// ports have adapters in sub-packages; "<port>test" sub-packages are contract kits.
var ports = map[string]bool{
	"auth": true, "vcs": true, "ecosystem": true, "runtime": true,
	"source": true, "store": true, "notify": true, "report": true, "jobs": true,
}

// foundation packages sit below the ports.
var foundation = map[string]bool{
	"model": true, "version": true, "registry": true, "plugin": true,
	"secret": true, "httpx": true, "gitx": true, "config": true,
}

// entry points other than the CLI: HTTP API, MCP server, embedded web UI.
var entries = map[string]bool{"api": true, "mcpserver": true, "webui": true}

// Layers, lowest first. A package may import its own layer or lower ones,
// never a higher one; adapters are further restricted (see violation).
type layer int

const (
	layerModel layer = iota
	layerFoundation
	layerPort // port packages and their contract kits
	layerAdapter
	layerCore
	layerService
	layerEntry
	layerApp
	layerCLI
	layerOther
)

var layerNames = []string{"model", "foundation", "port", "adapter", "core", "service", "entry", "app", "cli", "other"}

// classify returns the layer of an internal package path like "source/osv"
// and, for adapters, the adapter root ("source/osv").
func classify(pkg string) (layer, string) {
	parts := strings.Split(pkg, "/")
	switch {
	case pkg == "model":
		return layerModel, ""
	case foundation[parts[0]]:
		return layerFoundation, ""
	case ports[parts[0]] && (len(parts) == 1 || strings.HasSuffix(parts[1], "test")):
		return layerPort, ""
	case ports[parts[0]]:
		return layerAdapter, parts[0] + "/" + parts[1]
	case parts[0] == "core":
		return layerCore, ""
	case parts[0] == "service":
		return layerService, ""
	case entries[parts[0]]:
		return layerEntry, ""
	case parts[0] == "app":
		return layerApp, ""
	case parts[0] == "cli":
		return layerCLI, ""
	}
	return layerOther, ""
}

func TestDependencyRule(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		rel, _ := filepath.Rel(filepath.Join(root, "internal"), filepath.Dir(path))
		from := filepath.ToSlash(rel)
		fromLayer, fromAdapter := classify(from)
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if !strings.HasPrefix(p, module+"internal/") {
				continue
			}
			to := strings.TrimPrefix(p, module+"internal/")
			toLayer, toAdapter := classify(to)
			if msg := violation(fromLayer, fromAdapter, toLayer, toAdapter); msg != "" {
				t.Errorf("%s imports %s: %s", from, to, msg)
			}
			checked++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("no imports checked: walker is broken")
	}
}

func violation(from layer, fromAdapter string, to layer, toAdapter string) string {
	switch {
	case from == layerModel:
		return "model must not import internal packages"
	case from == layerOther || to == layerOther:
		return "package is not classified: add it to archtest"
	case to == layerAdapter:
		if from == layerApp || (from == layerAdapter && fromAdapter == toAdapter) {
			return ""
		}
		return "adapters may only be imported by internal/app (plugins.go)"
	case to > from:
		return fmt.Sprintf("%s must not import the higher %s layer", layerNames[from], layerNames[to])
	}
	return ""
}

func TestViolationRules(t *testing.T) {
	cases := []struct {
		from, to string
		bad      bool
	}{
		{"model", "version", true},
		{"source/osv", "model", false},
		{"source/osv", "httpx", false},
		{"source/osv", "source", false},
		{"source/osv", "vcs/github", true},
		{"source/osv", "source/endoflife", true},
		{"vcs/github", "vcs/github/internal/api", false},
		{"core", "source", false},
		{"core", "source/osv", true},
		{"core", "store/memstore", true},
		{"core", "service", true},
		{"service", "core", false},
		{"service", "store", false},
		{"service", "jobs", false},
		{"service", "jobs/asynq", true},
		{"service", "api", true},
		{"api", "service", false},
		{"api", "app", true},
		{"api", "store/postgres", true},
		{"mcpserver", "service", false},
		{"app", "source/osv", false},
		{"app", "api", false},
		{"cli", "app", false},
		{"cli", "api", false},
		{"cli", "source/osv", true},
		{"source", "app", true},
		{"httpx", "source", true},
		{"store/storetest", "store", false},
		{"source/osv", "core", true},
		{"jobs/asynq", "jobs", false},
		{"jobs/asynq", "service", true},
		{"mystery", "model", true},
	}
	for _, c := range cases {
		fl, fa := classify(c.from)
		tl, ta := classify(c.to)
		if got := violation(fl, fa, tl, ta) != ""; got != c.bad {
			t.Errorf("%s → %s: violation=%v, want %v", c.from, c.to, got, c.bad)
		}
	}
}
