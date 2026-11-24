package golang

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/runtime/runtimetest"
)

func rt(version, origin, via string) model.Runtime {
	return model.Runtime{Name: "go", Version: version, Origin: origin, Via: via}
}

func newDetector(t *testing.T) *Detector {
	t.Helper()
	d, err := New(nil, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*Detector)
}

func TestMatch(t *testing.T) {
	d := newDetector(t)
	for _, p := range []string{
		"go.mod", "svc/go.mod", "go.work", ".go-version", "svc/.tool-versions",
		"Dockerfile", "build/Dockerfile.prod", "Dockerfile-dev", "api.Dockerfile",
		".github/workflows/ci.yml", ".github/workflows/release.yaml",
	} {
		if !d.Match(p) {
			t.Errorf("Match(%q) = false", p)
		}
	}
	for _, p := range []string{
		"go.sum", "main.go", "README.md", ".github/workflows/sub/ci.yml",
		".github/dependabot.yml", "svc/.github/workflows/ci.yml", "docker-compose.yml",
	} {
		if d.Match(p) {
			t.Errorf("Match(%q) = true", p)
		}
	}
}

func TestContract(t *testing.T) {
	cases := []runtimetest.Case{
		{
			Name: "go.mod go and toolchain",
			Files: map[string]string{
				"go.mod":     "module example.com/a\n\ngo 1.22.3\n\ntoolchain go1.22.5\n\nrequire example.com/b v1.0.0\n",
				"svc/go.mod": "module example.com/svc\n\ngo 1.21\n",
				"lib/go.mod": "module example.com/lib\n", // no go directive
			},
			Want: []model.Runtime{
				rt("1.22.3", "go.mod", ViaGoDirective),
				rt("1.22.5", "go.mod", ViaToolchain),
				rt("1.21", "svc/go.mod", ViaGoDirective),
			},
		},
		{
			Name: "go.work",
			Files: map[string]string{
				"go.work": "go 1.23.0\n\ntoolchain go1.23.2\n\nuse ./a\n",
			},
			Want: []model.Runtime{
				rt("1.23.0", "go.work", ViaGoDirective),
				rt("1.23.2", "go.work", ViaToolchain),
			},
		},
		{
			Name: ".go-version",
			Files: map[string]string{
				".go-version":     "1.22.5\n",
				"svc/.go-version": "# pinned\n\ngo1.21.13\n",
				"bad/.go-version": "latest\n",
			},
			Want: []model.Runtime{
				rt("1.22.5", ".go-version", ViaGoVersion),
				rt("1.21.13", "svc/.go-version", ViaGoVersion),
			},
		},
		{
			Name: ".tool-versions",
			Files: map[string]string{
				".tool-versions":       "nodejs 20.11.0\ngolang 1.22.5 1.21.0 # first is active\nruby 3.3.0\n",
				"svc/.tool-versions":   "go 1.23.1\n",
				"other/.tool-versions": "nodejs 20.11.0\n# golang 1.20\n",
				"sys/.tool-versions":   "golang system\n",
			},
			Want: []model.Runtime{
				rt("1.22.5", ".tool-versions", ViaToolVersion),
				rt("1.23.1", "svc/.tool-versions", ViaToolVersion),
			},
		},
		{
			Name: "Dockerfile tags",
			Files: map[string]string{
				"Dockerfile": `# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.22.5-alpine3.20 AS build
WORKDIR /src
RUN go build ./...
FROM gcr.io/distroless/static-debian12
COPY --from=build /out /app
`,
				"build/Dockerfile.ci": `FROM golang:1.22-bookworm AS a
FROM docker.io/library/golang:1.23 as b
FROM golang:1.21rc2-bullseye
FROM golang:latest
FROM golang:alpine
FROM golang
FROM golang@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
FROM golang:1-alpine
FROM mygolang:1.20
FROM node:20-alpine
`,
				"api.Dockerfile": `FROM golang:1.22.4@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
FROM golang:1.22.4 AS again
`,
			},
			Want: []model.Runtime{
				rt("1.22.5", "Dockerfile", ViaDockerfile),
				rt("1.22", "build/Dockerfile.ci", ViaDockerfile),
				rt("1.23", "build/Dockerfile.ci", ViaDockerfile),
				rt("1.21rc2", "build/Dockerfile.ci", ViaDockerfile),
				rt("1.22.4", "api.Dockerfile", ViaDockerfile), // deduplicated
			},
		},
		{
			Name: "Dockerfile ARG substitution",
			Files: map[string]string{
				"Dockerfile": `ARG GO_VERSION=1.22.6
ARG VARIANT="alpine"
FROM golang:${GO_VERSION}-${VARIANT} AS build
FROM golang:${UNKNOWN}
FROM golang:${GO_MINOR:-1.21}
ARG LATE=1.20
FROM golang:$LATE
`,
				"Dockerfile.multiline": "FROM \\\n  golang:1.19-alpine \\\n  AS build\n",
			},
			Want: []model.Runtime{
				rt("1.22.6", "Dockerfile", ViaDockerfile),
				rt("1.21", "Dockerfile", ViaDockerfile),
				rt("1.19", "Dockerfile.multiline", ViaDockerfile),
			},
		},
		{
			Name: "workflow setup-go",
			Files: map[string]string{
				".github/workflows/ci.yml": `name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        go: ['1.21', '1.22']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: ${{ matrix.go }}
      - name: pinned
        uses: actions/setup-go@v5
        with:
          go-version: 1.20  # YAML float, must stay "1.20"
      - uses: actions/setup-go@0c52d547c9bc32b1aa3301fd7a9cb496313a4491
        with:
          go-version: '1.22.x'
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - uses: actions/setup-go@v5
        with:
          go-version: stable
      - uses: actions/setup-go@v5
        with:
          go-version: '>=1.21.0'
      - uses: actions/setup-go@v4
        with:
          go-version: "1.23.2"
          cache: true
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with:
          go-version: '1.19'
      - uses: golangci/golangci-lint-action@v6
`,
				".github/workflows/release.yaml": "jobs:\n  r:\n    steps:\n      - {uses: actions/setup-go@v5, with: {go-version: v1.22.1}}\n",
				".github/workflows/broken.yml":   "jobs: [\n",
			},
			Want: []model.Runtime{
				rt("1.20", ".github/workflows/ci.yml", ViaSetupGo),
				rt("1.22", ".github/workflows/ci.yml", ViaSetupGo),
				rt("1.23.2", ".github/workflows/ci.yml", ViaSetupGo),
				rt("1.22.1", ".github/workflows/release.yaml", ViaSetupGo),
			},
		},
		{
			Name: "unmatched and broken files are ignored",
			Files: map[string]string{
				"README.md": "FROM golang:1.22\n",
				"go.mod":    "this is not a go.mod {{{\n",
			},
		},
	}
	runtimetest.Run(t, newDetector(t), cases)
}

func TestCycle(t *testing.T) {
	for in, want := range map[string]string{
		"1.22.5": "1.22", "1.22": "1.22", "1.23rc1": "1.23", "go1.21.0": "1.21", "latest": "", "": "",
	} {
		if got := Cycle(in); got != want {
			t.Errorf("Cycle(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestInconsistencies(t *testing.T) {
	consistent := []model.Runtime{
		rt("1.21", "go.mod", ViaGoDirective), // minimum version: ignored
		rt("1.22.5", "go.mod", ViaToolchain),
		rt("1.22", "Dockerfile", ViaDockerfile),
		rt("1.22", ".github/workflows/ci.yml", ViaSetupGo),
		{Name: "node", Version: "20", Origin: ".nvmrc", Via: ".nvmrc"},
	}
	if got := Inconsistencies(consistent); got != nil {
		t.Errorf("consistent: got %+v", got)
	}

	mixed := append(consistent,
		rt("1.9.2", ".go-version", ViaGoVersion),
		rt("1.23.1", ".tool-versions", ViaToolVersion),
	)
	got := Inconsistencies(mixed)
	var cycles []string
	for _, g := range got {
		cycles = append(cycles, g.Cycle)
	}
	if len(got) != 3 || cycles[0] != "1.9" || cycles[1] != "1.22" || cycles[2] != "1.23" {
		t.Fatalf("cycles = %v, want [1.9 1.22 1.23]", cycles)
	}
	if len(got[1].Runtimes) != 3 {
		t.Errorf("1.22 group = %+v, want 3 declarations", got[1].Runtimes)
	}
}
