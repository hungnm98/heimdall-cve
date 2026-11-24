package node

import (
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/runtime/runtimetest"
)

func rt(version, origin, via string) model.Runtime {
	return model.Runtime{Name: "node", Version: version, Origin: origin, Via: via}
}

func newDetector(t *testing.T) *Detector {
	t.Helper()
	d, err := New(nil, plugin.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	return d.(*Detector)
}

func TestNewRejectsUnknownConfig(t *testing.T) {
	if _, err := New(plugin.Config{"unknown": 1}, plugin.Deps{}); err == nil {
		t.Error("unknown config key: want error")
	}
}

func TestMatch(t *testing.T) {
	d := newDetector(t)
	for _, p := range []string{
		".nvmrc", "web/.nvmrc", ".node-version", "svc/.tool-versions", "package.json", "apps/api/package.json",
		"Dockerfile", "build/Dockerfile.prod", "Dockerfile-dev", "web.Dockerfile",
		".github/workflows/ci.yml", ".github/workflows/release.yaml",
	} {
		if !d.Match(p) {
			t.Errorf("Match(%q) = false", p)
		}
	}
	for _, p := range []string{
		"package-lock.json", "index.js", "README.md", ".github/workflows/sub/ci.yml",
		"node_modules/x/package.json", "node_modules/x/.nvmrc", "a/node_modules/b/Dockerfile",
		"svc/.github/workflows/ci.yml", "docker-compose.yml",
	} {
		if d.Match(p) {
			t.Errorf("Match(%q) = true", p)
		}
	}
}

func TestContract(t *testing.T) {
	cases := []runtimetest.Case{
		{
			Name: ".nvmrc",
			Files: map[string]string{
				".nvmrc":                "v20.11.1\n",
				"web/.nvmrc":            "# pinned for CI\n18\n",
				"api/.nvmrc":            "20.x\n",
				"lts/.nvmrc":            "lts/*\n",
				"iron/.nvmrc":           "lts/iron\n",
				"node/.nvmrc":           "node\n",
				"range/.nvmrc":          ">=18\n",
				"empty/.nvmrc":          "\n",
				"node_modules/x/.nvmrc": "16\n",
			},
			Want: []model.Runtime{
				rt("20.11.1", ".nvmrc", ViaNvmrc),
				rt("20", "api/.nvmrc", ViaNvmrc),
				rt("18", "web/.nvmrc", ViaNvmrc),
			},
		},
		{
			Name: ".node-version",
			Files: map[string]string{
				".node-version":     "20.10.0\n",
				"svc/.node-version": "v18.19\n",
				"bad/.node-version": "latest\n",
			},
			Want: []model.Runtime{
				rt("20.10.0", ".node-version", ViaNodeVersion),
				rt("18.19", "svc/.node-version", ViaNodeVersion),
			},
		},
		{
			Name: ".tool-versions",
			Files: map[string]string{
				".tool-versions":       "golang 1.22.5\nnodejs 20.11.0 18.19.0 # first is active\nruby 3.3.0\n",
				"svc/.tool-versions":   "node 21.6.1\n",
				"other/.tool-versions": "golang 1.22.5\n# nodejs 16.0.0\n",
				"sys/.tool-versions":   "nodejs system\n",
			},
			Want: []model.Runtime{
				rt("20.11.0", ".tool-versions", ViaToolVersion),
				rt("21.6.1", "svc/.tool-versions", ViaToolVersion),
			},
		},
		{
			Name: "package.json engines and volta",
			Files: map[string]string{
				"package.json":                `{"name": "app", "engines": {"node": ">=18.17.0 <21", "npm": ">=9"}, "volta": {"node": "20.11.1", "yarn": "1.22.19"}}`,
				"apps/web/package.json":       `{"engines": {"node": "^20"}}`,
				"apps/cli/package.json":       `{"volta": {"node": "v18.19.0"}}`,
				"old/package.json":            `{"engines": ["node >= 0.4"]}`,
				"none/package.json":           `{"name": "no-engines", "dependencies": {"x": "1"}}`,
				"bad/package.json":            `{"engines": `,
				"node_modules/x/package.json": `{"engines": {"node": ">=4"}}`,
			},
			Want: []model.Runtime{
				rt(">=18.17.0 <21", "package.json", ViaEngines),
				rt("20.11.1", "package.json", ViaVolta),
				rt("^20", "apps/web/package.json", ViaEngines),
				rt("18.19.0", "apps/cli/package.json", ViaVolta),
			},
		},
		{
			Name: "Dockerfile tags",
			Files: map[string]string{
				"Dockerfile": `# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM node:20.11.1-alpine3.19 AS build
WORKDIR /app
RUN npm ci && npm run build
FROM gcr.io/distroless/nodejs20-debian12
COPY --from=build /app/dist /app
`,
				"build/Dockerfile.ci": `FROM node:18-bookworm-slim AS a
FROM docker.io/library/node:21 as b
FROM public.ecr.aws/docker/library/node:20.10 AS c
FROM node:latest
FROM node:lts-alpine
FROM node:current
FROM node:alpine
FROM node:iron-bookworm
FROM node
FROM node@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
FROM mynode:16
FROM golang:1.22
`,
				"web.Dockerfile": `FROM node:20.11.0@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
FROM node:20.11.0 AS again
`,
			},
			Want: []model.Runtime{
				rt("20.11.1", "Dockerfile", ViaDockerfile),
				rt("18", "build/Dockerfile.ci", ViaDockerfile),
				rt("21", "build/Dockerfile.ci", ViaDockerfile),
				rt("20.10", "build/Dockerfile.ci", ViaDockerfile),
				rt("20.11.0", "web.Dockerfile", ViaDockerfile), // deduplicated
			},
		},
		{
			Name: "Dockerfile ARG substitution",
			Files: map[string]string{
				"Dockerfile": `ARG NODE_VERSION=20.11.1
ARG VARIANT="alpine"
FROM node:${NODE_VERSION}-${VARIANT} AS build
FROM node:${UNKNOWN}
FROM node:${NODE_MAJOR:-18}
ARG LATE=16
FROM node:$LATE
`,
				"Dockerfile.multiline": "FROM \\\n  node:19-alpine \\\n  AS build\n",
			},
			Want: []model.Runtime{
				rt("20.11.1", "Dockerfile", ViaDockerfile),
				rt("18", "Dockerfile", ViaDockerfile),
				rt("19", "Dockerfile.multiline", ViaDockerfile),
			},
		},
		{
			Name: "workflow setup-node",
			Files: map[string]string{
				".github/workflows/ci.yml": `name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node: [18, 20]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node }}
      - name: pinned
        uses: actions/setup-node@v4
        with:
          node-version: 18.10  # YAML float, must stay "18.10"
      - uses: actions/setup-node@60edb5dd545a775178f52524783378180af0d1f8
        with:
          node-version: '20.x'
      - uses: actions/setup-node@v4
        with:
          node-version-file: .nvmrc
      - uses: actions/setup-node@v4
        with:
          node-version: lts/*
      - uses: actions/setup-node@v4
        with:
          node-version: '>=18'
      - uses: actions/setup-node@v3
        with:
          node-version: "21.6.1"
          cache: npm
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v5
        with:
          node-version: '16'
`,
				".github/workflows/release.yaml": "jobs:\n  r:\n    steps:\n      - {uses: actions/setup-node@v4, with: {node-version: v20.11.1}}\n",
				".github/workflows/broken.yml":   "jobs: [\n",
			},
			Want: []model.Runtime{
				rt("18.10", ".github/workflows/ci.yml", ViaSetupNode),
				rt("20", ".github/workflows/ci.yml", ViaSetupNode),
				rt("21.6.1", ".github/workflows/ci.yml", ViaSetupNode),
				rt("20.11.1", ".github/workflows/release.yaml", ViaSetupNode),
			},
		},
		{
			Name: "unmatched and broken files are ignored",
			Files: map[string]string{
				"README.md":    "FROM node:20\n",
				"package.json": "not json {{{\n",
			},
		},
	}
	runtimetest.Run(t, newDetector(t), cases)
}
