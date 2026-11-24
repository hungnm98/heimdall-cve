package ruby

import (
	"context"
	"testing"

	"github.com/hungnm98/heimdall-cve/internal/model"
	"github.com/hungnm98/heimdall-cve/internal/plugin"
	"github.com/hungnm98/heimdall-cve/internal/runtime"
	"github.com/hungnm98/heimdall-cve/internal/runtime/runtimetest"
)

func rt(version, origin, via string) model.Runtime {
	return model.Runtime{Name: "ruby", Version: version, Origin: origin, Via: via}
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
		".ruby-version", "svc/.ruby-version", ".tool-versions", "Gemfile", "svc/gems.rb",
		"Gemfile.lock", "svc/gems.locked", "Dockerfile", "docker/Dockerfile.prod", "web.Dockerfile",
		".github/workflows/ci.yml", ".github/workflows/test.yaml",
	} {
		if !d.Match(p) {
			t.Errorf("Match(%q) = false", p)
		}
	}
	for _, p := range []string{
		"Rakefile", "app.gemspec", "Gemfile.next", ".github/workflows/sub/ci.yml",
		"docker-compose.yml", "vendor/bundle/ruby/3.2.0/gems/x-1.0/.ruby-version",
		"vendor/bundle/ruby/3.2.0/gems/x-1.0/Gemfile",
	} {
		if d.Match(p) {
			t.Errorf("Match(%q) = true", p)
		}
	}
}

func TestContract(t *testing.T) {
	cases := []runtimetest.Case{
		{
			Name: ".ruby-version",
			Files: map[string]string{
				".ruby-version":       "3.2.2\n",
				"api/.ruby-version":   "ruby-3.3.0\n",
				"pre/.ruby-version":   "# pinned\n\n3.4.0-preview1\n",
				"jruby/.ruby-version": "jruby-9.4.5.0\n",
				"bad/.ruby-version":   "system\n",
				"vendor/bundle/ruby/3.2.0/gems/x-1.0/.ruby-version": "2.7.8\n",
			},
			Want: []model.Runtime{
				rt("3.2.2", ".ruby-version", ViaRubyVersion),
				rt("3.3.0", "api/.ruby-version", ViaRubyVersion),
				rt("3.4.0-preview1", "pre/.ruby-version", ViaRubyVersion),
			},
		},
		{
			Name: ".tool-versions",
			Files: map[string]string{
				".tool-versions":     "nodejs 20.11.0\nruby 3.2.2 3.1.4 # fallback\ngolang 1.22.5\n",
				"svc/.tool-versions": "nodejs 20.11.0\n",
			},
			Want: []model.Runtime{rt("3.2.2", ".tool-versions", ViaToolVersion)},
		},
		{
			Name: "Gemfile ruby",
			Files: map[string]string{
				"Gemfile":        "source \"https://rubygems.org\"\n\nruby \"3.2.2\"\n\ngem \"rails\"\n",
				"b/gems.rb":      "source 'https://rubygems.org'\nruby('3.1.4', patchlevel: '223')\n",
				"file/Gemfile":   "ruby file: \".ruby-version\"\ngem \"rails\"\n",
				"range/Gemfile":  "ruby \"~> 3.2.0\"\n",
				"jruby/Gemfile":  "ruby \"3.1.4\", engine: \"jruby\", engine_version: \"9.4.5.0\"\n",
				"dyn/Gemfile":    "ruby RUBY_VERSION\n",
				"plain/Gemfile":  "gem \"ruby-progressbar\", \"~> 1.13\"\n",
				"indent/Gemfile": "  ruby '3.3.0' # app runtime\n",
			},
			Want: []model.Runtime{
				rt("3.2.2", "Gemfile", ViaGemfile),
				rt("3.1.4", "b/gems.rb", ViaGemfile),
				rt("3.3.0", "indent/Gemfile", ViaGemfile),
			},
		},
		{
			Name: "lockfile RUBY VERSION",
			Files: map[string]string{
				"Gemfile.lock":     "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.0.9)\n\nDEPENDENCIES\n  rack\n\nRUBY VERSION\n   ruby 3.2.2p53\n\nBUNDLED WITH\n   2.5.6\n",
				"svc/gems.locked":  "GEM\n  specs:\n\nRUBY VERSION\n   ruby 3.3.0p0\r\n",
				"old/Gemfile.lock": "GEM\n  specs:\n    ruby (1.0.0)\n\nBUNDLED WITH\n   2.5.6\n",
			},
			Want: []model.Runtime{
				rt("3.2.2", "Gemfile.lock", ViaLockfile),
				rt("3.3.0", "svc/gems.locked", ViaLockfile),
			},
		},
		{
			Name: "Dockerfile",
			Files: map[string]string{
				"Dockerfile": `# syntax=docker/dockerfile:1
ARG RUBY_VERSION=3.2.2
ARG DISTRO
FROM --platform=linux/amd64 docker.io/library/ruby:$RUBY_VERSION-slim-bookworm AS base
FROM base AS build
FROM ruby:${RUBY_VERSION} AS test
FROM ruby:${DISTRO} AS unknown
FROM ruby:latest
FROM ruby:slim
FROM ruby:3-alpine
FROM ruby@sha256:0123456789abcdef
FROM node:20-alpine
`,
				"docker/Dockerfile.prod": "FROM \\\n  registry.example.com:5000/mirror/ruby:3.3-alpine3.19 AS app\n",
				"ci.Dockerfile":          "FROM public.ecr.aws/docker/library/ruby:3.1.4@sha256:abcdef\n",
				"Dockerfile.rc":          "FROM ruby:3.4.0-preview1-slim\n",
			},
			Want: []model.Runtime{
				rt("3.2.2", "Dockerfile", ViaDockerfile),
				rt("3.3", "docker/Dockerfile.prod", ViaDockerfile),
				rt("3.1.4", "ci.Dockerfile", ViaDockerfile),
				rt("3.4.0-preview1", "Dockerfile.rc", ViaDockerfile),
			},
		},
		{
			Name: "setup-ruby",
			Files: map[string]string{
				".github/workflows/ci.yml": `name: CI
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        ruby: ["3.1", "3.2"]
    steps:
      - uses: actions/checkout@v4
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: 3.2.2
          bundler-cache: true
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: ${{ matrix.ruby }}
      - uses: ruby/setup-ruby@1a615958ad9d422dd932dc1d5823942ee002799f
        with:
          ruby-version: '3.3'
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: .ruby-version
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: head
      - uses: ruby/setup-ruby@v1
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: ruby/setup-ruby@v1
        with:
          ruby-version: "3.2.2"
`,
				".github/workflows/broken.yml": "jobs: [\n",
			},
			Want: []model.Runtime{
				rt("3.2.2", ".github/workflows/ci.yml", ViaSetupRuby),
				rt("3.3", ".github/workflows/ci.yml", ViaSetupRuby),
			},
		},
		{
			Name: "all sources together",
			Files: map[string]string{
				".ruby-version":               "3.2.2",
				"Gemfile":                     "ruby file: \".ruby-version\"\n",
				"Gemfile.lock":                "RUBY VERSION\n   ruby 3.2.2p53\n",
				"Dockerfile":                  "FROM ruby:3.2.2\n",
				".github/workflows/ruby.yaml": "jobs:\n  t:\n    steps:\n      - uses: ruby/setup-ruby@v1\n        with:\n          ruby-version: '3.2'\n",
				"README.md":                   "ruby 3.2.2",
			},
			Want: []model.Runtime{
				rt("3.2.2", ".ruby-version", ViaRubyVersion),
				rt("3.2.2", "Gemfile.lock", ViaLockfile),
				rt("3.2.2", "Dockerfile", ViaDockerfile),
				rt("3.2", ".github/workflows/ruby.yaml", ViaSetupRuby),
			},
		},
	}
	runtimetest.Run(t, newDetector(t), cases)
}

func TestDetectSorted(t *testing.T) {
	files := model.FileSet{Files: map[string][]byte{
		"b/.ruby-version": []byte("3.1.4"),
		"a/.ruby-version": []byte("3.2.2"),
		"Dockerfile":      []byte("FROM ruby:3.3\nFROM ruby:3.2\nFROM ruby:3.3\n"),
	}}
	got, err := newDetector(t).Detect(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	want := []model.Runtime{
		rt("3.2", "Dockerfile", ViaDockerfile),
		rt("3.3", "Dockerfile", ViaDockerfile),
		rt("3.2.2", "a/.ruby-version", ViaRubyVersion),
		rt("3.1.4", "b/.ruby-version", ViaRubyVersion),
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestRegistered(t *testing.T) {
	f, err := runtime.Registry.Get("ruby")
	if err != nil {
		t.Fatal(err)
	}
	d, err := f(nil, plugin.Deps{})
	if err != nil || d.Runtime() != "ruby" {
		t.Fatalf("factory: %v, %v", d, err)
	}
	if _, err := New(plugin.Config{"unknown": 1}, plugin.Deps{}); err == nil {
		t.Error("unknown config key: want error")
	}
}
