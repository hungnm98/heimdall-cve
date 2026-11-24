package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hungnm98/heimdall-cve/internal/model"
)

const yamlCfg = `
auth_profiles:
  gh-app: { type: app, app_id_env: HEIMDALL_GH_APP_ID, private_key_file: /secrets/gh-app.pem }
  gh-pat: { type: token, token_env: GITHUB_TOKEN }
  gh-ssh: { type: ssh, key_file: ~/.ssh/id_ed25519 }
targets:
  - { kind: org, name: acme, auth: gh-app, filters: { exclude: ["sandbox-*"], skip_forks: false } }
  - { kind: user, name: someone, auth: gh-pat }
  - { kind: repo, url: "git@github.com:acme/foo.git", auth: gh-ssh, branch: develop }
  - { kind: org, name: acme, auth: gh-ssh, list_auth: gh-pat }
sources:
  osv: { enabled: true }
  endoflife: { enabled: false, eol_warning_days: 60 }
notify:
  slack-sec: { type: slack-webhook, webhook_env: SLACK_WEBHOOK_URL }
`

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadYAML(t *testing.T) {
	c, err := Load(write(t, "heimdall.yaml", yamlCfg))
	if err != nil {
		t.Fatal(err)
	}
	if c.Cache.TTL != 24*time.Hour || c.Store.Type != "postgres" || len(c.Ecosystems) != 0 { // empty = all compiled in
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.Sources["endoflife"].IsEnabled() || c.Sources["endoflife"].Options["eol_warning_days"] == nil {
		t.Fatalf("plugin options not kept: %+v", c.Sources["endoflife"])
	}
	if n := c.Notify["slack-sec"]; n.TypeOr("slack-sec") != "slack-webhook" || n.Options["webhook_env"] != "SLACK_WEBHOOK_URL" {
		t.Fatalf("notify: %+v", n)
	}
	ts := c.ModelTargets()
	if ts[0].Filter.SkipForks || !ts[0].Filter.SkipArchived || ts[0].Provider != "github" || ts[0].ListAuth != "gh-app" {
		t.Fatalf("target 0: %+v", ts[0])
	}
	if ts[2].Kind != model.TargetRepo || ts[2].Owner != "acme" || ts[2].Name != "foo" || ts[2].Branch != "develop" {
		t.Fatalf("target 2: %+v", ts[2])
	}
	if ts[3].ListAuth != "gh-pat" {
		t.Fatalf("target 3: %+v", ts[3])
	}
	if s := c.Summary(); !strings.Contains(s, "repo:acme/foo") || strings.Contains(s, "/secrets/gh-app.pem") {
		t.Fatalf("summary must list targets and hide option values:\n%s", s)
	}
}

func TestLoadJSONAndEnvOverride(t *testing.T) {
	t.Setenv("HEIMDALL_CACHE_TTL", "2h")
	p := write(t, "heimdall.json", `{
	  "auth_profiles": {"pat": {"type": "token", "token_env": "GITHUB_TOKEN"}},
	  "targets": [{"kind": "repo", "url": "https://github.com/acme/bar", "auth": "pat"}]
	}`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Cache.TTL != 2*time.Hour {
		t.Fatalf("env override: %+v", c.Cache)
	}
}

func TestValidateReportsAllErrors(t *testing.T) {
	p := write(t, "bad.yaml", `
auth_profiles:
  x: { token_env: T }
targets:
  - { kind: team, name: a, auth: x }
  - { kind: repo, url: "not-a-url", auth: missing }
policy: { fail_on: urgent }
`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"type is required", "kind must be", "unknown auth profile", "expected https://", "fail_on"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
}

func TestExampleConfigIsValid(t *testing.T) {
	c, err := Load("../../configs/heimdall.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Targets) != 4 || c.Policy.FailOn != "HIGH" {
		t.Fatalf("unexpected example config: %+v", c)
	}
}

func TestUnknownTopLevelKey(t *testing.T) {
	p := write(t, "typo.yaml", yamlCfg+"\ntargetz: []\n")
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), "targetz") {
		t.Fatalf("typo must fail, got %v", err)
	}
}

func TestEmptyPluginBlocksAndDefaultSources(t *testing.T) {
	base := "auth_profiles: { pat: { type: token, token_env: T } }\ntargets: [ { kind: org, name: acme, auth: pat } ]\n"
	c, err := Load(write(t, "a.yaml", base+"sources: { osv: {}, endoflife: {} }\nnotify: { slack-webhook: {} }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.Sources["osv"]; !ok || len(c.Sources) != 2 || len(c.Notify) != 1 {
		t.Fatalf("empty blocks must enable their plugin: sources=%v notify=%v", c.Sources, c.Notify)
	}
	c, err = Load(write(t, "b.yaml", base))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Sources) != len(DefaultSources) || !c.Sources["osv"].IsEnabled() {
		t.Fatalf("no sources section must enable the defaults, got %v", c.Sources)
	}
	c, err = Load(write(t, "c.yaml", base+"sources: { osv: { enabled: false } }\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Sources) != 1 || c.Sources["osv"].IsEnabled() {
		t.Fatalf("an explicit sources section replaces the defaults, got %v", c.Sources)
	}
}

func TestTargetBranchesScheduleAndPoll(t *testing.T) {
	const base = `
auth_profiles: { pat: { type: token, token_env: GH } }
targets:
  - { kind: org, name: acme, auth: pat, branches: ["release/*", develop], max_branches: 5, schedule: "@daily", poll: "@every 1h" }
`
	c, err := Load(write(t, "ok.yaml", base))
	if err != nil {
		t.Fatal(err)
	}
	mt := c.ModelTargets()[0]
	if len(mt.Branches) != 2 || mt.MaxBranches != 5 || c.Targets[0].Schedule != "@daily" || c.Targets[0].Poll != "@every 1h" {
		t.Fatalf("target = %+v / %+v", mt, c.Targets[0])
	}
	for name, bad := range map[string]string{
		"poll":     `poll: "every hour"`,
		"schedule": `schedule: "61 * * * *"`,
		"glob":     `branches: ["release/["]`,
	} {
		cfg := strings.Replace(base, `branches: ["release/*", develop], max_branches: 5, schedule: "@daily", poll: "@every 1h"`, bad, 1)
		if _, err := Load(write(t, name+".yaml", cfg)); err == nil {
			t.Errorf("%s: invalid value accepted", name)
		}
	}
}
