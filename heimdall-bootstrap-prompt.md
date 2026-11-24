# Heimdall — Implementation Prompt

> Paste this whole file into a coding agent (Claude Code, etc.) in an empty repo named `heimdall`.
> Heimdall is the Norse watchman of the gods who sees and hears everything across the nine realms — here, across every repo in the org.

---

## 0. Role & goal

You are a senior Go engineer building **Heimdall**, an internal tool that:

1. Discovers every repository in one or more VCS organizations.
2. Reads dependency manifests on each repo's **default branch** (Ruby, Go, Node.js).
3. Checks every dependency and every **language runtime version** against multiple vulnerability, security-signal and end-of-life sources.
4. Produces actionable recommendations: *which library to bump, to what version, is it a major bump, is it direct or transitive, is the runtime EOL*.
5. Notifies Slack (only what is new or still unresolved past SLA).
6. Exposes an **MCP server** and an **agent prompt** so an AI agent can run a daily scan, triage findings and add new check sources.
7. Later (phase 2): scans **source code** on the default branch (SAST, secrets, IaC).

**Non-negotiable design principle:** every axis of variation is a plugin behind an interface, registered in a registry and enabled by config:
VCS providers · auth methods · ecosystems/parsers · vulnerability sources · enrichers · runtime/EOL sources · code scanners · notifiers · report formats.
Adding a new one must never require touching the core pipeline.

Work in small, reviewable commits. Write tests as you go. Ask before adding heavy dependencies.

---

## 1. Tech stack

- **Go ≥ 1.23**, single static binary (`CGO_ENABLED=0`) — must run on macOS, Linux and Windows jump hosts.
- CLI: `spf13/cobra` + `spf13/viper` (YAML config + env overrides `HEIMDALL_*`).
- HTTP: stdlib `net/http` with a shared client: retries + exponential backoff, rate-limit awareness (`Retry-After`, `X-RateLimit-*`), per-host concurrency limits, on-disk response cache with TTL.
- Storage: SQLite via `modernc.org/sqlite` (pure Go) for scan history and diffing; Postgres optional later behind the same `Store` interface.
- Logging: `log/slog` (JSON in CI, text locally).
- MCP: official Go SDK `github.com/modelcontextprotocol/go-sdk` (stdio + streamable HTTP transports).
- Version parsing: `golang.org/x/mod/semver` for Go; `github.com/Masterminds/semver/v3` for npm; implement a RubyGems `Gem::Version`-compatible comparator (segments, prerelease letters).
- Package identity: **PURL** (`github.com/package-url/packageurl-go`) everywhere — e.g. `pkg:npm/%40scope/name@1.2.3`, `pkg:golang/github.com/foo/bar@v1.2.3`, `pkg:gem/rails@7.1.3`.

---

## 2. Repository layout

```
heimdall/
├── cmd/heimdall/                 # main, cobra commands
├── internal/
│   ├── core/                     # pipeline orchestration, scheduler, diffing
│   ├── model/                    # Repo, Manifest, Package, Runtime, Finding, Advisory, Severity, ScanRun
│   ├── registry/                 # generic plugin registry: Register/Get/List by kind+name
│   ├── vcs/
│   │   ├── vcs.go                # Provider interface
│   │   ├── github/               # REST + GraphQL, auth: app | token | ssh
│   │   └── (gitlab, bitbucket, gitea, azuredevops — later)
│   ├── auth/                     # credential providers (env, file, keychain, vault later)
│   ├── ecosystem/
│   │   ├── ecosystem.go          # Ecosystem interface
│   │   ├── npm/                  # package.json, package-lock (v1/v2/v3), npm-shrinkwrap, yarn.lock (v1 + berry), pnpm-lock.yaml
│   │   ├── gomod/                # go.mod (require/replace/exclude, go + toolchain directives), go.work
│   │   └── rubygems/             # Gemfile, Gemfile.lock (GEM/GIT/PATH specs, DEPENDENCIES, RUBY VERSION, BUNDLED WITH), *.gemspec
│   ├── runtime/                  # runtime version detectors: .nvmrc, .node-version, engines.node, .tool-versions,
│   │                             # .ruby-version, Gemfile `ruby`, go.mod go/toolchain, .go-version, Dockerfile FROM, CI files
│   ├── source/
│   │   ├── source.go             # VulnSource, Enricher, RuntimeSource, LatestVersionSource interfaces
│   │   ├── osv/  ghsa/  govulndb/  rubysec/  npmaudit/
│   │   ├── nvd/  kev/  epss/  depsdev/  scorecard/
│   │   ├── endoflife/  registry_latest/
│   │   └── exec/                 # generic external-command source (see §6.4)
│   ├── codescan/                 # phase 2: Scanner interface + semgrep, gosec, brakeman, gitleaks, trivy-config adapters
│   ├── policy/                   # severity thresholds, SLA, suppressions (.heimdall-ignore.yaml)
│   ├── recommend/                # computes fix version, bump type, direct/transitive advice
│   ├── store/                    # Store interface + sqlite impl + migrations
│   ├── notify/
│   │   ├── notify.go             # Notifier interface
│   │   └── slack/                # webhook + bot token (Block Kit)
│   ├── report/                   # json, markdown, html, csv, sarif, cyclonedx (SBOM)
│   └── mcpserver/                # MCP tools/resources/prompts
├── prompts/
│   ├── daily-scan.md             # agent routine (see §9)
│   └── add-source.md             # how an agent adds a new source
├── configs/heimdall.example.yaml
├── deploy/                       # Dockerfile, k8s CronJob, GitHub Action workflow
├── testdata/                     # fixture manifests per ecosystem + recorded HTTP responses
└── docs/                         # ARCHITECTURE.md, SOURCES.md, PLUGINS.md, RUNBOOK.md
```

---

## 3. Core interfaces (implement exactly this shape, adjust names if needed)

```go
// vcs
type Provider interface {
    Name() string                                                    // "github"
    ListRepos(ctx context.Context, org string, f RepoFilter) ([]model.Repo, error)
    DefaultBranchHead(ctx context.Context, r model.Repo) (sha string, err error)
    ListFiles(ctx context.Context, r model.Repo, ref string) ([]string, error)      // full tree, paths only
    ReadFile(ctx context.Context, r model.Repo, ref, path string) ([]byte, error)
    Checkout(ctx context.Context, r model.Repo, ref, dir string) error              // shallow clone, for code scanning / SSH mode
}

// ecosystem
type Ecosystem interface {
    Name() string                                   // "npm" | "go" | "rubygems"
    Match(path string) bool                         // is this file relevant?
    Parse(ctx context.Context, proj ProjectFiles) (*model.DependencyGraph, error)
    // ProjectFiles = all relevant files in one directory + access to ancestor files (workspaces / root lockfile)
}

// sources
type VulnSource interface {
    Name() string
    Supports(ecosystem string) bool
    Query(ctx context.Context, pkgs []model.Package) ([]model.Advisory, error)   // batch!
}
type Enricher interface {           // adds CVSS, EPSS, KEV, scorecard... to existing advisories/packages
    Name() string
    Enrich(ctx context.Context, f []*model.Finding) error
}
type RuntimeSource interface {      // EOL / support status for node, go, ruby
    Name() string
    Evaluate(ctx context.Context, rt model.Runtime) (*model.RuntimeStatus, error)
}
type LatestVersionSource interface {
    Latest(ctx context.Context, p model.Package) (string, error)
}

// code scanning (phase 2)
type CodeScanner interface {
    Name() string
    Applicable(repo model.Repo, files []string) bool
    Scan(ctx context.Context, checkoutDir string) ([]model.Finding, error)       // normalise from SARIF where possible
}

// notify
type Notifier interface {
    Name() string
    Notify(ctx context.Context, ev model.NotificationEvent) error
}
```

`model.Finding` must carry: `ID` (stable hash of repo+manifest path+purl+advisory), `Kind` (dependency | runtime | code | secret | config), repo, manifest path, PURL, current version, direct/transitive, dependency scope (prod/dev/optional), advisory IDs + aliases (GHSA/CVE/GO/OSV/MAL), summary, severity (normalised CRITICAL/HIGH/MEDIUM/LOW/UNKNOWN), CVSS vector+score, EPSS score/percentile, `InKEV bool`, fixed versions, recommended version, bump type (patch/minor/major/none-available), `FirstSeen`, `LastSeen`, `Status` (open/fixed/suppressed), source names that reported it.

**Deduplicate advisories across sources** by ID + aliases (GHSA ↔ CVE ↔ GO-xxxx ↔ OSV). Keep the union of sources that reported it.

---

## 4. VCS & authentication (GitHub first)

Support three auth modes, selected per org in config:

| Mode | Listing repos | Reading files | Notes |
|---|---|---|---|
| **GitHub App** (recommended) | `GET /installation/repositories` using an installation token | Contents/Trees API | Sign JWT (RS256) with app private key → `POST /app/installations/{id}/access_tokens`; auto-discover installation by org; refresh tokens before expiry (1h). Minimal permissions: `Contents: read`, `Metadata: read` (+ `Dependabot alerts: read` / `Code scanning alerts: read` if those sources are enabled). |
| **Token** (classic PAT / fine-grained PAT / `GITHUB_TOKEN`) | `GET /orgs/{org}/repos` (fallback `/users/{user}/repos`) | Contents/Trees API | Read from env/file, never from CLI args. |
| **SSH** | **SSH alone cannot list repos.** Use one of: a token/App for listing only, or a static repo list in config | `git clone --depth 1 --filter=blob:none --sparse` then sparse-checkout manifests; full shallow clone for code scanning | Support `ssh_key_path`, `known_hosts`, ssh-agent. Use `git` binary via `os/exec` (or go-git behind an interface). |

Requirements:
- `base_url` configurable for **GitHub Enterprise Server**.
- Filters: include/exclude glob on repo name, topics, skip archived, skip forks, skip empty, `max_repos`, language hint.
- Use the Git Trees API (`?recursive=1`) to find manifests; handle `truncated: true` by falling back to sparse clone.
- Skip vendored/irrelevant paths: `node_modules/`, `vendor/`, `testdata/`, `.git/`, `examples/` (configurable).
- Respect rate limits; when using GraphQL prefer batching.
- Record the default-branch HEAD SHA per scan → if unchanged since last scan and sources' data unchanged, reuse parsed manifests (incremental scans).

Design `vcs` so **GitLab, Bitbucket, Gitea, Azure DevOps** can be added as new packages only. Write a `docs/PLUGINS.md` section "Adding a VCS provider".

---

## 5. Ecosystems & runtimes

### 5.1 Dependencies
- **Node**: prefer lockfiles (exact versions, full transitive graph, `dev`/`optional` flags); `package.json` alone → mark versions as `approximate` and emit a `missing-lockfile` finding instead of guessing vulnerabilities (configurable `--detection comprehensive` to query the min version in range). Handle npm aliases (`npm:pkg@x`), workspaces (root lockfile covers child `package.json`), `file:`/`link:`/`git+` deps (skip, list as `unresolvable`).
- **Go**: `go.mod` require (mark `// indirect`), `replace` (module→module with version = use replacement; local path = skip), `exclude`. Strip `+incompatible`. Treat pseudo-versions correctly. Mark modules matching `GOPRIVATE`-style patterns from config as `private` (skip public lookups).
- **Ruby**: `Gemfile.lock` specs (strip platform suffix like `-x86_64-linux`), direct = `DEPENDENCIES`, `GIT`/`PATH` sources = unresolvable/private; `Gemfile` alone → approximate.

### 5.2 Runtimes
Detect declared runtime versions from every source and keep all of them with their origin file:
- Node: `.nvmrc`, `.node-version`, `.tool-versions`, `package.json engines.node`, `volta.node`, Dockerfile `FROM node:*`, CI files (`actions/setup-node` `node-version`).
- Go: `go.mod` `go` + `toolchain`, `.go-version`, `.tool-versions`, Dockerfile `FROM golang:*`, CI `setup-go`.
- Ruby: `.ruby-version`, `.tool-versions`, `Gemfile` `ruby`, `Gemfile.lock` `RUBY VERSION`, Dockerfile `FROM ruby:*`, CI `setup-ruby`.

Evaluate each with: support status (supported / security-only / EOL / EOL within N days), latest patch of the same cycle, latest supported cycle. For **Go**, also query OSV for `stdlib` (and `toolchain`) vulns at the detected version. Flag inconsistencies (e.g. `.nvmrc` = 18 but Dockerfile = 20).

---

## 6. Check sources (all optional, toggled in config)

### 6.1 Vulnerability sources (Phase 1 – implement)
| Name | What | Access | Notes |
|---|---|---|---|
| `osv` | **OSV.dev** — aggregates GHSA, Go vulndb, RubySec, npm, malicious-packages (`MAL-*`) | `POST https://api.osv.dev/v1/querybatch` + `GET /v1/vulns/{id}` | Primary source. Batch ≤1000 queries, follow `next_page_token`, cache vuln details. Offline mode: download `https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip`. |
| `ghsa` | **GitHub Advisory Database** | GraphQL `securityVulnerabilities` / REST `/advisories` | Best severity + CVSS data; uses same GitHub credentials. |
| `govulndb` | **Go vulnerability DB** | `https://vuln.go.dev` | Also used for `stdlib`/toolchain. |
| `rubysec` | **ruby-advisory-db** (bundler-audit data) | git clone `rubysec/ruby-advisory-db` | Cache locally, refresh daily. |
| `npmaudit` | **npm registry bulk advisories** | `POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk` | Cross-check for npm. |

### 6.2 Enrichers (Phase 1 – implement)
| Name | What | Access |
|---|---|---|
| `nvd` | CVSS v3/v4 vectors & CWE for CVE aliases | NVD API 2.0 (API key optional, strict rate limit → cache) |
| `kev` | **CISA Known Exploited Vulnerabilities** → `InKEV` = top priority | JSON feed, refresh daily |
| `epss` | **FIRST EPSS** exploit probability | `https://api.first.org/data/v1/epss?cve=...` |
| `endoflife` | Runtime EOL/support for nodejs, go, ruby | `https://endoflife.date/api/...` |
| `registry_latest` | Latest versions | npm registry, `proxy.golang.org/{module}/@latest` (case-encode `!`), `rubygems.org/api/v1/versions/{gem}/latest.json` |

### 6.3 Optional / later sources (stub interfaces + docs only, implement on demand)
- `depsdev` — Google **deps.dev** API (versions, dependency graph, licenses, advisories).
- `scorecard` — **OpenSSF Scorecard** for direct deps (abandoned/unmaintained signal).
- `github_dependabot` — read existing Dependabot alerts per repo (avoid duplicate triage).
- `github_code_scanning` — read existing code-scanning alerts.
- `ossindex` — Sonatype OSS Index (free with account).
- `snyk`, `socket` — commercial, token-gated.
- `trivy_db` / `grype_db` — offline DBs for air-gapped runs.
- License policy (from deps.dev / registries).

### 6.4 Generic extension source: `exec`
Lets anyone (including the AI agent) add a source **without recompiling**:
```yaml
sources:
  - name: my-internal-feed
    type: exec
    command: ["python3", "/opt/heimdall-sources/internal_feed.py"]
    supports: [npm, go, rubygems]
    timeout: 60s
```
Contract: Heimdall writes `{"packages":[{"purl":"...","ecosystem":"...","name":"...","version":"..."}]}` to stdin; the command prints `{"advisories":[{...OSV schema...}]}` to stdout. Also support `type: http` (same JSON contract via POST to a URL). **Use the OSV schema as the interchange format.** Validate output, enforce timeout, sandbox env (no secrets passed unless listed).

### 6.5 Code scanners (Phase 2 – default branch, full shallow clone)
- `semgrep` (OSS rules: `p/golang`, `p/ruby`, `p/javascript`, `p/secrets`, custom rules dir)
- `gosec` (Go), `brakeman` (Rails), `eslint-plugin-security` (optional)
- `govulncheck` — **reachability**: downgrade Go dependency findings whose vulnerable symbols are never called
- `gitleaks` or `trufflehog` — secrets (current tree; optional history depth)
- `trivy config` / `hadolint` — Dockerfile & K8s manifests misconfig
- `osv-scanner` — as an optional cross-check source

All scanners run as external binaries (or containers) through the `CodeScanner` interface; normalise via **SARIF** parser.

---

## 7. Recommendation logic (`internal/recommend`)
For each vulnerable package version:
1. Collect fixed versions from all advisories; pick, per advisory, the smallest fixed version > current within the same introduced range; the recommended version = max over advisories.
2. Bump type vs current: patch / minor / **major (breaking — needs testing)** / `no-fix-available` (suggest alternatives or mitigations, link advisory).
3. If **transitive**: identify the direct parent(s) from the dependency graph and suggest bumping the parent; otherwise suggest `overrides` (npm), `resolutions` (yarn), `pnpm.overrides`, `replace` / `go get mod@ver` (Go), adding the gem explicitly to the Gemfile (Ruby).
4. Priority score: `InKEV` > CVSS/severity × EPSS × (prod ? 1 : 0.3) × (direct ? 1 : 0.8) × (reachable? govulncheck). Make weights configurable.
5. Runtime: "upgrade to latest patch X.Y.Z" when behind in same cycle; "migrate to cycle N" when EOL or EOL < 90 days.
6. Group per repo into a **single upgrade plan** (one line per package, not per advisory).

---

## 8. Slack notifications (`internal/notify/slack`)
- Support **Incoming Webhook** (simple) and **Bot token** (`chat.postMessage`, threads, updates). Prefer bot token.
- Events:
  - `scan.summary` — daily digest: repos scanned, new / fixed / still-open counts by severity, top 10 by priority, EOL runtimes, link to full HTML report.
  - `finding.new` — immediately for `CRITICAL`, `InKEV`, malicious package (`MAL-*`), or leaked secret (phase 2).
  - `finding.sla_breached` — open past SLA (e.g. critical 7d, high 30d).
  - `runtime.eol_soon` — runtime EOL within N days.
- Routing: default channel + per-repo/team overrides (map from config, or from GitHub CODEOWNERS/topics). One thread per repo per digest.
- **Only notify on diffs** (new / fixed / SLA) using the store; never spam the same finding daily.
- Block Kit with severity emoji, package, current → recommended, bump type, advisory links, repo link.
- Notifier interface so Teams / Discord / email / Jira / GitHub Issues can be added later.

---

## 9. MCP server & AI-agent daily routine

### 9.1 MCP server (`heimdall mcp --transport stdio|http`)
Tools (all return JSON, all read-only unless stated):
- `list_orgs`, `list_repos(org, filter)`
- `scan_org(org, sources?, since_last?)` → scan run ID (async; `get_scan_status(run_id)`)
- `scan_repo(repo, ref?)`
- `get_findings(filter: repo|severity|kind|status|kev|new_since)`
- `get_finding(id)` — full detail incl. all advisories and recommendation
- `get_upgrade_plan(repo)`
- `get_runtime_status(org?)`
- `diff_scans(run_a, run_b)`
- `list_sources()` — enabled/disabled, last refresh, health
- `test_source(name, sample_purls)` — dry-run a source
- **write** `register_source(config)` — add an `exec`/`http` source to config (requires `--allow-config-writes`)
- **write** `suppress_finding(id, reason, expires_at)` — appends to suppressions with mandatory reason + expiry
- `post_slack_summary(run_id, channel?)` — **write**, gated by flag

Resources: `heimdall://reports/latest.md`, `heimdall://sources`, `heimdall://config` (secrets redacted).
Prompts: expose `prompts/daily-scan.md` and `prompts/add-source.md` as MCP prompts.

Security: write tools disabled by default; never return secrets; audit-log every MCP call.

### 9.2 `prompts/daily-scan.md` (write this file)
Agent routine, run once a day (e.g. scheduled Claude Code / CI job with the MCP server attached):
1. `scan_org` for each configured org, wait for completion.
2. `diff_scans` vs previous run; list **new** CRITICAL/HIGH, KEV, malicious, and newly EOL runtimes.
3. For each new top-priority finding: read `get_finding`, verify the fix version exists (`registry_latest`), check whether it is a major bump, and write a 2–3 line human triage note (impact, recommended action, effort).
4. Detect gaps: ecosystems/files seen but unsupported, advisories lacking severity, sources failing health checks → propose fixes.
5. **Source discovery**: check whether new public advisory feeds or better sources exist for npm/Go/RubyGems (e.g. new OSV ecosystems, vendor feeds). If one is valuable, draft an `exec` source script + config following `prompts/add-source.md`, run `test_source`, and open a PR (never enable it directly in prod).
6. Post the Slack digest with triage notes (`post_slack_summary`).
7. Output a short markdown summary of what was done.
Rules: never suppress findings without a human; never push to default branches; keep the Slack message concise.

### 9.3 `prompts/add-source.md` (write this file)
Step-by-step for humans/agents: choose type (`exec`/`http`/native Go), map the feed to OSV schema, handle ecosystems + version ranges, add fixtures in `testdata/`, add a contract test, document in `docs/SOURCES.md`, open PR.

---

## 10. CLI

```
heimdall scan --org remitano [--repo 'dax-*'] [--sources osv,ghsa,kev,epss] [--code] [--out reports/] [--format md,html,json,sarif,csv,cyclonedx] [--fail-on high]
heimdall repos --org remitano
heimdall sources list | test <name>
heimdall report --run latest --format html
heimdall diff --from <run> --to latest
heimdall notify --run latest
heimdall suppress add <finding-id> --reason "..." --expires 2027-01-31
heimdall mcp --transport stdio
heimdall db migrate
```
Exit codes: `0` ok, `1` findings ≥ `--fail-on`, `2` runtime error.

---

## 11. Config (`configs/heimdall.example.yaml`)

```yaml
orgs:
  - name: remitano
    provider: github
    base_url: https://api.github.com          # GHES: https://ghe.example.com/api/v3
    auth:
      type: app                               # app | token | ssh
      app_id: ${HEIMDALL_GH_APP_ID}
      private_key_file: /secrets/gh-app.pem
      # token_env: GITHUB_TOKEN
      # ssh: { key_file: ~/.ssh/id_ed25519, known_hosts: ~/.ssh/known_hosts, list_with: token }
    filters:
      include: ["*"]
      exclude: ["*-archive", "sandbox-*"]
      skip_archived: true
      skip_forks: true
    private_modules: ["github.com/remitano/*", "@remitano/*"]

ecosystems: [npm, go, rubygems]
detection: precise            # precise | comprehensive

sources:
  - { name: osv,        enabled: true }
  - { name: ghsa,       enabled: true }
  - { name: govulndb,   enabled: true }
  - { name: rubysec,    enabled: true }
  - { name: npmaudit,   enabled: false }
  - { name: nvd,        enabled: true, api_key_env: NVD_API_KEY }
  - { name: kev,        enabled: true }
  - { name: epss,       enabled: true }
  - { name: endoflife,  enabled: true, eol_warning_days: 90 }
  - { name: registry_latest, enabled: true, direct_only: true }

codescan:
  enabled: false
  scanners: [semgrep, gosec, brakeman, gitleaks, govulncheck, trivy-config]

policy:
  sla_days: { CRITICAL: 7, HIGH: 30, MEDIUM: 90 }
  ignore_dev_dependencies: false
  suppressions_file: .heimdall-ignore.yaml

notify:
  slack:
    enabled: true
    bot_token_env: SLACK_BOT_TOKEN
    default_channel: "#sec-deps"
    routes:
      - { repo: "dax-*", channel: "#dax-security" }
    immediate: [CRITICAL, KEV, MALICIOUS, SECRET]

store: { driver: sqlite, dsn: ./heimdall.db }
cache: { dir: ~/.cache/heimdall, ttl: 24h }
concurrency: { repos: 8, http_per_host: 4 }
```
Secrets only via env/file references — never inline.

---

## 12. Reports
- **HTML** (single self-contained file): org overview, per-repo upgrade plan, runtime table, filters by severity/kind/repo, KEV/EPSS badges.
- **Markdown** (for PRs/Slack attachments), **JSON** (full model), **CSV** (findings), **SARIF** (upload to GitHub code scanning), **CycloneDX SBOM** per repo (feedable to Dependency-Track later).

---

## 13. Deployment
- `Dockerfile` (distroless, non-root) with optional "full" image bundling semgrep/gosec/brakeman/gitleaks/govulncheck/trivy.
- `deploy/k8s/cronjob.yaml` — daily CronJob, secrets from K8s Secret, SQLite on a PVC (or Postgres).
- `deploy/github-action.yml` — scheduled workflow alternative.
- `docs/RUNBOOK.md` — creating the GitHub App (permissions list), Slack app scopes (`chat:write`, `chat:write.public`), rotating keys, adding a repo route.

---

## 14. Quality bar
- Unit tests for every parser with real-world fixtures (npm lock v1/v2/v3, yarn v1 + berry, pnpm v6/v9, go.mod with replace/indirect/toolchain, Gemfile.lock with GIT/PATH/platforms).
- Contract tests for each source using recorded responses (`httptest`); no live network in `go test ./...` (live tests behind `-tags=live`).
- Golden-file tests for reports and Slack payloads.
- `golangci-lint` clean, `go vet`, race detector in CI.
- Every source/enricher must degrade gracefully: on failure, log + mark source unhealthy in the run, continue with others, and surface it in the report and Slack digest.

---

## 15. Milestones (implement in order, stop and summarise after each)
1. **M1 – Skeleton**: repo layout, config, registry, model, CLI `repos` with GitHub token auth, SQLite store.
2. **M2 – Parsers**: npm, go, rubygems + runtime detectors, with fixtures/tests. `heimdall scan --dry-run` prints inventory.
3. **M3 – Sources**: osv, ghsa, govulndb, rubysec, endoflife, kev, epss, nvd, registry_latest; dedup + recommend.
4. **M4 – Reports & diff**: md/json/html/csv/sarif/cyclonedx, scan history, `diff`.
5. **M5 – Auth**: GitHub App + SSH modes, GHES support.
6. **M6 – Slack**: digest, immediate alerts, routing, SLA.
7. **M7 – MCP**: server, tools, prompts (`daily-scan.md`, `add-source.md`), `exec`/`http` sources.
8. **M8 – Deploy**: Docker, CronJob, GitHub Action, RUNBOOK.
9. **M9 – Code scanning (phase 2)**: shallow checkout, semgrep/gosec/brakeman/gitleaks/govulncheck/trivy-config via SARIF.
10. **M10 – More VCS**: GitLab provider (groups + subgroups), then Bitbucket/Gitea.

Start with M1. Before writing code, output a short plan of M1 and the exact interfaces you will create.
