# Writing a Heimdall plugin

Every plugin follows the same recipe. Read [ARCHITECTURE.md](ARCHITECTURE.md) first.

## Common checklist

1. Create `internal/<port>/<name>/` (e.g. `internal/source/osv/`).
2. Define the plugin's config struct with `mapstructure` tags, plus `Validate()` if needed.
   Secrets are referenced by `*_env` / `*_file` keys and read with `secret.Resolve`.
3. Write the factory and register it in `init()`:

   ```go
   func init() { source.Vuln.Register("osv", New) }

   type Config struct {
       BaseURL string `mapstructure:"base_url"`
   }

   func New(raw plugin.Config, deps plugin.Deps) (source.VulnSource, error) {
       cfg := Config{BaseURL: "https://api.osv.dev"}
       if err := raw.Decode(&cfg); err != nil {
           return nil, fmt.Errorf("osv: %w", err)
       }
       return &OSV{cfg: cfg, http: deps.HTTP, cache: deps.Cache}, nil
   }
   ```
4. Use `deps.HTTP` for HTTP, `deps.Cache` for caching, `deps.Git` for git. Never create your own client.
5. Import only `model`, foundation packages and ports. Never another adapter (`archtest` fails).
6. Add the blank import to `internal/app/plugins.go`.
7. Run the port's contract kit in your tests, with fixtures in `testdata/`.
8. Document config keys in `configs/heimdall.example.yaml`.

## Adding a VCS provider (GitLab, Bitbucket, Gitea...)

- Package: `internal/vcs/<name>`; register in `vcs.Registry`.
- Factory: `func(cfg plugin.Config, creds vcs.Credentials, deps plugin.Deps) (vcs.Provider, error)`.
  `creds.List` lists repos, `creds.Read` reads code; use `auth.TokenSource` / `auth.SSHSource`.
  Return `vcs.ErrUnsupported` when a credential cannot do an operation.
- Handle the three target kinds (`org`, `user`, `repo`), apply `model.RepoFilter`, set `Repo.Ref`.
- Return `vcs.ErrNotFound` for missing refs/files.
- Test: `vcstest.Run(t, provider, vcstest.Fixture{...})` against an `httptest` server.

## Adding an auth method

- Package: `internal/auth/<name>`; register in `auth.Registry` under the `type` used in `auth_profiles`.
- Implement `auth.TokenSource` and/or `auth.SSHSource`. Cache and refresh tokens internally.

## Adding an ecosystem

- Package: `internal/ecosystem/<name>`; register in `ecosystem.Registry`.
- `Parse` receives all matched files of a repo (for workspaces/root lockfiles) and returns
  one graph per manifest. Build packages with `model.NewPackage`.
- Mark `Private` using `ecosystem.Options.PrivatePatterns`; set `Unresolvable` (with a reason)
  for local paths / git sources; set `Approximate` when there is no lockfile.
- Provide a `version.Comparator` (add it to `internal/version`).
- Add its runtime name to `runtimeOf` in `internal/app/app.go`.
- Test: `ecosystemtest.Run`.

## Adding a runtime detector

- Package: `internal/runtime/<name>`; register in `runtime.Registry`. `Runtime()` returns
  `go`, `node` or `ruby`; the app enables detectors whose runtime matches a configured ecosystem.
- Every result carries `Origin` (file) and `Via` (how it was declared).
- Test: `runtimetest.Run`.

## Adding a check source

- Vulnerabilities: `source.Vuln`; enrichment (CVSS/EPSS/KEV): `source.Enrichers`;
  runtime EOL: `source.Runtime`; latest version: `source.Latest`. One package may register
  in several kinds under the same name.
- Map records to the OSV-shaped `model.Advisory`, fill `Sources` with the source name and
  list the matched package in `Affected`.
- Batch queries; respect `ctx`; return errors instead of partial silence (the core marks the
  source unhealthy and continues).
- Test: `sourcetest.RunVuln` / `sourcetest.RunRuntime` with recorded responses.

## Adding a notifier

- Package: `internal/notify/<name>`; register in `notify.Registry`.
- Render every `model.EventType`; the core decides what to send and handles idempotency.
- Test: `notifytest.Run` with an `httptest` endpoint, plus golden payloads using `notifytest.Events()`.

## Adding a report format

- Package: `internal/report/<name>`; register in `report.Registry` under the format name.
- Output must be deterministic. Test: `reporttest.Run` (golden file in `testdata/`).

## Adding a store

- Package: `internal/store/<name>`; register in `store.Registry`.
- Must pass `storetest.Run`. `memstore` is the reference implementation.
