# Heimdall architecture

Heimdall is built as **ports and adapters**. The core pipeline only knows
interfaces (ports). Every axis of variation (VCS provider, auth method,
ecosystem, runtime detector, check source, store, notifier, report format) is an
adapter package that registers itself. Adding one never touches the core.

## Layers and the dependency rule

```
cmd/heimdall ─► internal/cli ─► internal/app (composition root, plugins.go)
                                     │
                                     ▼
                              internal/core  (pipeline, dedup, diff, recommend)
                                     │ depends on interfaces only
     ports:     auth · vcs · ecosystem · runtime · source · store · notify · report
                (+ contract test kits: vcstest, sourcetest, storetest, ...)
                                     ▲ implemented by
     adapters:  vcs/github · auth/token · ecosystem/gomod · source/osv · store/postgres
                notify/slackwebhook · report/markdown · ...
     foundation: model (no internal imports) · version · registry · plugin · secret
                 config · httpx · gitx
```

Layers, lowest first: `model` → foundation → ports (+ contract kits) → adapters → `core` →
`service` → entries (`api`, `mcpserver`, `webui`) → `app` → `cli`.

Rules (enforced by `internal/archtest`, which runs with `go test ./...`):

- A package may import its own layer or lower layers, **never a higher one**.
- `model` imports nothing internal.
- Adapters (`internal/<port>/<name>`, e.g. `source/osv`, `jobs/asynq`) may only be imported by
  `internal/app` (through `plugins.go`); an adapter never imports another adapter, core or service.
- Every internal package must belong to a layer (unclassified packages fail the test).

Ports: `auth`, `vcs`, `ecosystem`, `runtime`, `source`, `store` (+ optional `store.Catalog`),
`notify`, `report`, `jobs`. `core.Scanner` is the pipeline entry point; `service` is the
application layer shared by the REST API, MCP and CLI (see [WEBAPP.md](WEBAPP.md)).

## Plugin mechanics

1. Each port declares a typed registry, e.g. `source.Vuln = registry.New[source.VulnFactory]("vuln-source")`.
2. An adapter registers in `init()`: `source.Vuln.Register("osv", newOSV)`.
3. `internal/app/plugins.go` blank-imports the adapters compiled into the binary.
4. `app.New(cfg)` looks every configured name up in its registry and calls the factory with:
   - the plugin's **own raw config block** (`plugin.Config`), which the plugin decodes into its
     own struct with `cfg.Decode(&myCfg)` (unknown keys fail; `Validate()` runs if defined);
   - shared `plugin.Deps`: logger, `httpx.Client`, `httpx.Cache`, `gitx.Runner`, cache dir.
5. Missing plugins and bad options are all reported at once (`heimdall config validate`).

Optional capabilities are separate small interfaces (`source.HealthChecker`,
`auth.TokenSource`, `auth.SSHSource`) detected with type assertions, so plugins
never implement empty methods.

## Data model highlights

- **PURL** identifies packages everywhere (`model.NewPackage` builds it).
- **Finding ID** = hash(provider, repo, manifest path, version-less PURL, canonical advisory ID).
  Bumping a still-vulnerable package keeps the same finding, so `FirstSeen` and SLA survive.
- Advisories from different sources are merged by ID + aliases (GHSA ↔ CVE ↔ GO-…).
- The store records per-run snapshots; Slack only receives new / fixed / SLA-breached
  findings, made idempotent with `Store.MarkNotified`.
- A repo that failed to scan is never treated as "all findings fixed": `RecordFindings`
  only closes findings of repos listed as scanned.

## Shared infrastructure

- `httpx.Client`: retries with jittered exponential backoff, `Retry-After`,
  `X-RateLimit-Reset`, per-host concurrency, JSON helpers. Plugins must use it.
- `httpx.Cache`: TTL'd on-disk cache; a nil cache is valid and disables caching.
- `gitx.Runner`: runs `git` with a minimal environment and non-interactive SSH.
- `secret.Resolve(env, file)`: the only way to read secrets.

## Testing

- Every port has a contract kit; every adapter must run it (`storetest.Run`, `sourcetest.RunVuln`, ...).
- `store/memstore` is the reference store and the store used by core unit tests.
- Sources are tested against recorded responses with `httptest`; no live network in
  `go test ./...` (live tests use `-tags=live`).
- Reports and Slack payloads use golden files (`go test ./... -update` rewrites them).
