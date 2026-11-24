# Heimdall

Heimdall watches every repository in your GitHub orgs, users or listed repos,
reads dependency manifests on the default (or configured) branch, checks them
and the declared language runtimes against vulnerability and end-of-life data,
and tells you what to upgrade, through reports, Slack and an MCP server for AI agents.

Status: **MVP wired end to end** (Go ecosystem, OSV + endoflife, GitHub token/App/SSH,
Postgres, asynq + Valkey, Slack webhook, React UI). See [docs/PLAN.md](docs/PLAN.md) for what is next.
See [docs/PLAN.md](docs/PLAN.md).

## Build

Requires Go 1.26+.

```bash
make build      # bin/heimdall
make check      # go vet + go test -race
```

The PostgreSQL store contract runs only when a test database is given
(each test uses its own schema and drops it):

```bash
HEIMDALL_TEST_PG_DSN="postgres://localhost:5432/heimdall_test?sslmode=disable" make test-pg
```

## Use

```bash
cp configs/heimdall.example.yaml heimdall.yaml   # edit targets and auth profiles
export GITHUB_TOKEN=...                          # or a GitHub App / SSH profile
export HEIMDALL_PG_DSN="postgres://heimdall:***@localhost:5432/heimdall?sslmode=disable"
bin/heimdall db migrate
bin/heimdall config validate
bin/heimdall repos                               # check credentials and filters
bin/heimdall scan --fail-on HIGH                 # one scan in this process; exit 1 on findings
```

Web UI + API (jobs and the scheduler run in the same process; with `jobs.type: asynq`
you can scale out with `heimdall worker` and run `serve --api-only`):

```bash
make web build
export HEIMDALL_MASTER_KEY="$(openssl rand -base64 32)"   # to store secrets entered in the UI
bin/heimdall serve                                         # http://127.0.0.1:8080
```

Quick local try without Postgres/Valkey: set `store: { type: memory }` and `jobs: { type: inline }`.

## Docs

- [docs/PLAN.md](docs/PLAN.md): MVP scope and delivery plan
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, dependency rule, plugin mechanics
- [docs/WEBAPP.md](docs/WEBAPP.md): web app design (UI, REST API, job queue, encrypted secrets)
- [docs/PLUGINS.md](docs/PLUGINS.md): how to add a VCS, auth method, ecosystem, source, notifier, report or store
