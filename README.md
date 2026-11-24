# Heimdall

Heimdall watches every repository in your GitHub orgs, users or listed repos,
reads dependency manifests on the default (or configured) branch, checks them
and the declared language runtimes against vulnerability and end-of-life data,
and tells you what to upgrade, through reports, Slack and an MCP server for AI agents.

Status: **Phase 0 (skeleton)**. Interfaces, config, plugin registry and CLI
skeleton are in place; the PostgreSQL store is done; other adapters (GitHub, Go parser, OSV, Slack) come next.
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
export HEIMDALL_PG_DSN="postgres://heimdall:***@localhost:5432/heimdall?sslmode=disable"
bin/heimdall db migrate
bin/heimdall config validate
bin/heimdall plugins
```

## Docs

- [docs/PLAN.md](docs/PLAN.md): MVP scope and delivery plan
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, dependency rule, plugin mechanics
- [docs/WEBAPP.md](docs/WEBAPP.md): web app design (UI, REST API, job queue, encrypted secrets)
- [docs/PLUGINS.md](docs/PLUGINS.md): how to add a VCS, auth method, ecosystem, source, notifier, report or store
