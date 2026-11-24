# Heimdall

Heimdall watches every repository in your GitHub orgs, users or listed repos,
reads dependency manifests on the default (or configured) branch, checks them
and the declared language runtimes against vulnerability and end-of-life data,
and tells you what to upgrade, through reports, Slack and an MCP server for AI agents.

Status: **MVP wired end to end** (Go, Node.js and Ruby — multi-language repos in one pass; OSV + endoflife, GitHub token/App/SSH,
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

## MCP

`heimdall mcp` lets AI agents (Claude Code, Claude Desktop, any MCP client) read scan
results, research the libraries in use, feed findings back as an unverified `agent` source
and notify the team. Claude Code / Claude Desktop config (`.mcp.json` or
`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "heimdall": {
      "command": "/path/to/bin/heimdall",
      "args": ["mcp", "--transport", "stdio", "-c", "/path/to/heimdall.yaml"],
      "env": { "HEIMDALL_PG_DSN": "postgres://..." }
    }
  }
}
```

Or over HTTP: `bin/heimdall mcp --transport http` serves `http://127.0.0.1:8090/mcp`
(`--listen` / `mcp.listen`; no authentication, keep it on loopback).

- **Read tools**: `list_targets`, `list_repos`, `get_inventory`, `get_analysis_queue`,
  `get_analyses`, `get_findings`, `get_finding`, `get_upgrade_plan`, `get_runtime_status`,
  `list_runs`, `diff_scans`, `list_sources`, `get_scan_status`.
- **Gated tools**, off by default, enabled by a flag or the config (flags only enable):
  `scan_target` / `scan_repo` (`--allow-scan`, `mcp.allow_scan`; they queue jobs that
  `heimdall serve` or `heimdall worker` executes, `mcp` runs no workers),
  `submit_advisory` / `submit_analysis` (`--allow-agent-writes`, `mcp.allow_agent_writes`),
  `notify_user` (`--allow-notify`, `mcp.allow_notify`; deduplicated, at most
  `mcp.notify_daily_limit` messages per UTC day, default 20). Disabled tools stay listed and
  answer with the flag that enables them.
- Agent advisories use ids `HEIMDALL-AGENT-<year>-<n>` (public ids go in `aliases`), need
  https evidence and a confidence, and are always stored unverified; they merge with the
  public record once OSV publishes one sharing an alias.
- Every tool call is written to the audit log as `mcp:<client name>`. No tool returns secrets.
- Resources: `heimdall://runs/latest`, `heimdall://config` (redacted). Prompts: the routines
  in [prompts/](prompts) (`daily-scan`, `analyze-library`, `refresh-intel`).
- The inventory, analysis queue, agent writes and `notify_user` need a store implementing
  agent intelligence (`store.Intel`): currently only `memory`; the Postgres store does not
  implement it yet, so with Postgres these tools answer "unavailable".

## Docs

- [docs/PLAN.md](docs/PLAN.md): MVP scope and delivery plan
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): layers, dependency rule, plugin mechanics
- [docs/WEBAPP.md](docs/WEBAPP.md): web app design (UI, REST API, job queue, encrypted secrets)
- [docs/PLUGINS.md](docs/PLUGINS.md): how to add a VCS, auth method, ecosystem, source, notifier, report or store
