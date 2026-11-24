# Heimdall — Plan triển khai MVP

> Spec gốc: [`heimdall-bootstrap-prompt.md`](../heimdall-bootstrap-prompt.md). File này là bản **đã chốt phạm vi** cho MVP; phần nào spec có mà ở đây không nhắc → để sau MVP.

## 1. Phạm vi MVP (đã chốt)

| Hạng mục | MVP | Để sau |
|---|---|---|
| Ecosystem | **Go** (go.mod, go.work) qua `golang.org/x/mod/modfile` + runtime Go | npm, rubygems (đánh giá osv-scalibr lúc đó) |
| Vuln source | **OSV.dev** (1 source chung, đã gom GHSA + Go vulndb) | ghsa, govulndb, nvd, kev, epss, … |
| Runtime EOL | endoflife.date (`go`) + OSV `stdlib`/`toolchain` | node, ruby |
| Dedup | Gộp advisory theo ID + aliases; finding ID ổn định → không ghi 2 lỗi, không notify lặp | — |
| VCS / auth | GitHub: **token**, **GitHub App**, **SSH**; GHES qua `base_url` | GitLab, Bitbucket… |
| Target | org, user cá nhân, **1 repo URL cụ thể**, mỗi target gắn 1 **auth profile** | — |
| Branch | default branch hoặc branch khai báo trong config | — |
| Config | YAML **hoặc** JSON (viper) + env `HEIMDALL_*` | — |
| Chạy | **CLI** + **`heimdall serve`** (web UI + API + scheduler + worker trong 1 binary); lịch 1 ngày / 3 ngày đặt trên UI hoặc cron ngoài gọi CLI | K8s manifest, GH Action |
| Web UI | React + TS SPA nhúng vào binary, không login (chạy nội bộ), thêm target/auth profile (secret mã hoá trong Postgres), trigger/huỷ scan, xem tiến độ trực tiếp. Thiết kế: [WEBAPP.md](WEBAPP.md) | SSO/RBAC |
| Store | **PostgreSQL** (pgx, schema riêng, migration nhúng, đã xong) + `memory` cho chạy local | — (đã quyết định bỏ SQLite) |
| Report | markdown + json | html, csv, sarif, cyclonedx |
| Notify | Slack **Incoming Webhook** (chỉ gửi diff: new / fixed / SLA) | Slack bot token (thread, update), Teams, Jira… |
| MCP | Server stdio: tool đọc + agent-as-source (`submit_*`) + `notify_user` (§6) | http transport, `register_source`, `suppress_finding` |
| Code scan | — | semgrep, gosec, gitleaks… |

## 2. Config mẫu (target + auth profile)

```yaml
auth_profiles:
  gh-app:  { type: app,   app_id_env: HEIMDALL_GH_APP_ID, private_key_file: /secrets/gh-app.pem }   # installation tự dò theo owner
  gh-pat:  { type: token, token_env: GITHUB_TOKEN }
  gh-ssh:  { type: ssh,   key_file: ~/.ssh/id_ed25519, known_hosts: ~/.ssh/known_hosts }

targets:
  - { kind: org,  name: remitano, auth: gh-app, filters: { include: ["*"], exclude: ["sandbox-*"], skip_archived: true, skip_forks: true } }
  - { kind: user, name: some-dev, auth: gh-pat }
  - { kind: repo, url: git@github.com:remitano/foo.git, auth: gh-ssh, branch: develop }
  - { kind: repo, url: https://github.com/remitano/bar, auth: gh-pat }
  # SSH không list được repo → org dùng ssh phải có list_auth (token/app) hoặc danh sách repo tĩnh:
  - { kind: org,  name: remitano, auth: gh-ssh, list_auth: gh-pat }

private_modules: ["github.com/remitano/*"]
sources: { osv: { enabled: true }, endoflife: { enabled: true, eol_warning_days: 90 } }
policy:  { sla_days: { CRITICAL: 7, HIGH: 30, MEDIUM: 90 } }
notify:  { slack: { enabled: true, webhook_env: SLACK_WEBHOOK_URL } }
store:   { type: postgres, dsn_env: HEIMDALL_PG_DSN, schema: heimdall }
cache:   { dir: ~/.cache/heimdall, ttl: 24h }
```
Secret chỉ qua env/file, không bao giờ inline hay qua CLI arg.

## 3. Thiết kế lõi

### 3.1 Pipeline
```
targets → resolve repos (Provider) → HEAD sha (skip nếu sha + source data không đổi)
       → list files → match go.mod/go.work/runtime files → parse (DependencyGraph + Runtimes)
       → OSV querybatch (batch toàn org, cache vuln detail) → dedup → recommend
       → store (upsert findings, ScanRun) → diff vs run trước → report + Slack (chỉ diff)
```

### 3.2 Fetch code
- **token / app**: Git Trees API `?recursive=1` + Contents API (chỉ tải file manifest). `truncated: true` → fallback sparse clone.
- **ssh**: giữ **bare mirror cache** trong `cache.dir`, mỗi lần chạy `git fetch --depth 1 <branch>` rồi sparse-checkout manifest → rẻ khi chạy hàng ngày.

### 3.3 Dedup (yêu cầu "trùng thì bỏ qua")
1. **Giữa các advisory**: union-find trên `{id} ∪ aliases` (GHSA ↔ CVE ↔ GO-xxxx). Canonical ID ưu tiên `GO-` > `GHSA-` > `CVE-`. Giữ union `sources`.
2. **Finding ID** = `sha256(repo_full_name | manifest_path | purl không version | canonical_advisory_id)` — **không chứa version**, nên bump patch mà vẫn dính lỗi thì vẫn là cùng finding (giữ `FirstSeen`, SLA chạy tiếp).
3. **Giữa các lần scan**: store upsert theo Finding ID; Slack chỉ gửi `new`, `fixed`, `sla_breached` → không spam hằng ngày.

### 3.4 Recommend (Go)
Fixed version nhỏ nhất > current cho mỗi advisory → lấy max → bump type patch/minor/major/no-fix. Transitive (`// indirect`) → gợi ý `go get mod@ver`; `replace` local path → bỏ qua, ghi `unresolvable`; module private → không query public.

### 3.5 Kiến trúc & quy ước mở rộng (bắt buộc cho mọi code MVP)
MVP chỉ gọn về **tính năng**. Kiến trúc thì làm đủ chuẩn ngay từ đầu, để thêm VCS, ecosystem, source hay notifier mới chỉ cần **thêm 1 package**, không phải sửa core.

**Ports & adapters (dependency rule):**
```
cmd/heimdall ──► internal/app (wiring) ──► internal/core (pipeline, dedup, diff)
                                               │ chỉ phụ thuộc interface (ports)
       ports:  vcs · ecosystem · runtime · source · store · notify · report
                                               ▲ implement
       adapters: vcs/github · ecosystem/gomod · source/osv · source/endoflife
                 store/postgres · notify/slackwebhook · report/{markdown,json} · mcpserver
       nền:   model (data thuần, không import gì) · registry · config · httpx · gitx
```
- `model` không import package nội bộ nào khác. `core` không import adapter. Các adapter không import lẫn nhau.
- Rule này được `internal/archtest` kiểm tra trong `go test ./...`.

**Plugin = 1 package tự đăng ký:**
- Mỗi adapter gọi `registry.Register[source.VulnSource]("osv", factory)` trong `init()`.
- `internal/app/plugins.go` blank-import các adapter được build vào binary.
- `factory(cfg config.Raw, deps Deps)` decode config **riêng của plugin** vào struct của nó và chạy `Validate()`. Core không biết field config của từng plugin.
- Thêm plugin = 1 package + 1 dòng import + 1 block config.

**Interface nhỏ + capability tùy chọn:**
- Interface chính tối thiểu như spec §3.
- Khả năng phụ là interface riêng (`HealthChecker`, `Closer`, `BatchSizer`). Core nhận biết qua type assertion, nên plugin không phải implement method rỗng.

**Quy ước code:**
- Dependency truyền qua constructor. Không có global state, trừ registry.
- `context.Context` ở mọi I/O.
- Lỗi wrap bằng `%w` + sentinel (`ErrNotFound`, `ErrRateLimited`, `ErrUnsupported`).
- `slog` gắn attr `component`, `plugin`, `repo`.
- Mỗi ecosystem có `version.Comparator` riêng. Định danh package luôn là **PURL**.
- Hạ tầng dùng chung: `internal/httpx` (retry, backoff, rate-limit, cache đĩa) và `internal/gitx` (bọc lệnh `git`). Plugin không tự viết lại.

**Contract test kit:**
- Mỗi port có bộ test dùng lại được: `vcstest.Run`, `sourcetest.Run`, `storetest.Run`, `notifytest.Run`.
- Plugin mới chỉ cần gọi kit là chứng minh đúng contract, không phải đọc lại core.

**Docs:** `docs/ARCHITECTURE.md` (sơ đồ + dependency rule) và `docs/PLUGINS.md` (checklist thêm VCS / ecosystem / source / notifier / report).

## 4. Chia việc cho agent (song song)

**Phase 0 — Contracts (làm tuần tự, 1 agent, phải merge trước):**
`go.mod` (`go 1.26`), layout thư mục, `internal/model`, mọi interface (`vcs.Provider`, `ecosystem.Ecosystem`, `source.VulnSource`, `source.RuntimeSource`, `store.Store`, `notify.Notifier`), `internal/registry`, `internal/config` (YAML/JSON + targets + auth profiles), CLI skeleton (cobra), `internal/app` wiring, `internal/httpx`, `internal/gitx`, contract test kit cho từng port, `internal/archtest` (kiểm tra dependency rule) + golangci-lint, `docs/ARCHITECTURE.md` + `docs/PLUGINS.md` (§3.5). Sau Phase 0 interface **đóng băng**.

**Phase 0b — Contracts cho web (1 agent, merge trước Phase 1):** `internal/service` (interface + memstore-backed impl), port `internal/jobs` (Queue), `secret.Resolver` trong `plugin.Deps`, migration `0002_webapp.sql`, `api/openapi.yaml` bản đầu, mở rộng `archtest` cho `service`/`api`/`mcpserver`. Chi tiết: [WEBAPP.md](WEBAPP.md).

**Phase 1 — 6 agent song song, mỗi agent 1 worktree/branch, không đụng file của nhau:**

| Track | Package | Nội dung | Done khi |
|---|---|---|---|
| **A. VCS GitHub** | `internal/vcs/github`, `internal/auth` | token + App (JWT RS256, auto-discover installation, refresh token) + SSH (bare mirror, sparse checkout); target org/user/repo URL; filters; GHES | test `httptest` + test SSH với repo local; `heimdall repos` chạy được |
| **B. Go ecosystem + runtime** | `internal/ecosystem/gomod`, `internal/runtime` | go.mod/go.work (require/indirect/replace/exclude/pseudo/+incompatible/private), runtime từ go directive, toolchain, `.go-version`, `.tool-versions`, Dockerfile `FROM golang`, CI `setup-go`; cờ inconsistency | fixture tests; `scan --dry-run` in inventory |
| **C. Sources + dedup + recommend** | `internal/source/osv`, `internal/source/endoflife`, `internal/recommend`, `internal/core/dedup` | OSV querybatch (≤1000, next_page_token, cache), stdlib/toolchain, endoflife go; dedup union-find; recommend | contract test với recorded response, golden test |
| **D. Report + Slack** | `internal/report`, `internal/notify/slackwebhook` | md/json report (store Postgres đã xong ở Phase 0); Slack webhook (Block Kit, chỉ diff, SLA) | golden test report + Slack payload |
| **E. Web backend** | `internal/api`, `internal/jobs/postgres`, `internal/jobs` (worker, scheduler), `internal/secretstore`, `internal/webui`, lệnh `serve`/`worker` | REST theo OpenAPI, SSE, CSRF/audit middleware, job queue SKIP LOCKED + lease, scheduler leader-lock, envelope encryption | test API khớp OpenAPI; test queue/scheduler trên Postgres thật |
| **F. Web UI** | `web/` | React + TS: Dashboard, Findings, Repo detail, Targets (preview), Auth profiles, Scans/Jobs (log SSE), Settings; mock API bằng MSW theo OpenAPI | Vitest + Playwright e2e trên luồng thêm target → scan → xem finding |

**Phase 2 — Integration (1 agent):** `internal/core` pipeline nối A–F (worker gọi pipeline, UI chạy trên API thật), `heimdall scan`, exit code `--fail-on`, e2e test với fixture repo + một lần chạy thật read-only lên org remitano.

**Phase 3 — MCP + AI agent (1 agent):** xem §6.

Ước lượng: Phase 0 ✅ → Phase 0b ~1 ngày → Phase 1 song song ~3–4 ngày (E/F dài nhất) → Phase 2 ~1–2 ngày → Phase 3 ~1 ngày.

## 5. Quality bar
- `go test ./...` không gọi mạng thật; live test sau `-tags=live`.
- `go vet`, `golangci-lint`, `-race`.
- Source lỗi → đánh dấu unhealthy trong run, chạy tiếp, hiện trong report + Slack.
- Commit nhỏ, không có AI attribution trong commit/PR.

## 6. MCP: AI agent là một nguồn + notify

Ý tưởng: AI agent được coi như **một `VulnSource` tên `agent`**. Agent tự đi nghiên cứu lib (changelog, issue, advisory mới chưa vào OSV, dấu hiệu lib bị bỏ rơi/bị chiếm quyền), rồi ghi kết quả ngược vào Heimdall qua MCP. Kết quả đó đi qua **cùng pipeline dedup/store/notify** như OSV.

### 6.1 Tools (`heimdall mcp --transport stdio`)
| Nhóm | Tool | Ghi? |
|---|---|---|
| Đọc | `list_targets`, `list_repos`, `get_inventory(repo?)` (danh sách lib + version + repo đang dùng), `get_findings(filter)`, `get_finding(id)`, `get_upgrade_plan(repo)`, `get_runtime_status`, `diff_scans`, `list_sources`, `get_analysis_queue()` (lib nên phân tích: mới xuất hiện, direct dep, dùng ở nhiều repo, lâu chưa phân tích) | không |
| Scan | `scan_target`, `scan_repo` (async) + `get_scan_status` | không (chỉ ghi kết quả scan) |
| Nguồn agent | `submit_advisory(osv_json, evidence_urls[], confidence)` — advisory mới theo **OSV schema** | có |
| Nguồn agent | `submit_analysis(purl, verdict, summary, evidence_urls[], recommended_version?)` — nhận định về lib (vd: `abandoned`, `suspicious-release`, `safe-to-bump`, `breaking-change`) | có |
| Notify | `notify_user(title, body, severity, refs[])` → đi qua `Notifier` (Slack), có routing + dedup | có |

### 6.2 Luật an toàn
- Tool ghi tắt mặc định, bật bằng `--allow-agent-writes` / `--allow-notify`.
- Dữ liệu agent luôn gắn `source=agent`, `verified=false`, kèm evidence URL bắt buộc. Report và Slack hiển thị rõ nhãn "AI chưa xác minh". Khi OSV/GHSA ra advisory trùng alias thì gộp lại (dedup §3.3) và đánh dấu `verified`.
- Agent **không** được suppress finding và không đổi config. Không nhận secret.
- `notify_user`: dedup theo hash nội dung + refs, rate limit (vd ≤ 20 tin/ngày), mọi lần gọi đều ghi audit log.

### 6.3 Prompts (expose dạng MCP prompt + file trong `prompts/`)
- `daily-scan.md`: scan → diff → triage lỗi mới (CRITICAL/HIGH, EOL) → `notify_user` gửi digest ngắn.
- `analyze-library.md`: lấy `get_analysis_queue` → với từng lib: đọc changelog/release, advisory, issue bảo mật, tình trạng bảo trì, bump có breaking không → `submit_analysis` / `submit_advisory` kèm bằng chứng → chỉ `notify_user` khi có điều mới, đáng hành động.
- `refresh-intel.md`: kiểm tra phân tích cũ (quá N ngày, hoặc lib vừa ra version mới) → cập nhật lại.

## 7. Câu hỏi còn mở
1. ~~Parser~~ → **đã chốt: `golang.org/x/mod/modfile`** (sau interface `Ecosystem`; osv-scalibr xét lại khi thêm npm/Ruby).
2. ~~Slack~~ → **đã chốt: chỉ webhook** trong MVP; bot token là một `Notifier` plugin riêng sau này.
3. ~~Go toolchain~~ → **đã chốt: Go 1.26** (`go 1.26` trong go.mod).
