# Heimdall Web App — Thiết kế

> Quyết định đã chốt: UI là **React + TypeScript SPA** nhúng vào binary Go · **không có login** (chỉ chạy nội bộ) · **nhập secret trên UI**, lưu mã hoá trong Postgres · background job dùng **asynq + Valkey** · cache repo trong `workspace.dir` · làm **song song** với các track Phase 1.
>
> Hợp đồng đã đóng băng ở Phase 0b: [`api/openapi.yaml`](../api/openapi.yaml), `internal/service` (interface), `internal/store/catalog.go` (+ `storetest.RunCatalog`), `internal/jobs` (+ `jobstest`), `internal/core.Scanner`, migration `0002_webapp.sql`.

## 1. Mục tiêu

- Theo dõi: dashboard tổng quan, danh sách finding, upgrade plan theo repo, runtime EOL, lịch sử scan, sức khoẻ source.
- Điều khiển: trigger scan (toàn bộ / 1 target / 1 repo), huỷ scan, xem tiến độ trực tiếp.
- Quản lý: thêm/sửa/tắt target (org, user, repo URL), auth profile (kèm secret), lịch chạy (hằng ngày, 3 ngày/lần…), suppress finding có lý do + hạn.
- CLI, web và MCP dùng **chung một lớp service**: không có logic nào chỉ tồn tại ở UI.

Ngoài phạm vi: multi-tenant, phân quyền theo user (vì không có login), sửa code/mở PR từ UI.

## 2. Kiến trúc chạy

Vẫn **một binary**. Có thêm 2 lệnh:

```
heimdall serve   = HTTP server (REST API + SPA nhúng + SSE)
                 + scheduler (chỉ 1 replica làm leader, qua pg_try_advisory_lock)
                 + worker pool (chạy scan job)
heimdall worker  = chỉ worker pool, để scale ngang khi nhiều repo
```

```
 Browser (React SPA) ──HTTP/JSON + SSE──► internal/api ─┐
 AI agent ───────────────MCP──────────► internal/mcpserver ├─► internal/service ─► core pipeline ─► ports/adapters
 Terminal ───────────────────────────► internal/cli ─────┘          │
                                                                   ├─► jobs (asynq + Valkey) ◄── scheduler
                                                                   └─► store (Postgres)          ▲
                                                       worker pool ── nhận job ── chạy pipeline ─┘
```

- **`internal/service`**: application services (`Targets`, `AuthProfiles`, `Scans`, `Findings`, `Schedules`). API, MCP và CLI là lớp mỏng phía trên: chỉ parse input, gọi service và trả output.
- **Trigger scan = tạo job**, không chạy trực tiếp trong HTTP request. Worker nhận job, chạy pipeline, ghi tiến độ vào `job_events`. UI đọc tiến độ qua SSE.
- Chạy cron bên ngoài vẫn được: `heimdall scan` chỉ là "tạo job rồi chạy luôn trong process".

Dependency rule bổ sung (archtest sẽ kiểm):
`api`, `mcpserver`, `cli` → `service` → `core`, ports. `api` và `mcpserver` không import adapter, không import lẫn nhau.

## 3. Dữ liệu (migration `0002_webapp.sql`)

Postgres là **nguồn sự thật**. File YAML/JSON thành **bootstrap**: khi start, target và auth profile trong file được đồng bộ vào DB với `origin = 'config'` và **chỉ đọc trên UI** (sửa thì sửa file), để không có hai nơi cùng sửa một thứ. Những gì tạo trên UI có `origin = 'ui'`.

| Bảng | Cột chính | Ghi chú |
|---|---|---|
| `secrets` | id, kind, ciphertext, nonce, wrapped_dek, kek_id, fingerprint, created_at, rotated_at | Không bao giờ trả plaintext qua API |
| `auth_profiles` | id, name (unique), type, options jsonb (không chứa secret), secret_id → secrets, origin | `options` chỉ giữ thứ không nhạy cảm (app_id, known_hosts…) |
| `targets` | id, kind, provider, base_url, owner, name, url, branch, auth_profile_id, list_auth_profile_id, filters jsonb, schedule, next_run_at, enabled, origin, created_at, updated_at | Index `(enabled, next_run_at)` cho scheduler |
| `scan_jobs` | id, target_id (null = tất cả), repo ('' = cả target), branch, auth_profile, trigger, status (`queued`/`running`/`succeeded`/`failed`/`canceled`), run_id, attempts, requested_by, error, created_at, started_at, finished_at | **Unique partial index** `(coalesce(target_id,0), repo)` WHERE status IN ('queued','running') → bấm trigger 2 lần không tạo 2 job |
| `repos` | full_name, target_id, data (model.Repo), last_listed_at, last_head_sha, last_scanned_at | Cache danh sách repo (§5b) |
| `suppressions` | finding_id, reason (bắt buộc), expires_at (bắt buộc), actor, created_at | Hết hạn thì mở lại finding |
| `job_events` | id, job_id, at, level, repo, message | Tiến độ cho SSE; dọn theo retention |
| `audit_log` | id, at, actor, action, object_type, object_id, details jsonb | Mọi thao tác ghi (UI, API, MCP) |

## 4. Secret nhập trên UI

- **Envelope encryption**: mỗi secret có một DEK ngẫu nhiên (AES-256-GCM). DEK được mã hoá bằng **KEK** lấy từ `HEIMDALL_MASTER_KEY` (base64, 32 byte) hoặc `master_key_file`. KEK không bao giờ nằm trong DB.
- Có `kek_id` để xoay khoá: `heimdall secrets rotate-kek` chỉ mã hoá lại DEK, không đụng dữ liệu.
- API **chỉ ghi, không đọc**. Response chỉ trả `fingerprint` (8 ký tự đầu sha256) và 4 ký tự cuối, để nhận diện. Muốn đổi secret thì ghi đè.
- Plaintext chỉ tồn tại trong bộ nhớ worker, lúc dựng credentials. Không log, không đưa vào job_events.
- Mở rộng: thêm `secret.Resolver` vào `plugin.Deps`. Auth plugin đọc secret qua `token_env` / `token_file` / **`token_ref`** (id trong bảng `secrets`). Sau này thêm Vault/AWS Secrets Manager chỉ cần thêm một resolver.
- Thiếu master key → `serve` vẫn chạy, nhưng tính năng nhập secret trên UI bị tắt và báo rõ trên UI.

## 5. Job queue & scheduler (asynq + Valkey)

- Port `internal/jobs` (`Backend`: Enqueue / Cancel / Run). Adapter:
  - **`jobs/asynq`** cho production: [asynq](https://github.com/hibiken/asynq) chạy trên **Valkey** (tương thích giao thức Redis).
  - **`jobs/inline`** (in-process) cho CLI và test. Đây là bản tham chiếu, đã pass `jobstest`.
- **Queue chỉ chở job ID.** Bản ghi job (phạm vi, trạng thái, tiến độ, lỗi) nằm trong `scan_jobs`/`job_events` ở Postgres. Vì vậy UI và audit không phụ thuộc thời gian lưu của Valkey, và đổi backend không mất lịch sử.
- **Không trùng job**:
  - Postgres có unique index cho job đang chạy theo phạm vi (target, repo), nên bấm "Scan" hai lần chỉ tạo một job.
  - asynq dùng `TaskID = job-<id>`, nên enqueue lại cùng ID là no-op.
- **Retry / crash**: asynq tự retry khi worker chết (lease), tối đa 3 lần. Handler luôn đọc lại job và bỏ qua nếu job đã xong hoặc đã huỷ (idempotent).
- **Huỷ**: API đặt `status = canceled` rồi gọi `Backend.Cancel`. Với asynq đó là `Inspector.CancelProcessing`, ctx của handler bị huỷ; job còn trong hàng đợi thì bị xoá.
- **Scheduler**: không dùng `asynq.Scheduler`, vì lịch nằm trong DB và sửa được từ UI.
  - Mỗi phút: `Catalog.DueTargets(now)` → `Jobs.Trigger(trigger=schedule)` → tính `next_run_at` mới bằng parser cron (`robfig/cron/v3`).
  - Chạy nhiều replica vẫn an toàn nhờ chống trùng ở `CreateJob`. Chỉ một replica làm việc này nhờ lock Valkey (`SET NX PX`), các replica khác bỏ qua.
- **Hết hạn suppress**: cùng vòng lặp scheduler gọi `ExpiredSuppressions(now)` để mở lại finding và ghi audit.
- **Giám sát**: có thể bật Asynqmon (UI riêng của asynq) sau reverse proxy. Heimdall UI đã có trang Jobs riêng.
- Config:

  ```yaml
  jobs:
    type: asynq                     # inline (mặc định, không cần Valkey) | asynq
    addr_env: HEIMDALL_VALKEY_ADDR  # host:port; mật khẩu qua password_env
    password_env: HEIMDALL_VALKEY_PASSWORD
    db: 0
    concurrency: 4
    queue: heimdall
  ```

## 5b. Cache repo (không clone lại liên tục)

- `workspace.dir` (mặc định `~/.cache/heimdall/repos`) là thư mục cache nội dung repo giữa các lần scan:
  - **SSH / checkout**: mỗi repo giữ một **bare mirror** (`<dir>/<host>/<owner>/<name>.git`). Lần sau chỉ `git fetch --depth 1 <branch>` phần mới rồi sparse-checkout manifest, không clone lại.
  - **Token / App (API)**: file manifest tải về được cache theo **commit SHA** (`<dir>/<host>/<owner>/<name>/<sha>/…`). SHA không đổi thì đọc từ đĩa, không gọi API.
  - `workspace.prune_after` (mặc định 30 ngày) xoá mirror của repo lâu không scan.
- Danh sách repo của từng target được cache trong bảng `repos` (Catalog `UpsertRepos`/`ListRepos`). Trang Repos đọc bảng này, không gọi GitHub mỗi lần mở trang. Danh sách được làm mới ở mỗi lần scan target hoặc khi bấm "Refresh".
- Scan tăng dần: HEAD SHA (`MarkRepoScanned`) và dữ liệu source không đổi thì bỏ qua repo, trừ khi `force`.

## 6. REST API (`/api/v1`, đặc tả tại `api/openapi.yaml`)

Spec OpenAPI là hợp đồng giữa backend và UI. TS types sinh bằng `openapi-typescript`, nên UI và server không lệch nhau.

| Nhóm | Endpoint |
|---|---|
| Dashboard | `GET /dashboard` (đếm theo severity/trạng thái, xu hướng N ngày, runtime EOL, source unhealthy, job đang chạy) |
| Targets | `GET/POST /targets`, `GET/PATCH/DELETE /targets/{id}`, `POST /targets/preview` (liệt kê thử repo trước khi lưu) |
| Auth profiles | `GET/POST /auth-profiles`, `PATCH/DELETE /auth-profiles/{id}`, `PUT /auth-profiles/{id}/secret`, `POST /auth-profiles/{id}/test` |
| Repos | `GET /repos`, `GET /repos/{owner}/{name}` (finding, runtime, upgrade plan, lần scan cuối) |
| Findings | `GET /findings` (filter + **cursor pagination**), `GET /findings/{id}`, `POST /findings/{id}/suppress` (lý do + hạn bắt buộc), `DELETE /findings/{id}/suppress` |
| Scans | `GET /runs`, `GET /runs/{id}`, `GET /runs/{id}/diff?against=` |
| Jobs | `POST /jobs` (`{target_id}` / `{repo_url, auth_profile_id, branch}` / `{}` = tất cả), `GET /jobs`, `GET /jobs/{id}`, `POST /jobs/{id}/cancel`, `GET /jobs/{id}/events` (SSE) |
| Hệ thống | `GET /sources`, `GET /notifiers`, `POST /notifiers/{name}/test`, `GET /audit` |
| Vận hành | `GET /healthz`, `GET /readyz` (DB + migration), `GET /metrics` (Prometheus) |

- Dùng router `net/http` của stdlib (Go 1.22+ đã hỗ trợ method + path pattern), không thêm framework.
- Lỗi theo RFC 9457 (`application/problem+json`).
- Danh sách lớn dùng **keyset pagination** (theo `severity_rank, repo, id`), không dùng OFFSET, nên vẫn nhanh khi có hàng triệu finding.

## 7. UI (React SPA)

Stack: Vite · React · TypeScript · TanStack Query (cache/refetch) · TanStack Router · TanStack Table (bảng lớn, virtualized) · component library nhẹ (shadcn/ui + Tailwind) · Recharts (biểu đồ xu hướng).
Build ra `web/dist`, nhúng bằng `go:embed` trong `internal/webui`; SPA fallback về `index.html`.

| Trang | Nội dung | Thao tác |
|---|---|---|
| Dashboard | Thẻ đếm CRITICAL/HIGH/KEV/malicious, xu hướng mở/đóng, top 10 ưu tiên, runtime sắp EOL, source lỗi, job đang chạy | Trigger scan toàn bộ |
| Findings | Bảng lọc theo repo/severity/kind/status/KEV/mới từ ngày, tìm theo package/CVE | Xem chi tiết, suppress (lý do + hạn) |
| Finding detail | Advisory gộp (GHSA/CVE/GO), CVSS, nguồn, version hiện tại → đề xuất, bump type, lệnh nâng (`go get …`), lịch sử | Suppress / bỏ suppress |
| Repos | Danh sách repo, lần scan cuối, số finding theo severity | Scan riêng repo |
| Repo detail | Upgrade plan (mỗi package 1 dòng), runtime, manifest, lỗi scan | Scan lại, đổi branch |
| Targets | org / user / repo URL, auth profile, branch, lịch, bật/tắt; target từ config hiện nhãn "config" và chỉ đọc | Thêm (có bước **preview** liệt kê repo), sửa, tắt, xoá, scan ngay |
| Auth profiles | Tên, loại, fingerprint secret, dùng bởi target nào | Thêm, thay secret, **test kết nối** |
| Scans & Jobs | Lịch sử run, trạng thái, thời gian, diff giữa 2 run; job đang chạy có **log trực tiếp** (SSE) | Huỷ job, chạy lại |
| Settings | Source (health, lần refresh), notifier, audit log | Gửi thử Slack |

Yêu cầu chung: responsive, có dark mode, điều hướng bằng bàn phím, có trạng thái loading/empty/error rõ ràng, filter giữ trên URL (chia sẻ link được).

## 8. Bảo mật khi không có login

Không có login nghĩa là ai vào được mạng nội bộ đều thao tác được. Thiết kế giảm thiểu như sau:

- Mặc định chỉ listen `127.0.0.1:8080`. Muốn mở ra mạng phải chỉ định rõ `--listen 0.0.0.0:8080`, và log sẽ cảnh báo.
- **Khuyến nghị mạnh** đặt sau reverse proxy có SSO (oauth2-proxy, Cloudflare Access, VPN). Tuỳ chọn `trusted_user_header` (vd `X-Forwarded-Email`) để ghi đúng người thao tác vào audit log.
- Chống CSRF: mọi request ghi bắt buộc `Content-Type: application/json` + header `X-Heimdall-Request: 1`, không bật CORS. Trang web lạ không gửi được request ghi.
- Secret chỉ ghi, không đọc (§4). Không endpoint nào trả token, key hay DSN.
- Mọi thao tác ghi đều có audit log. Suppress bắt buộc có lý do + ngày hết hạn.
- Header bảo mật: CSP chặt (SPA tự host, không dùng CDN), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.

## 9. Cấu trúc thư mục bổ sung

```
api/openapi.yaml                 # hợp đồng REST
internal/service/                # application services (dùng chung CLI/API/MCP)
internal/core/                   # core.Scanner (pipeline) — implementation in Phase 2
internal/jobs/                   # port Backend + inline (reference) + asynq (Valkey) adapters
internal/service/                # + scheduler loop (due targets, expired suppressions)
internal/secret/                 # envelope encryption (KeyRing, Seal/Open/Rewrap), Resolver chain
internal/api/                    # HTTP handlers, middleware (CSRF, audit, problem+json), SSE
internal/webui/                  # go:embed web/dist + SPA fallback
web/                             # React app (Vite, TS)
internal/store/postgres/migrations/0002_webapp.sql
```

## 10. Test

- Service: unit test với `memstore` + fake queue.
- API: `httptest` + kiểm response khớp OpenAPI (kin-openapi validator).
- Jobs: `jobstest.Run` cho mọi backend; asynq chạy với Valkey thật khi có `HEIMDALL_TEST_VALKEY_ADDR`. Unique index của job: `storetest.RunCatalog` trên Postgres.
- Secretstore: mã hoá/giải mã, sai KEK thì lỗi, xoay KEK.
- UI: Vitest + Testing Library cho component; MSW mock API theo OpenAPI để UI làm song song khi backend chưa xong; Playwright e2e cho các luồng chính (thêm target → preview → scan → xem finding).
