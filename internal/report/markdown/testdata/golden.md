# Heimdall scan report — run #7

- **Generated:** 2026-01-02T03:04:05Z
- **Status:** ✅ succeeded
- **Started:** 2026-01-02T03:04:05Z
- **Duration:** 1m30s
- **Repos scanned:** 1 · **failed:** 0

## Source health

| Source | Status | Calls | Duration | Error |
|---|---|---:|---:|---|
| osv | ✅ healthy | 1 | 0s |  |

## Summary

| Severity | Findings |
|---|---:|
| 🔴 CRITICAL | 0 |
| 🟠 HIGH | 1 |
| 🟡 MEDIUM | 0 |
| 🔵 LOW | 0 |
| ⚪ UNKNOWN | 0 |
| **Total** | **1** |

- **Known exploited (CISA KEV):** 0
- **Malicious packages:** 0

## New since previous run

Run #6 → #7: **1 new**, 0 fixed, 0 still open.

| Repo | Package | Current → Recommended | Bump | Severity | Advisory |
|---|---|---|---|---|---|
| acme/api | golang.org/x/net | v0.20.0 → v0.23.0 | minor | 🟠 HIGH | [GO-2024-2687](https://osv.dev/vulnerability/GO-2024-2687) |

## acme/api

[repository](https://github.com/acme/api) · ref main · commit 0123456789ab · 1 findings

### Upgrade plan

| Package | Manifest | Current → Recommended | Bump | Severity | Advisories |
|---|---|---|---|---|---|
| golang.org/x/net | go.mod | v0.20.0 → v0.23.0 | minor | 🟠 HIGH | [GO-2024-2687](https://osv.dev/vulnerability/GO-2024-2687) |

### Runtimes

| Runtime | Version | Declared in | Cycle | Support | EOL date | Latest patch | Latest cycle |
|---|---|---|---|---|---|---|---|
| go | 1.24 | go.mod (go directive) | 1.24 | 🔴 **EOL** | 2026-02-11 | 1.24.13 | 1.26 |

