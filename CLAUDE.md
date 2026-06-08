# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Swift Package providing reusable Hummingbird 2.x middleware components for the Mendesky platform. This is a library package (not an executable) consumed by other services.

## Build & Test Commands

```bash
swift build              # Build the package
swift test               # Run all tests
swift test --filter MiddlewareTests/testName  # Run a single test
swift package resolve    # Resolve dependencies
```

Requires Swift 6.0+ and macOS 15+.

## Dependencies

- **Hummingbird 2.x** — HTTP server framework (provides `MiddlewareProtocol`, `RouterMiddleware`, `Request`, `Response`)
- **jose-swift 6.x** — JWE/JWK token handling for bearer token authentication
- **swift-openapi-runtime 1.x** — OpenAPI `ClientMiddleware` protocol for outbound HTTP interception

## Architecture

The package exposes a single `Middleware` module with two categories of middleware:

### Server-side (Hummingbird `MiddlewareProtocol` / `RouterMiddleware`)

- **BearerTokenAuthenticationMiddleware** — JWE-based auth that decrypts bearer tokens using JWK keys loaded from environment variables (`MENDESKY_AUTH_RECIPIENT_JWK`, `MENDESKY_AUTH_RECIPIENT_JWK_PATH`, `MENDESKY_AUTH_SENDER_JWK`, `MENDESKY_AUTH_SENDER_JWK_PATH`, `MENDESKY_AUTH_PASSWORD`). Supports path whitelisting and auto-skips OPTIONS requests.
- **DynamicCORSMiddleware** — Generic over `RequestContext`; origin-whitelist-based CORS with preflight handling.
- **LoggingMiddleware** — Debug-level request/response logging.
- **ProxyHeaderReceiverMiddleware** — Captures specified inbound headers into a `TaskLocal`-backed `SetHeaders.Management` store for downstream forwarding.

### Client-side (OpenAPI `ClientMiddleware`)

- **AccessTokenMiddleware** — Forwards the `Authorization` header from the current request to outbound client calls.
- **ProxyHeaderSenderMiddleware** — Reads headers from `SetHeaders.Management` (populated by `ProxyHeaderReceiverMiddleware`) and attaches them to outbound requests. These two form a pair for header proxying across service-to-service calls.

### Key pattern: Header proxying

`ProxyHeaderReceiverMiddleware` (server) + `ProxyHeaderSenderMiddleware` (client) work together via the `SetHeaders` `TaskLocal` to forward headers from an inbound request through to outbound service calls within the same async task.

<!-- BEGIN brain-link (managed by /link-brain) -->

## brain vault 整合

此專案已 link 到個人 wiki vault `~/brain`（slug: `mendesky-middleware`）。完整協議見 `~/brain/_schema/WIKI_SCHEMA.md` §11。

### 寫入規則（你唯一能改的位置）

- 唯一可寫路徑：`~/brain/raw/projects/mendesky-middleware/YYYY-MM-DD.md`
- 同一天 append 到同一檔，不另開新檔。
- 條目格式：
  ```
  ## [HH:MM] <topic>

  - bullet
  - bullet
  ```
- 何時值得寫：本 session 有「未來會想回頭看」的決策、bug 根因、API 變動、會議結論、踩到的非顯而易見的雷。**不要把所有 commit 訊息照抄一次**——那是 git log 的工作。
- Commit 寫入時：在 brain 那個 repo commit，prefix `[claude]` / `[codex]` / `[gemini]`，message 必須含 slug，例如：`[claude] log: mendesky-middleware YYYY-MM-DD session`。

### 讀取規則

- 可讀：`~/brain/wiki/` 任何頁、`~/brain/_meta/index.md`。需要找既有研究、概念、過往決策時，先看 index。
- 不可讀：其他專案的 `raw/projects/<other>/`（用 wiki 頁取得跨專案知識，不直接挖別人的原始筆記）。

### 絕對禁止

- 寫入 `~/brain/wiki/`、`~/brain/_meta/`、`~/brain/_schema/`、其他專案的 raw。
- 從本專案觸發 brain ingest——ingest 由 user 在 brain 那邊主動跑。
- 刪改 `raw/projects/mendesky-middleware/` 內既有檔案——raw 是 immutable，新進度 append 到當日檔即可。

<!-- END brain-link -->
