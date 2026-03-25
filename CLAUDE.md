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
