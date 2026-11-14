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

- **BearerTokenAuthenticationMiddleware** — Authenticates bearer tokens by segment count: 5 segments = legacy JWE (decrypted with JWK keys from `MENDESKY_AUTH_RECIPIENT_JWK`, `MENDESKY_AUTH_RECIPIENT_JWK_PATH`, `MENDESKY_AUTH_SENDER_JWK`, `MENDESKY_AUTH_SENDER_JWK_PATH`, `MENDESKY_AUTH_PASSWORD`), 3 segments = signed RS256 `at+jwt` (see below). Supports path whitelisting and auto-skips OPTIONS requests. Status codes: 401 (bad/expired token, route not open to that caller), 403 `insufficient scope.` (delegated user scope), 400 (`operatorId` missing/mismatched; `.user` and `.delegatedUser` only). Never logs tokens; handler errors propagate unchanged. `init(validators:)` / `init(validators:accepting:)` read the trust and legacy-JWE env vars and log startup notices (signed tokens enabled/disabled, legacy JWE mode); `init(verification:validators:)` never reads `MENDESKY_ACCESS_TOKEN_TRUST` (JWE only).
- **Signed access tokens** (`Sources/Middleware/SignedAccessToken/`, `Sources/Middleware/ApplicationToken/`) — `AccessTokenTrust` (from `MENDESKY_ACCESS_TOKEN_TRUST` base64 JSON or `MENDESKY_ACCESS_TOKEN_TRUST_PATH` file, file wins; neither set = off) lists trusted issuers with `callerTypes` (`user` / `application` / `delegatedUser`), `actors` and public JWKs; invalid trust (two `user` issuers, delegatedUser without actors, duplicate issuer/`kid`, private fields, <2048-bit or non-RSA keys) or any old `MENDESKY_APP_TOKEN_*` variable (renamed; setting it fails startup) throws at startup. `SignedAccessTokenVerification` is the hardened verifier (fixed RS256, strict base64url/JSON, duplicate `alg` rejected, unverified `iss` only picks the key); `ApplicationTokenVerification` wraps it for the single-issuer, `sub_type: application` case. `RouteAcceptance` (`accepting: [.application(...), .delegatedUser(..., requiresScope:, actors:)]`; `acceptsApplication:` still works) opens routes to non-user callers; first-party users pass everywhere. Handlers read `Caller.current` (`CallerIdentity`: `.user` / `.application` / `.delegatedUser`; use `if case`, not an exhaustive switch) and check `Scope.grants(held, required)`. `MENDESKY_LEGACY_JWE` = `accept` (default) | `warn` | `reject` controls JWE and logs `legacy-jwe-accepted` / `legacy-jwe-rejected` (also in `PermissionMiddleware`'s JWE fallback). Only the environment-reading inits read it (Bearer `init(validators:)` / `init(validators:accepting:)` / `init(validators:acceptsApplication:)`, `PermissionMiddleware.init(rules:provider:)`); explicit inits use the value passed (or `.accept`) and ignore it. Rotate keys: add new public key and deploy, switch the issuer, remove old key. `jti` gives no replay protection; a disabled client's tokens live until `exp` (≤15 min).
- **PermissionMiddleware** — Reads `Caller.current`, so it must run after the Bearer middleware to see `at+jwt` callers; `.user` and `.delegatedUser` are checked against IAM by `sub`, `.application` is never granted (so application routes must not be `PermissionRule` routes). Its own JWE fallback (no Bearer middleware ahead of it) is deprecated.
- **DynamicCORSMiddleware** — Generic over `RequestContext`; origin-whitelist-based CORS with preflight handling.
- **LoggingMiddleware** — Debug-level request/response logging.
- **ProxyHeaderReceiverMiddleware** — Captures specified inbound headers into a `TaskLocal`-backed `SetHeaders.Management` store for downstream forwarding.

### Testing product

- **MiddlewareTesting** (separate product) — `AccessTokenTestSigner` (= `ApplicationTokenTestSigner`) mints `at+jwt` tokens in tests (`subType:`, `actors:`, `trustedIssuer(callerTypes:actors:)`, `trustBase64(audience:issuers:)`, `rawToken(headerData:payloadData:)`). Tests only; never depend on it from production targets.

### Client-side (OpenAPI `ClientMiddleware`)

- **AccessTokenMiddleware** — Forwards the `Authorization` header from the current request to outbound client calls.
- **ProxyHeaderSenderMiddleware** — Reads headers from `SetHeaders.Management` (populated by `ProxyHeaderReceiverMiddleware`) and attaches them to outbound requests. These two form a pair for header proxying across service-to-service calls.

### Key pattern: Header proxying

`ProxyHeaderReceiverMiddleware` (server) + `ProxyHeaderSenderMiddleware` (client) work together via the `SetHeaders` `TaskLocal` to forward headers from an inbound request through to outbound service calls within the same async task.
