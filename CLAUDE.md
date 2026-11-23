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
- **jose-swift 6.x** — JWK/JWS handling for signed `at+jwt` access tokens (JWE support was removed in 2.0)
- **swift-openapi-runtime 1.x** — OpenAPI `ClientMiddleware` protocol for outbound HTTP interception

## Architecture

The package exposes a single `Middleware` module with two categories of middleware:

### Server-side (Hummingbird `MiddlewareProtocol` / `RouterMiddleware`)

- **BearerTokenAuthenticationMiddleware** — Accepts only signed RS256 `at+jwt` (3 segments, see below). Since 2.0 a 5-segment token (legacy JWE) is refused with `401` `access token rejected.` without decryption, logged at notice as `Bearer token rejected: legacy JWE access tokens are no longer accepted` (metadata `route`, `service` only); other shapes keep `Bearer token rejected: neither a signed access token nor a JWE`. Supports path whitelisting and auto-skips OPTIONS requests. Status codes: 401 (bad/expired token, route not open to that caller), 403 `insufficient scope.` (delegated user scope), 400 (caller headers, compared exactly against `Caller.current`; names in public `CallerHeaders`: `operatorId` — deprecated `userId` fallback — must be `sub` for `.user`/`.delegatedUser` and the lowercased applicationId for `.application` (later: the application's bound service account); `applicationId` must be the actor `act.sub` for `.delegatedUser`, the applicationId for `.application`, and for `.user` is optional — absent → Bearer adds `applicationId: mendesky-first-party` to the request it passes on, present → must equal it; a repeated `applicationId` is refused; a repeated `operatorId`, or a repeated `userId` when `operatorId` is absent, is refused too; the point is that the headers agree with the token so a caller cannot name someone else, not to stop a stolen token). Whitelisted paths and OPTIONS get no checks and no added header. Never logs tokens; handler errors propagate unchanged. `init(validators:)` / `init(validators:accepting:)` / `init(validators:acceptsApplication:)` read the trust env vars (required: neither set throws `BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured`), log `Signed access tokens enabled: ...`, log one warning when no trusted issuer has `callerTypes` `user` (`BearerTokenAuthenticationMiddleware.noUserIssuerWarning`: the service starts but every first-party user gets 401; not fatal because application-only services are legitimate), and log one warning naming any leftover 1.x variable (`MENDESKY_AUTH_RECIPIENT_JWK(_PATH)`, `MENDESKY_AUTH_SENDER_JWK(_PATH)`, `MENDESKY_AUTH_PASSWORD`, `MENDESKY_LEGACY_JWE`; names only, never values; ignored, never fatal). `init(trust:validators:accepting:serviceName:logger:)` reads no environment. No init takes `verification:` any more; `AccessTokenVerification` is a caseless enum holding only `bearerToken(fromHeaderValue:)` / `operatorId(fromHeaders:)` / `bytesEqual`.
- **Signed access tokens** (`Sources/Middleware/SignedAccessToken/`, `Sources/Middleware/ApplicationToken/`) — `AccessTokenTrust` (from `MENDESKY_ACCESS_TOKEN_TRUST` base64 JSON or `MENDESKY_ACCESS_TOKEN_TRUST_PATH` file, file wins; `AccessTokenTrust.fromEnvironment` returns nil when neither is set, which the Bearer env inits turn into a startup error) lists trusted issuers with `callerTypes` (`user` / `application` / `delegatedUser`), `actors` and public JWKs; invalid trust (two `user` issuers, delegatedUser without actors, duplicate issuer/`kid`, private fields, <2048-bit or non-RSA keys) or any old `MENDESKY_APP_TOKEN_*` variable (renamed; setting it fails startup) throws at startup. `SignedAccessTokenVerification` is the hardened verifier (fixed RS256, strict base64url/JSON, duplicate `alg` rejected, optional `nbf` must be a JSON number <= now (no leeway) else 401, unverified `iss` only picks the key); `ApplicationTokenVerification` wraps it for the single-issuer, `sub_type: application` case. `RouteAcceptance` (`accepting: [.application(...), .delegatedUser(..., requiresScope:, actors:)]`; `acceptsApplication:` still works) opens routes to non-user callers; first-party users pass everywhere. Handlers read `Caller.current` (`CallerIdentity`: `.user` / `.application` / `.delegatedUser`; use `if case`, not an exhaustive switch) and check `Scope.grants(held, required)`. Rotate keys: add new public key and deploy, switch the issuer, remove old key. `jti` gives no replay protection; a disabled client's tokens live until `exp` (≤15 min).
- **PermissionMiddleware** — Reads only `Caller.current`, so it must run after the Bearer middleware; no caller (no Bearer in front) → `401` (the JWE self-decryption fallback was removed in 2.0). `.user` and `.delegatedUser` are checked against IAM by `sub`, `.application` is never granted (so application routes must not be `PermissionRule` routes). `init(rules:provider:)` stays `throws` for source compatibility but never throws.
- **DynamicCORSMiddleware** — Generic over `RequestContext`; origin-whitelist-based CORS with preflight handling.
- **LoggingMiddleware** — Debug-level request/response logging.
- **ProxyHeaderReceiverMiddleware** — Captures specified inbound headers (plus `applicationId`, always, never twice) into a `TaskLocal`-backed `SetHeaders.Management` store for downstream forwarding. The `.user` filled-in `applicationId` is captured only when the receiver runs after Bearer; downstreams fill it in again otherwise.

### Testing product

- **MiddlewareTesting** (separate product) — `AccessTokenTestSigner` (= `ApplicationTokenTestSigner`) mints `at+jwt` tokens in tests (`subType:`, `actors:`, `trustedIssuer(callerTypes:actors:)`, `trustBase64(audience:issuers:)`, `rawToken(headerData:payloadData:)`). Tests only; never depend on it from production targets.

### Client-side (OpenAPI `ClientMiddleware`)

- **AccessTokenMiddleware** — Forwards the `Authorization` header from the current request to outbound client calls.
- **ProxyHeaderSenderMiddleware** — Reads headers from `SetHeaders.Management` (populated by `ProxyHeaderReceiverMiddleware`) and attaches them to outbound requests. These two form a pair for header proxying across service-to-service calls.

### Key pattern: Header proxying

`ProxyHeaderReceiverMiddleware` (server) + `ProxyHeaderSenderMiddleware` (client) work together via the `SetHeaders` `TaskLocal` to forward headers from an inbound request through to outbound service calls within the same async task.
