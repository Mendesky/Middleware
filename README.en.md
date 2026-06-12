# Middleware

[繁體中文](README.md) ｜ **English**

Shared [Hummingbird 2.x](https://github.com/hummingbird-project/hummingbird) middleware package for the Mendesky platform. This is a **library package** (not an executable), consumed by the various context services (OpportunityContext, QuotingContext, …).

Provides:

- **Authentication**: JWE bearer-token decryption (`BearerTokenAuthenticationMiddleware`)
- **Authorization**: endpoint-level RBAC (`PermissionMiddleware`, live lookups against IAMContext)
- **CORS**: origin allowlist + preflight (`DynamicCORSMiddleware`)
- **Logging**: debug-level request/response logging (`LoggingMiddleware`)
- **Header proxying**: forward inbound headers to outbound service calls (`ProxyHeaderReceiverMiddleware` + `ProxyHeaderSenderMiddleware`)

---

## Requirements & Installation

- Swift 6.0+ / macOS 15+
- Dependencies: Hummingbird 2.x, jose-swift 6.x, swift-openapi-runtime 1.x

`Package.swift`:

```swift
.package(url: "git@github.com:Mendesky/Middleware.git", from: "1.0.0"),
// target dependency
.product(name: "Middleware", package: "Middleware"),
```

```bash
swift build
swift test
```

---

## Middleware overview

| Name | Kind | Role |
|---|---|---|
| `BearerTokenAuthenticationMiddleware` | server (`MiddlewareProtocol`) | Decrypt JWE token, verify identity (who you are) |
| `PermissionMiddleware` | server (`MiddlewareProtocol`) | Endpoint permission check (what you may do) |
| `DynamicCORSMiddleware<Context>` | server (`RouterMiddleware`) | Origin-allowlist CORS + preflight |
| `LoggingMiddleware` | server (`MiddlewareProtocol`) | Debug-level request/response logging |
| `ProxyHeaderReceiverMiddleware` | server (`MiddlewareProtocol`) | Capture specified inbound headers into a `TaskLocal` |
| `AccessTokenMiddleware` | client (`ClientMiddleware`) | Forward the current request's `Authorization` to outbound calls |
| `ProxyHeaderSenderMiddleware` | client (`ClientMiddleware`) | Attach headers collected by `SetHeaders` to outbound calls |

---

## Authentication: `BearerTokenAuthenticationMiddleware`

Decrypts the `Authorization: Bearer <JWE>` access token and checks the `userId` header to prevent token theft.

Keys are loaded from environment variables:

| Environment variable | Required | Description |
|---|---|---|
| `MENDESKY_AUTH_RECIPIENT_JWK` or `..._JWK_PATH` | ✅ | Decryption private key (JWK JSON / base64, or a file path) |
| `MENDESKY_AUTH_SENDER_JWK` or `..._JWK_PATH` | — (recommended in production) | Sender-authentication public key |
| `MENDESKY_AUTH_PASSWORD` | — | JWK password (base64) |

> ⚠️ **Set `MENDESKY_AUTH_SENDER_JWK` in production.** Without it the JWE has confidentiality only, not sender authentication — anyone holding the recipient **public** key can forge a token, and this middleware fully trusts the `userId` inside the token.

```swift
router.add(middleware: try BearerTokenAuthenticationMiddleware(
    validators: [PathValidator("/health")]   // whitelist (skips authentication)
))
```

Behavior & status codes:

| Case | Response |
|---|---|
| OPTIONS / whitelisted path | pass through (skipped) |
| No `Authorization` header | `401` |
| Not `Bearer <token>` format | `400` |
| Decrypt failed / token expired | `401` |
| No `userId` header | `400` |
| `userId` header ≠ userId inside token | `400` (anti-theft) |
| Unexpected error | `503` |

> Whitelisting uses `PathValidator` (below); matching paths skip authentication. `OPTIONS` is always skipped (for CORS preflight).

---

## Authorization: `PermissionMiddleware` (endpoint-level RBAC)

Goes after `BearerTokenAuthenticationMiddleware`. For routes covered by a rule: decrypt the token to get `userId` → fetch that user's permissions via a `PermissionsProvider` → **AND**-match (exact string match) against the rule's required permissions → allow or deny.

### Three roles (responsibility boundaries)

| Thing | Lives in | Responsibility |
|---|---|---|
| Permission vocabulary + "who has which permissions" | **IAMContext** | Authoritative source (grant/revoke, getPermissions) |
| The "route → required permissions" rule table | **Each context itself** | Injected at startup via `PermissionMiddleware(rules:)` |
| The matching engine | **This package** | `PermissionMiddleware` / `PermissionRule` — holds **no** concrete rules or permission strings |

> This package **deliberately does not depend on IAMContext**. The actual IAM HTTP client is injected by the consumer as a `PermissionsProvider` (see "Wiring example").

### `PermissionRule`

```swift
PermissionRule(
    _ pathMatcher: any WhitelistValidator,     // path match (use PathValidator)
    methods: Set<HTTPRequest.Method>? = nil,   // restrict methods; nil = any
    requires: [String]                          // required permissions (AND — all must be present)
)
```

### `PermissionsProvider` (port)

```swift
public protocol PermissionsProvider: Sendable {
    func permissions(forUserId userId: String) async throws -> [String]
}
```

- `ClosurePermissionsProvider { userId in ... }` — quick injection via a closure.
- `CachingPermissionsProvider(wrapping:ttl:negativeTTL:maxEntries:)` — actor, per-userId, monotonic-clock TTL (default 60s), **caches successes only**, `invalidate(userId:)` / `invalidateAll()`. Empty results (IAM 404 → `[]`) use a shorter `negativeTTL` (default 10s; `nil` = don't cache empties) so a just-provisioned user isn't denied for the full `ttl`; `maxEntries` (default 10000) bounds memory, evicting expired-then-oldest when full.

### Status codes

| Case | Response |
|---|---|
| OPTIONS | pass through (skipped) |
| No rule covers this route | pass through |
| Rule matched but no trusted token | `401` |
| Provider (IAM lookup) failed | `502` (fail-closed; 502 not 503, to distinguish an upstream-dependency failure) |
| Missing a required permission | `403` |
| All permissions present | pass through to handler |

---

## Wiring example (OCServer)

```swift
// (1) Token-decryption keys: load from the MENDESKY_AUTH_* environment variables
let verification = try AccessTokenVerification.fromEnvironment()

// (2) Permission source: IAM adapter (the real IAMContext client) + cache.
//     Base URL comes from an env var — do not hardcode.
let iamBase = Environment().get("IAM_BASE_URL") ?? "http://localhost:24202"
let iamProvider = ClosurePermissionsProvider { userId in
    let encoded = userId.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? userId
    let url = URL(string: "\(iamBase)/employee-access/permissions/\(encoded)")!
    let (data, resp) = try await URLSession.shared.data(from: url)
    switch (resp as? HTTPURLResponse)?.statusCode {
    case 200: return try JSONDecoder().decode([String].self, from: data)
    case 404: return []                            // no profile = no permissions
    default:  throw URLError(.badServerResponse)    // -> middleware returns 502
    }
}
let provider = CachingPermissionsProvider(wrapping: iamProvider, ttl: .seconds(60))

// (3) Route -> required-permissions rule table (this context's own policy).
//     NOTE: PathValidator("string") is a *literal* match; for regex use PathValidator(try Regex(...)).
let rules: [PermissionRule] = [
    .init(PathValidator(try Regex("/opportunity-context/audit-quotings/.+/total-assets")),
          methods: [.patch], requires: ["business:write"]),
    .init(PathValidator(try Regex("/opportunity-context/audit-quotings/.+")),
          methods: [.get],   requires: ["business:read"]),
]

// (4) Compose the middleware chain (order: authentication -> authorization)
let router = Router()
router.add(middleware: DynamicCORSMiddleware(allowedOrigins: ["https://app.mendesky.com"]))
router.add(middleware: try BearerTokenAuthenticationMiddleware())          // authentication
router.add(middleware: PermissionMiddleware(rules: rules,                  // authorization
                                            provider: provider,
                                            verification: verification))
router.add(middleware: LoggingMiddleware())
try api.registerHandlers(on: router, serverURL: URL(string: "/opportunity-context")!)
```

> `PermissionMiddleware` also has `init(rules:provider:)` (throws), which loads `verification` from `MENDESKY_AUTH_*` itself, letting you skip step (1).

### Request flow

```
Frontend ──HTTP──▶ CORS ─▶ BearerTokenAuth (decrypt, verify userId) ─▶ PermissionMiddleware ─▶ handler
                                                                        │ 1. match rules by method/path → required permissions
                                                                        │ 2. decrypt token → userId
                                                                        │ 3. provider fetches the user's permissions (cache hit ⇒ no IAM call)
                                                                        │ 4. AND-match → allow / 401 / 403 / 502
                                                                        ▼
                                                provider miss ──HTTP──▶ IAMContext GET /employee-access/permissions/{userId}
```

A protected request must carry: `Authorization: Bearer <JWE>` and `userId: <id>` (must equal the userId inside the token).

---

## CORS: `DynamicCORSMiddleware`

```swift
DynamicCORSMiddleware<Context>(
    allowedOrigins: ["https://app.mendesky.com"],
    allowedMethods: [.get, .post, .put, .delete, .options],   // default
    allowedHeaders: [.contentType, .authorization],            // default
    allowCredentials: true,                                    // default
    maxAge: 3600                                               // default
)
```

Only origins in the allowlist receive CORS headers; an `OPTIONS` preflight returns `204 No Content`.

---

## Logging: `LoggingMiddleware`

```swift
router.add(middleware: LoggingMiddleware())
```

Logs requests/responses at debug level.

---

## Header proxying

For cross-service calls, forward inbound headers outbound via the `SetHeaders` `TaskLocal`:

```swift
// server side: collect the specified headers
router.add(middleware: ProxyHeaderReceiverMiddleware(presetKeys: [.init("operatorId")!]))

// client side (OpenAPI client): attach the collected headers to outbound requests
let client = Client(serverURL: ..., transport: ..., middlewares: [
    AccessTokenMiddleware(),        // forward Authorization
    ProxyHeaderSenderMiddleware(),  // forward headers collected by SetHeaders
])
```

`ProxyHeaderReceiverMiddleware` (server) + `ProxyHeaderSenderMiddleware` (client) are used as a pair to forward inbound headers to outbound service calls **within the same async task**.

---

## Testing

```bash
swift test                                  # all unit tests (no external dependencies)
```

The end-to-end integration test against a live IAMContext is gated by `IAM_BASE_URL` and skipped by default:

```bash
IAM_BASE_URL=http://localhost:24202 swift test --filter LiveIAMIntegrationTests
```

---

## Design notes

- **`PermissionMiddleware` does not call IAMContext**: it only calls the injected `PermissionsProvider` (a port). The real HTTP client is supplied by the consumer — keeping this package free of any IAM dependency and independently compilable/testable (unit tests inject a fake provider, zero network).
- **Where the IAM client belongs**: prefer an IAMContext client product / shared client package (implementing `PermissionsProvider`) rather than baking it into this package — "whoever provides the API owns the client."
- **Permission freshness**: IAMContext projections are eventually consistent (a grant/revoke takes ~1–2s to reflect); the cache `ttl` / `negativeTTL` and `invalidate(userId:)` are the knobs for controlling freshness.
- **Sender authentication**: the JWE `senderKey` is optional, but without it a token has confidentiality only and the issuer cannot be verified — set `MENDESKY_AUTH_SENDER_JWK` in production, otherwise anyone holding the recipient public key can forge a token (this middleware treats the token's `userId` as the sole authorization input).
- **Coarse-grained**: this layer is an endpoint-level check ("may you call this endpoint"); resource-level rules ("may you edit *this* record") still belong inside the handler.
