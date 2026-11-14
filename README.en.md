# Middleware

[繁體中文](README.md) ｜ **English**

Shared [Hummingbird 2.x](https://github.com/hummingbird-project/hummingbird) middleware package for the Mendesky platform. This is a **library package** (not an executable), consumed by the various context services (OpportunityContext, QuotingContext, …).

Provides:

- **Authentication**: bearer-token verification, JWE (legacy) or at+jwt (`BearerTokenAuthenticationMiddleware`)
- **Signed access tokens (`at+jwt`)**: RS256 JWTs for first-party users, external systems (application) and delegated users; routes opt in (`RouteAcceptance`, `Caller`, `Scope`); a test signer lives in `MiddlewareTesting`
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
| `BearerTokenAuthenticationMiddleware` | server (`MiddlewareProtocol`) | Verify the Bearer token (JWE legacy or at+jwt), verify identity (who you are) |
| `PermissionMiddleware` | server (`MiddlewareProtocol`) | Endpoint permission check (what you may do) |
| `DynamicCORSMiddleware<Context>` | server (`RouterMiddleware`) | Origin-allowlist CORS + preflight |
| `LoggingMiddleware` | server (`MiddlewareProtocol`) | Debug-level request/response logging |
| `ProxyHeaderReceiverMiddleware` | server (`MiddlewareProtocol`) | Capture specified inbound headers into a `TaskLocal` |
| `AccessTokenMiddleware` | client (`ClientMiddleware`) | Forward the current request's `Authorization` to outbound calls |
| `ProxyHeaderSenderMiddleware` | client (`ClientMiddleware`) | Attach headers collected by `SetHeaders` to outbound calls |

---

## Authentication: `BearerTokenAuthenticationMiddleware`

Verifies `Authorization: Bearer <token>`: the token is a JWE (legacy, 5 segments) or an at+jwt (3 segments, below), and the `operatorId` header (`userId` is the deprecated fallback) is checked to prevent token theft.

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

> ⚠️ **On routes opened for `.application`, the `operatorId` / `userId` headers are NOT verified and pass through to the handler unchanged.** Handlers must not trust them to identify an application caller; read `Caller.current` (`if case .application(let c) = Caller.current`). `ProxyHeaderReceiverMiddleware` stores the header regardless of authentication and `ProxyHeaderSenderMiddleware` forwards it on every downstream call, so a caller-chosen `operatorId` travels with the application token to downstream services; a downstream that records `operatorId` in events would attribute the action to whoever the caller named.

| Case | Response |
|---|---|
| OPTIONS / whitelisted path | pass through (skipped) |
| No `Authorization` header | `401` |
| Not `Bearer <token>` format | `400` |
| JWE decrypt failed / token expired | `401` |
| JWE: no `operatorId` (or deprecated `userId`) header | `400` |
| JWE: `operatorId` / `userId` header ≠ userId inside token | `400` (anti-theft) |
| Unexpected error during token verification | `401` |

> Whitelisting uses `PathValidator` (below); matching paths skip authentication. `OPTIONS` is always skipped (for CORS preflight).

### Signed access tokens (`at+jwt`)

Besides user JWE tokens, `BearerTokenAuthenticationMiddleware` accepts **signed access tokens**: RS256 JWTs (`typ: at+jwt` or `application/at+jwt`, with a `kid` header). There are three kinds of caller:

- **user**: a first-party user (issued by IdentityContext, `sub_type: user`, no `act`), mapped to `.user`; accepted on every route, exactly like a JWE user.
- **application**: an external system using OAuth `client_credentials`, with **no user account** (`sub_type: application`, `sub` is the applicationId, exposed lowercased); the route must opt in explicitly.
- **delegatedUser**: a user's token held by an actor such as an MCP server (`sub_type: user` with an `act` claim, RFC 8693); the route must opt in explicitly.

Claims: `iss`, `aud` (`mendesky-services`, string or array), `sub`, `sub_type`, `client_id`, `scope` (space-delimited; may be an empty string but must be present), `exp`. The issuer always sets `iat` and `jti`, but Middleware neither requires nor checks them.

#### Trust configuration

| Environment variable | Required | Description |
|---|---|---|
| `MENDESKY_ACCESS_TOKEN_TRUST_PATH` | — (neither set = at+jwt not accepted, JWE only) | Path of the trust configuration JSON file; wins when both are set |
| `MENDESKY_ACCESS_TOKEN_TRUST` | — | Base64 of the trust configuration JSON |

```json
{
  "audience": "mendesky-services",
  "issuers": [
    {
      "issuer": "https://<platform-domain>/identity-context",
      "callerTypes": ["user"],
      "keys": { "keys": [ { "kty": "RSA", "kid": "ic-2026-11", "n": "…", "e": "AQAB" } ] }
    },
    {
      "issuer": "https://oidc.jwcpas.net/oidc-context",
      "callerTypes": ["application", "delegatedUser"],
      "actors": ["mendesky-mcp-server"],
      "keys": { "keys": [ { "kty": "RSA", "kid": "oidc-at-2026-11", "n": "…", "e": "AQAB" } ] }
    }
  ]
}
```

- `actors` lists the allowed `act.sub` values; public keys only; `/jwks` is never fetched at runtime.
- **A bad configuration throws at startup (the service does not start)** on any of:
  - more than one issuer allowed `user`, or the `user` issuer also allowed `application` or `delegatedUser`;
  - an issuer allowed `delegatedUser` with an empty `actors`;
  - a duplicate `issuer`, or the same `kid` twice (within one issuer or across issuers);
  - a key that is not `kty=RSA`, lacks `n` or `e`, has an `alg` other than `RS256`, has a modulus under 2048 bits, or carries private fields (`d`, `p`, `q`, `dp`, `dq`, `qi`).
- ⚠️ `MENDESKY_APP_TOKEN_*` was renamed to the two variables above; setting any old variable fails startup (the error names the variable to use instead).
- `init(verification:validators:)` **never reads** `MENDESKY_ACCESS_TOKEN_TRUST`: with that init, at+jwt is not accepted even if the variable is set, and nothing is logged about it. To enable at+jwt use `init(validators:)`, `init(validators:accepting:)`, or the init that takes `trust:` explicitly.
- Every init that reads the environment (`init(validators:)`, `init(validators:accepting:)`, `init(validators:acceptsApplication:)`) logs notice lines at startup: `Signed access tokens enabled: ...` (audience, plus each issuer's callerTypes, actors and kids) or `Signed access tokens disabled: ...`, and `Legacy JWE mode: accept|warn|reject`.

#### Legacy JWE switch: `MENDESKY_LEGACY_JWE`

| Value | Behavior |
|---|---|
| `accept` (default; unset or blank) | JWE is decrypted as usual; each admitted request logs one `legacy-jwe-accepted` line (`.notice`) |
| `warn` | Same, logged at `.warning` |
| `reject` | 5-segment tokens are not decrypted; logs `legacy-jwe-rejected` (`.notice`) and answers `401` |

Any other value fails startup. **Only** the environment-reading inits read this variable: Bearer's `init(validators:)`, `init(validators:accepting:)`, `init(validators:acceptsApplication:)`, and `PermissionMiddleware.init(rules:provider:)` (its JWE fallback, when no Bearer runs in front, honours the switch too). The explicit inits (Bearer's `init(verification:validators:)` and `init(verification:applicationTokens:validators:acceptsApplication:logger:)`, always `accept`; `init(verification:trust:legacyJWE:…)`, default `accept`; `PermissionMiddleware.init(rules:provider:verification:…)`) use the value passed (or `accept`) and **ignore** the variable. The `legacy-jwe-accepted` metadata holds only `clientId` (the clientId inside the JWE; empty for first-party), `route` (the route template such as `/items/{id}`, not the actual path; `unknown` if unavailable) and `service` (defaults to the process name, overridable via an init parameter); `legacy-jwe-rejected` holds only `route` and `service`. The logs **never contain the token or the userId**.

#### Opening routes: `accepting: [RouteAcceptance]`

```swift
router.add(middleware: try BearerTokenAuthenticationMiddleware(
    validators: [PathValidator("/health")],
    accepting: [
        // application tokens: only matching routes accept them
        .application(PathValidator("/notification-context/notifications"), methods: [.post]),
        // delegated user tokens: scope must contain quote:read exactly, actor restricted
        .delegatedUser(
            PathValidator("/quoting-context/drafts"),
            requiresScope: "quote:read",
            actors: ["mendesky-mcp-server"]
        ),
    ]
))
```

- First-party users (JWE or at+jwt) need no opt-in; every route accepts them.
- ⚠️ **On routes opened for `.application`, the `operatorId` / `userId` headers are NOT verified and pass through to the handler unchanged.** An application caller has no user, so handlers must not trust these headers; read `Caller.current` (`if case .application(let c) = Caller.current`) instead. `ProxyHeaderReceiverMiddleware` stores the header regardless of authentication and `ProxyHeaderSenderMiddleware` forwards it on every downstream call, so a caller-chosen `operatorId` travels with the application token to downstream services; a downstream that records `operatorId` in events would attribute the action to whoever the caller named.
- The old `BearerTokenAuthenticationMiddleware(acceptsApplication:)` still works and equals `accepting: [.application(where:)]`.
- `actors: nil` on `.delegatedUser` accepts any actor the issuer is trusted for; `requiresScope` is matched exactly (**`*` does not apply**), and a delegated token is always rejected if any scope item contains a `*` character (for example `*` or `quote:*`).
- `PathValidator(try Regex(...))` matches the **raw request path**. Write `[^/]+` (one path segment) in examples rather than `.+`: `/quotes/.+` also matches `/quotes/1/admin`, opening the sub-paths too. For example `PathValidator(try Regex("/quotes/[^/]+"))`.

Behavior and status codes (at+jwt rows; the rest as in the table above):

| Situation | Response |
|---|---|
| 3-segment token with no trust configuration / bad signature / expired / `callerTypes` mismatch | `401` |
| Token with neither 3 nor 5 segments | `401` |
| Route not open to that caller (or actor not allowed by the route) | `401` |
| `.delegatedUser`: route open and actor allowed, but scope lacks `requiresScope` | `403` (body `insufficient scope.`) |
| `.user` and `.delegatedUser`: `operatorId` missing or ≠ `sub` | `400` (the `userId` header is a deprecated fallback) |
| `.application` | no `operatorId` needed; if sent it is **not verified** and passes to the handler unchanged (see the warning above) |
| 5-segment token with `MENDESKY_LEGACY_JWE=reject` | `401` |

Verification accepts RS256 only (fixed, never taken from the token) and checks `typ`, `kid`, signature, `iss`, `aud` and `exp`; failure reasons are logged, **never the token**.

#### Reading the caller in a handler

```swift
if case .application(let claims) = Caller.current {
    guard Scope.grants(claims.scope, Scope.notificationSend) else { throw HTTPError(.forbidden) }
}
```

- `Caller.current` is a task-local `CallerIdentity?`: `.user(userId:clientId:)`, `.application(ApplicationTokenClaims)` or `.delegatedUser(DelegatedUserClaims)`; cases may be added later, so use `if case` rather than an exhaustive `switch`.
- `Scope.grants(held, required)`: passes if `*` (`Scope.all`) is held or the scope equals `required`; `Scope.notificationSend` = `notification:send`.

#### Key rotation and limits

- An issuer may carry several public keys. To rotate: (1) add the new public key to the trust configuration and deploy the services; (2) switch the issuer to the new private key; (3) remove the old public key.
- `aud` is shared platform-wide as `mendesky-services`, so any service that receives a token can use it to call other services. This is the same as JWE today and is why token forwarding works. A `.delegatedUser` token forwarded to a downstream route that isn't opened for delegatedUser gets `401`.
- `reject` mode still requires the JWE keys (`MENDESKY_AUTH_*`) to be configured until the major version that removes JWE.
- The base64 in `MENDESKY_ACCESS_TOKEN_TRUST` must be **single-line** (`base64 -w0` on GNU, `base64 -i file` on macOS); line-wrapped values fail startup.
- ⚠️ `jti` gives **no replay protection**; after a client is disabled, tokens already issued stay valid until `exp` (up to 15 minutes).
- `PermissionMiddleware` **must run after the Bearer middleware** to see at+jwt callers (it reads `Caller.current`). `.user` and `.delegatedUser` are looked up in IAM by `sub`; `.application` has no IAM user and is **never granted**, so a route open to applications must not also be a `PermissionRule` route.
- Behavior changes for existing services upgrading: token verification failures answer `401` (some used to be `503`); errors thrown by handlers: those conforming to Hummingbird's `HTTPResponseError` keep their status (404 stays 404), any other error is still a `503` (generic `service unavailable.` body, the log carries only the error type); tokens are never logged. Application tokens now require `sub_type: "application"`, and the key rules are stricter (≥ 2048 bits, no private fields).

---

## Authorization: `PermissionMiddleware` (endpoint-level RBAC)

Goes after `BearerTokenAuthenticationMiddleware`. For routes covered by a rule: read `Caller.current` to get `userId` (decrypting the JWE is only the deprecated fallback) → fetch that user's permissions via a `PermissionsProvider` → **AND**-match (exact string match) against the rule's required permissions → allow or deny.

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
- `CachingPermissionsProvider(wrapping:ttl:negativeTTL:maxEntries:)` — actor, per-userId, monotonic-clock TTL (default 60s), **caches successes only**, `invalidate(userId:)` / `invalidateAll()`. Empty results (IAM 404 → `[]`) use a shorter `negativeTTL` (default 10s; `nil` = don't cache empties) so a just-provisioned user isn't denied for the full `ttl`; `maxEntries` (default 500) bounds memory, evicting expired-then-oldest when full.

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
//     NOTE: a regex matches the raw request path: use [^/]+ rather than .+ (else /…/audit-quotings/1/admin also matches).
let rules: [PermissionRule] = [
    .init(PathValidator(try Regex("/opportunity-context/audit-quotings/[^/]+/total-assets")),
          methods: [.patch], requires: ["business:write"]),
    .init(PathValidator(try Regex("/opportunity-context/audit-quotings/[^/]+")),
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

> `PermissionMiddleware` must run after `BearerTokenAuthenticationMiddleware` to see at+jwt callers (it reads `Caller.current`; when Bearer comes after it, or is absent, it only falls back to the old JWE parsing, which is deprecated).
>
> `PermissionMiddleware` also has `init(rules:provider:)` (throws), which loads `verification` from `MENDESKY_AUTH_*` itself, letting you skip step (1).

### Request flow

```
Frontend ──HTTP──▶ CORS ─▶ BearerTokenAuth (verify JWE/at+jwt, verify operatorId, set Caller.current) ─▶ PermissionMiddleware ─▶ handler
                                                                        │ 1. match rules by method/path → required permissions
                                                                        │ 2. read Caller.current → userId (decrypt the JWE only as the deprecated fallback)
                                                                        │ 3. provider fetches the user's permissions (cache hit ⇒ no IAM call)
                                                                        │ 4. AND-match → allow / 401 / 403 / 502
                                                                        ▼
                                                provider miss ──HTTP──▶ IAMContext GET /employee-access/permissions/{userId}
```

A protected request must carry: `Authorization: Bearer <token>` (at+jwt or legacy JWE) and `operatorId: <id>` (must equal the user id inside the token; `userId` is the deprecated fallback). Application tokens need no `operatorId`.

> ⚠️ **On routes opened for `.application`, the `operatorId` / `userId` headers are NOT verified and pass through to the handler unchanged.** Handlers must not trust them for application callers; read `Caller.current` (`if case .application(let c) = Caller.current`). `ProxyHeaderReceiverMiddleware` stores the header regardless of authentication and `ProxyHeaderSenderMiddleware` forwards it on every downstream call, so a caller-chosen `operatorId` travels with the application token to downstream services; a downstream that records `operatorId` in events would attribute the action to whoever the caller named.

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

The `MiddlewareTesting` product provides `AccessTokenTestSigner` (an alias of `ApplicationTokenTestSigner`), which signs at+jwt tokens (RS256) in tests:

```swift
let signer = AccessTokenTestSigner()
// Use this signer as a trusted issuer and build the base64 for MENDESKY_ACCESS_TOKEN_TRUST
let issuer = signer.trustedIssuer(callerTypes: [.application, .delegatedUser], actors: ["mendesky-mcp-server"])
let trust = AccessTokenTestSigner.trustBase64(issuers: [issuer])

let app = signer.token(sub: "app-1", scope: "notification:send")                      // application (default subType: "application")
let delegated = signer.token(sub: "user-1", scope: "quote:read",
                             subType: "user", actors: ["mendesky-mcp-server"])        // delegated user (actors nest into act, outermost first)
```

- `trustedIssuer(callerTypes:actors:)` and `trustBase64(audience:issuers:)` build the trust configuration; `rawToken(headerData:payloadData:)` hand-builds malformed tokens to test the verifier's rejection paths.

> `MiddlewareTesting` is for tests only — do not depend on it from production targets.

---

## Design notes

- **`PermissionMiddleware` does not call IAMContext**: it only calls the injected `PermissionsProvider` (a port). The real HTTP client is supplied by the consumer — keeping this package free of any IAM dependency and independently compilable/testable (unit tests inject a fake provider, zero network).
- **Where the IAM client belongs**: prefer an IAMContext client product / shared client package (implementing `PermissionsProvider`) rather than baking it into this package — "whoever provides the API owns the client."
- **Permission freshness**: IAMContext projections are eventually consistent (a grant/revoke takes ~1–2s to reflect); the cache `ttl` / `negativeTTL` and `invalidate(userId:)` are the knobs for controlling freshness.
- **Sender authentication**: the JWE `senderKey` is optional, but without it a token has confidentiality only and the issuer cannot be verified — set `MENDESKY_AUTH_SENDER_JWK` in production, otherwise anyone holding the recipient public key can forge a token (this middleware treats the token's `userId` as the sole authorization input).
- **Coarse-grained**: this layer is an endpoint-level check ("may you call this endpoint"); resource-level rules ("may you edit *this* record") still belong inside the handler.
