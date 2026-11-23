# Middleware

[繁體中文](README.md) ｜ **English**

Shared [Hummingbird 2.x](https://github.com/hummingbird-project/hummingbird) middleware package for the Mendesky platform. This is a **library package** (not an executable), consumed by the various context services (OpportunityContext, QuotingContext, …).

Provides:

- **Authentication**: bearer-token verification, at+jwt only (`BearerTokenAuthenticationMiddleware`; legacy JWE was removed in 2.0, see "Migrating from 1.3 to 2.0")
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
.package(url: "git@github.com:Mendesky/Middleware.git", from: "2.0.0"),
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
| `BearerTokenAuthenticationMiddleware` | server (`MiddlewareProtocol`) | Verify the Bearer token (at+jwt), verify identity (who you are) |
| `PermissionMiddleware` | server (`MiddlewareProtocol`) | Endpoint permission check (what you may do) |
| `DynamicCORSMiddleware<Context>` | server (`RouterMiddleware`) | Origin-allowlist CORS + preflight |
| `LoggingMiddleware` | server (`MiddlewareProtocol`) | Debug-level request/response logging |
| `ProxyHeaderReceiverMiddleware` | server (`MiddlewareProtocol`) | Capture specified inbound headers into a `TaskLocal` |
| `AccessTokenMiddleware` | client (`ClientMiddleware`) | Forward the current request's `Authorization` to outbound calls |
| `ProxyHeaderSenderMiddleware` | client (`ClientMiddleware`) | Attach headers collected by `SetHeaders` to outbound calls |

---

## Authentication: `BearerTokenAuthenticationMiddleware`

Verifies `Authorization: Bearer <token>`: the token must be an at+jwt (3 segments, see "Signed access tokens" below), and the `operatorId` (`userId` is the deprecated fallback) and `applicationId` headers are checked so that the headers agree with the token and a caller cannot name someone else (see "Caller headers" below).

The trust configuration (`MENDESKY_ACCESS_TOKEN_TRUST` or `MENDESKY_ACCESS_TOKEN_TRUST_PATH`, see "Trust configuration" below) is **required**: the environment-reading inits throw `BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured` when neither is set (the service does not start). The init that reads no environment is `init(trust:validators:accepting:serviceName:logger:)`.

> Since 2.0 a legacy JWE (5 segments) always gets `401`, and `MENDESKY_AUTH_*` and `MENDESKY_LEGACY_JWE` are no longer read; if any is still set, **one** warning naming the variables (never their values) is logged at startup. Remove them and delete the JWE private key.

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
| Token verification failed / token expired | `401` (body `access token rejected.`) |
| Legacy JWE (5-segment token) | `401` (body `access token rejected.`; never decrypted) |
| No `operatorId` (or deprecated `userId`) header, or ≠ the userId in the token | `400` (ensures the headers agree with the token; a caller cannot name someone else) |
| `.user`: `applicationId` header present but ≠ `mendesky-first-party`, or repeated | `400` |
| `.user`: no `applicationId` | pass; the request passed on gets `applicationId: mendesky-first-party` |
| Unexpected error during token verification | `401` |

> Whitelisting uses `PathValidator` (below); matching paths skip authentication. `OPTIONS` is always skipped (for CORS preflight). `PathValidator` normalizes the path the way Hummingbird's router splits it (empty segments dropped) before matching, so `/health/` and `//health` are the same path as `/health`.

### Caller headers: `operatorId` and `applicationId`

After the route admission check, the middleware compares two headers (names in `CallerHeaders`) per identity, **exactly and case-sensitively**, against the values in `Caller.current`; missing, mismatched or repeated → `400` (this ensures the headers agree with the token and a caller cannot name someone else; it does not stop a stolen token, since whoever holds the token can read the right values from it):

| Identity | `operatorId` | `applicationId` |
|---|---|---|
| `.user` | required, = the userId in the token (`sub`), verbatim | optional. When absent the middleware adds `applicationId: mendesky-first-party` (`CallerHeaders.firstPartyApplicationId`) to the request it passes on; when present it must be exactly that |
| `.delegatedUser` | required, = `sub` | required, = the actor (`act.sub`, e.g. `mendesky-mcp-server`) |
| `.application` | required, = the applicationId | required, = the applicationId |

- `operatorId` and the deprecated `userId` header must agree: either one repeated → `400` (whether or not the other is present); both present → they must be byte-identical, else `400` (handlers read `userId` as the operator, so a disagreeing pair would let a caller record events as someone else); only one present → that value is compared with the token. `userId` **never** stands in for `applicationId`.
- Identifiers (`operatorId`, `userId`, `applicationId`) are compared **by UTF-8 bytes**, not Unicode canonical equivalence: `é` as U+00E9 and as `e` + U+0301 are different (→ `400`).
- An `.application`'s applicationId is the token `sub` lowercased, so headers must carry the lowercase form (an uppercase UUID → `400`); what a handler reads from the header always equals `Caller.current`.
- An `.application`'s `operatorId` is its applicationId today; it will later become the application's bound service account.
- Whitelisted paths and `OPTIONS` are not checked and get no header added.

### Signed access tokens (`at+jwt`)

`BearerTokenAuthenticationMiddleware` accepts **signed access tokens** only: RS256 JWTs (`typ: at+jwt` or `application/at+jwt`, with a `kid` header). There are three kinds of caller:

- **user**: a first-party user (issued by IdentityContext, `sub_type: user`, no `act`), mapped to `.user`; accepted on every route.
- **application**: an external system using OAuth `client_credentials`, with **no user account** (`sub_type: application`, `sub` is the applicationId, exposed lowercased); the route must opt in explicitly.
- **delegatedUser**: a user's token held by an actor such as an MCP server (`sub_type: user` with an `act` claim, RFC 8693); the route must opt in explicitly.

Claims: `iss`, `aud` (`mendesky-services`, string or array), `sub`, `sub_type`, `client_id`, `scope` (space-delimited; may be an empty string but must be present), `exp` (must be a JSON number: `"exp": true` → `401`, not read as 1); `nbf` is optional, but when present it must be a JSON number (a boolean or string is not one) no later than now (no clock-skew leeway, like `exp`), otherwise `401`. The issuer always sets `iat` and `jti`, but Middleware neither requires nor checks them.

#### Trust configuration

| Environment variable | Required | Description |
|---|---|---|
| `MENDESKY_ACCESS_TOKEN_TRUST_PATH` | ✅ one of the two (neither set = startup fails) | Path of the trust configuration JSON file; wins when both are set |
| `MENDESKY_ACCESS_TOKEN_TRUST` | ✅ one of the two | Base64 of the trust configuration JSON |

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
- ⚠️ `MENDESKY_APP_TOKEN_*` was renamed to the two variables above; setting any old variable fails startup (the error names the variable to use instead). This applies only to the environment-reading entry points: Bearer's `init(validators:)`, `init(validators:accepting:)`, `init(validators:acceptsApplication:)` and `AccessTokenTrust.fromEnvironment(_:)`; the explicit `init(trust:…)` never reads the environment.
- Every init that reads the environment (`init(validators:)`, `init(validators:accepting:)`, `init(validators:acceptsApplication:)`) logs a notice at startup: `Signed access tokens enabled: ...` (audience, plus each issuer's callerTypes, actors and kids); if any 1.x `MENDESKY_AUTH_*` / `MENDESKY_LEGACY_JWE` variable is still set, it also logs one warning naming them.

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
            methods: [.get],
            requiresScope: "quote:read",
            actors: ["mendesky-mcp-server"]
        ),
    ]
))
```

- `methods:` limits the methods a `RouteAcceptance` opens (`nil` = any method): without it a `quote:read` holder could also `POST` the route. A `HEAD` request matches an entry whose `methods` include `GET`.
- First-party users need no opt-in; every route accepts them.
- `.application` and `.delegatedUser` must both send `operatorId` and `applicationId`; see "Caller headers" above.
- When a route matches several `RouteAcceptance` entries they combine as a **union (OR)**: any one admitting is enough. Adding a broader entry later (e.g. without an actor restriction) silently widens an existing actor-restricted one.
- The old `BearerTokenAuthenticationMiddleware(acceptsApplication:)` still works and equals `accepting: [.application(where:)]`.
- `actors: nil` on `.delegatedUser` accepts any actor the issuer is trusted for; `requiresScope` is matched exactly (**`*` does not apply**), and a delegated token is always rejected if any scope item contains a `*` character (for example `*` or `quote:*`).
- `PathValidator(try Regex(...))` matches the **raw request path**. Write `[^/]+` (one path segment) in examples rather than `.+`: `/quotes/.+` also matches `/quotes/1/admin`, opening the sub-paths too. For example `PathValidator(try Regex("/quotes/[^/]+"))`.

Behavior and status codes (at+jwt rows; the rest as in the table above):

| Situation | Response |
|---|---|
| Bad signature / expired / `callerTypes` mismatch | `401` |
| Token without exactly 3 segments (a 5-segment legacy JWE included) | `401` |
| Route not open to that caller (or actor not allowed by the route) | `401` |
| `.delegatedUser`: route open and actor allowed, but scope lacks `requiresScope` | `403` (body `insufficient scope.`) |
| `.user` and `.delegatedUser`: `operatorId` missing or ≠ `sub` | `400` (the deprecated `userId` header may stand in for it, but when both are sent they must be identical) |
| `.application`: `operatorId` missing or ≠ the applicationId (lowercase) | `400` (a present `userId` must equal it too) |
| `.delegatedUser`: `applicationId` missing or ≠ the actor (`act.sub`) | `400` |
| `.application`: `applicationId` missing or ≠ the applicationId (lowercase) | `400` |
| `.user`: `applicationId` present but ≠ `mendesky-first-party`; or a repeated `applicationId` for any identity | `400` |
| Any identity: repeated `operatorId`; repeated `userId` (even with `operatorId` present); or `operatorId` and `userId` both present but not byte-identical | `400` |
| Any identity: `operatorId` / `userId` / `applicationId` equal to the expected value only under Unicode canonical equivalence (NFC vs NFD) | `400` (byte-exact comparison) |
| at+jwt: `exp` missing or not a JSON number (a boolean is not one), or already past | `401` |
| at+jwt: `nbf` not a JSON number, or later than now | `401` |

Verification accepts RS256 only (fixed, never taken from the token), requires the header to be exactly `{alg, typ, kid}` (extra parameters such as `crit` or `jwk` are refused), checks `typ`, `kid`, signature, `iss`, `aud`, `exp` and `nbf` (when present), and requires `sub`, `sub_type`, `client_id` and `scope` to be present; failure reasons are logged, **never the token**.

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
- `aud` is shared platform-wide as `mendesky-services`, so any service that receives a token can use it to call other services. This is the same as with the 1.x JWE tokens and is why token forwarding works. A `.delegatedUser` token forwarded to a downstream route that isn't opened for delegatedUser gets `401`.
- The base64 in `MENDESKY_ACCESS_TOKEN_TRUST` must be **single-line** (`base64 -w0` on GNU, `base64 -i file` on macOS); line-wrapped values fail startup.
- ⚠️ `jti` gives **no replay protection**; after a client is disabled, tokens already issued stay valid until `exp` (up to 15 minutes).
- `PermissionMiddleware` **must run after the Bearer middleware** (it reads only `Caller.current`; no caller means `401`). `.user` and `.delegatedUser` are looked up in IAM by `sub`; `.application` has no IAM user and is **never granted**, so a route open to applications must not also be a `PermissionRule` route.
- Behavior changes for existing services upgrading: token verification failures answer `401` (some used to be `503`); errors thrown by handlers: those conforming to Hummingbird's `HTTPResponseError` keep their status (404 stays 404), any other error is still a `503` (generic `service unavailable.` body, the log carries only the error type); tokens are never logged. Application tokens now require `sub_type: "application"`, and the key rules are stricter (≥ 2048 bits, no private fields).

---

## Migrating from 1.3 to 2.0

2.0 removes legacy JWE access tokens and accepts only RS256-signed at+jwt. The `try BearerTokenAuthenticationMiddleware(...)` calls in each service's `main.swift` (the `validators:`, `accepting:` and `acceptsApplication:` forms) and `try PermissionMiddleware(rules:provider:)` compile unchanged; what changes is the deployment configuration and a few APIs:

1. **The trust configuration is required**: set `MENDESKY_ACCESS_TOKEN_TRUST` or `MENDESKY_ACCESS_TOKEN_TRUST_PATH`, otherwise startup throws `BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured` (the message names only the variables). In 1.3 leaving both unset only meant "at+jwt not accepted". **The trust must list IdentityContext as the user issuer (`callerTypes: ["user"]`)**: a 1.3 trust that lists only application / delegated user issuers was fine while users came in as JWE, but on 2.0 it still starts and every first-party user gets `401`. The environment inits log one warning when no issuer is trusted for user tokens (`No issuer in the access token trust is trusted for user tokens: ...`).
2. **`MENDESKY_AUTH_*` and `MENDESKY_LEGACY_JWE` are no longer read** (`MENDESKY_AUTH_RECIPIENT_JWK`, `MENDESKY_AUTH_RECIPIENT_JWK_PATH`, `MENDESKY_AUTH_SENDER_JWK`, `MENDESKY_AUTH_SENDER_JWK_PATH`, `MENDESKY_AUTH_PASSWORD`, `MENDESKY_LEGACY_JWE`): leaving them set does not fail startup; one warning naming them (never their values) is logged. Remove them from the deployment and delete the JWE private key. (`MENDESKY_APP_TOKEN_*` still fails startup, as in 1.3.)
3. **`init(verification:…)` → `init(trust:…)`**: every init taking `verification:` is gone — Bearer's `init(verification:validators:)`, `init(verification:trust:legacyJWE:…)`, `init(verification:applicationTokens:validators:acceptsApplication:logger:)`, and `PermissionMiddleware.init(rules:provider:verification:…)`. Without the environment, use:
   ```swift
   BearerTokenAuthenticationMiddleware(trust: trust, validators: [...], accepting: [...])   // trust is not optional
   try PermissionMiddleware(rules: rules, provider: provider)
   ```
   The former `init(verification:applicationTokens:…acceptsApplication:)` becomes `init(trust:accepting: [.application(where:)])`, with the first-party user issuer in the same trust. `AccessTokenVerification` keeps only the static `bearerToken(fromHeaderValue:)` and `operatorId(fromHeaders:)`; `AccessTokenPayload`, `LegacyJWEMode`, `LegacyJWEModeError` and `BearerTokenAuthenticationMiddlewareError.recipientKeyNotFoundInEnvironment` are removed.
4. **5-segment tokens → `401`**: body `access token rejected.`, never decrypted; logged at notice as `Bearer token rejected: legacy JWE access tokens are no longer accepted` (metadata only `route` and `service`, never the token). `legacy-jwe-accepted` / `legacy-jwe-rejected` are gone.
5. **`PermissionMiddleware` needs Bearer in front**: it no longer decrypts JWE itself; with no `Caller.current`, every request matching a rule gets `401`.
6. **Tests**: replace JWE user tokens with at+jwt from `MiddlewareTesting`'s `AccessTokenTestSigner` (`subType: "user"`), with that signer in the trust as `callerTypes: [.user]`.

Rollout: deploy every service on 1.3.0 with the trust configuration (accepts both tokens) → switch IdentityContext to at+jwt → once the old JWE tokens have expired, move services to 2.0 → delete the JWE private key and `MENDESKY_AUTH_*`.

Before moving to 2.0, check on the services still running 1.3 that `legacy-jwe-accepted` has stopped appearing (the last one older than the JWE lifetime, 15 minutes for first-party JWE). 2.0 no longer logs it (see point 4), so this can only be checked on 1.3; a fresh `legacy-jwe-accepted` means someone still sends JWE and would get `401` on 2.0.

---

## Authorization: `PermissionMiddleware` (endpoint-level RBAC)

Goes after `BearerTokenAuthenticationMiddleware`. For routes covered by a rule: read `Caller.current` to get `userId` (no caller, e.g. no Bearer in front, means `401`) → fetch that user's permissions via a `PermissionsProvider` → **AND**-match (exact string match) against the rule's required permissions → allow or deny.

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

A `HEAD` request matches a rule whose `methods` include `GET` (a rule with `methods: nil` matches every method).

> ⚠️ **Do not enable Hummingbird's `RouterOptions.caseInsensitive` or `.autoGenerateHeadEndpoints` in a service using this package** (both are off by default). `PermissionRule` and `RouteAcceptance` match the request path as written (case-sensitively); with `caseInsensitive` a different-case path (`/Quotations/1`) would reach the handler without matching any rule, and with `autoGenerateHeadEndpoints` a `HEAD` request is routed to the `GET` handler (this package only widens method matching for `HEAD` vs `GET` rules).

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
| Rule matched but no `Caller.current` (no Bearer in front), or the caller is `.application` | `401` |
| Provider (IAM lookup) failed | `502` (fail-closed; 502 not 503, to distinguish an upstream-dependency failure) |
| Missing a required permission | `403` |
| All permissions present | pass through to handler |

---

## Wiring example (OCServer)

```swift
// (1) Trust configuration: BearerTokenAuthenticationMiddleware() loads MENDESKY_ACCESS_TOKEN_TRUST(_PATH) (required)

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
router.add(middleware: try PermissionMiddleware(rules: rules,              // authorization
                                                provider: provider))
router.add(middleware: LoggingMiddleware())
try api.registerHandlers(on: router, serverURL: URL(string: "/opportunity-context")!)
```

> `PermissionMiddleware` must run after `BearerTokenAuthenticationMiddleware`: it reads only `Caller.current`, so when Bearer comes after it, or is absent, every request matching a rule gets `401`.
>
> `PermissionMiddleware.init(rules:provider:)` is marked `throws` only so existing `try` call sites keep compiling; since 2.0 it reads no environment and never throws.

### Request flow

```
Frontend ──HTTP──▶ CORS ─▶ BearerTokenAuth (verify at+jwt, verify operatorId/applicationId, set Caller.current) ─▶ PermissionMiddleware ─▶ handler
                                                                                      │ 1. match rules by method/path → required permissions
                                                                                      │ 2. read Caller.current → userId (none ⇒ 401)
                                                                                      │ 3. provider fetches the user's permissions (cache hit ⇒ no IAM call)
                                                                                      │ 4. AND-match → allow / 401 / 403 / 502
                                                                                      ▼
                                                              provider miss ──HTTP──▶ IAMContext GET /employee-access/permissions/{userId}
```

A protected request must carry: `Authorization: Bearer <token>` (at+jwt) and `operatorId: <id>` (`userId` is the deprecated fallback); `.application` and `.delegatedUser` must also send `applicationId`, which `.user` may omit (the middleware fills in `mendesky-first-party`). See "Caller headers" for the values each identity sends.

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

`ProxyHeaderReceiverMiddleware` **always** captures `applicationId` (no need to list it in `presetKeys`; listing it does not capture it twice). `.application` / `.delegatedUser` requests carry `applicationId` from the caller, so it is captured whatever the middleware order; for a `.user` request the `mendesky-first-party` value Bearer fills in is captured only when the receiver runs **after** Bearer — and a downstream that receives a `.user` request without `applicationId` fills it in itself, so forwarding never breaks.

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
- **Why JWE was removed**: the 1.x JWE (ECDH-ES) had confidentiality but no issuer authentication — anyone holding the recipient **public** key could produce a valid token, and the recipient private key had to be copied to every service. 2.0 accepts only RS256-signed at+jwt; services need only the issuers' public keys.
- **Coarse-grained**: this layer is an endpoint-level check ("may you call this endpoint"); resource-level rules ("may you edit *this* record") still belong inside the handler.
