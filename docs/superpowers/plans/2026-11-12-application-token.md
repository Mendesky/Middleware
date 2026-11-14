# Application Token Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let services verify OIDCContext-signed application tokens (RS256 JWT, `typ: at+jwt`) next to the existing user JWE, and tell a handler whether the caller is a user or an application.

**Architecture:** A new `ApplicationTokenVerification` checks a compact JWS against OIDCContext's application-token public keys (picked by `kid`), issuer, audience and expiry, and returns `ApplicationTokenClaims`. `BearerTokenAuthenticationMiddleware` routes a 3-segment bearer to it only on routes the service opts in to, and publishes the caller in a `TaskLocal` (`Caller.current`). A `Scope` helper gives every service the same "has X or `*`" check. User-token behavior is unchanged except that failures no longer log the token and answer 401 instead of 503.

**Tech Stack:** Swift 6, Hummingbird 2, jose-swift 6.0.x (`JSONWebSignature`, `JSONWebKey`), swift-crypto `_CryptoExtras` (tests and the testing library only).

**Spec:** Application 憑證與通知送出 API — https://claude.ai/artifact/G2weGnGd9HgAfyiWqhxKyw (local copy: `/private/tmp/claude-501/-Volumes-Development-NotificationContext/68842528-5dbf-456b-bc9d-dd12bff652a9/scratchpad/app-credential-design.html`). Sections used: 〈OIDCContext › 換 token〉 for the token format, 〈Middleware〉 for behavior.

## Global Constraints

- Do not modify swift-ddd-kit. Keep jose-swift at `"6.0.0"..<"6.0.5"` (see the Package.swift comment).
- Token format (spec): compact JWS, header `alg: RS256`, `typ: at+jwt`, `kid`; claims `iss`, `aud`, `sub` (= applicationId), `client_id`, `scope` (space-delimited string, RFC 9068), `iat`, `exp`, `jti`. `aud` may be a string or an array; it must contain the configured audience (OIDCContext issues `mendesky-services`).
- Application tokens are signed with their own RSA key, not the ID Token key. Every configured public key must carry a `kid`; a token is checked only against the key whose `kid` matches its header. Several keys may be configured at once so a rotation can overlap.
- Required claims: `client_id` and `scope` must be present (`scope` may be `""` only if it is present — an absent claim is rejected), so an OIDC ID Token (`typ: JWT`, no `client_id`/`scope`, `aud` = a client id) can never pass.
- `jti` is an identifier only; there is no replay protection, and a disabled client's tokens stay valid until `exp` (≤ 15 minutes). Docs must not claim otherwise.
- `applicationId` is exposed lowercased.
- Scope names: `*` (all resources) and `notification:send`. Only `*` is issued in this rollout.
- Keys, issuer and audience come from the environment: `MENDESKY_APP_TOKEN_JWKS` (base64 of a JWK Set JSON, `{"keys":[…]}`) or `MENDESKY_APP_TOKEN_JWKS_PATH` (file path to the JWK Set JSON), plus `MENDESKY_APP_TOKEN_ISSUER` and `MENDESKY_APP_TOKEN_AUDIENCE`. No runtime fetch of `/jwks`.
- Services accept application tokens only on routes they opt in to; the default accepts none.
- User tokens: unchanged, including the `operatorId` == `userId` check. Application tokens need no `operatorId`.
- No log line may contain a bearer token.
- PR targets main; work happens in this worktree (`feat/application-token`).

## Review Focus

1. A JWS-shaped bearer on a route that has not opted in → 401, never 503, never forwarded (Task 3).
2. `sub` sent in uppercase → `applicationId` comes out lowercased (Task 1).
3. A valid signature but `typ` missing, or `alg: none`/`HS256` → rejected; an `alg: none` token must never pass. An ID-Token-shaped JWT signed by a configured key (`typ: JWT`, no `client_id`/`scope`, `aud` = a client id) → rejected (Task 1).
4. `exp` equal to now → expired (Task 1).
5. A user JWE that fails to decrypt → 401 and the log line carries no token text (Task 3).
6. Rotation: with two keys configured, tokens from either `kid` pass; a token with no `kid` or an unknown `kid` → rejected (Task 1).

---

### Task 1: ApplicationTokenVerification and Scope

**Files:**
- Create: `Sources/Middleware/ApplicationToken/ApplicationTokenVerification.swift`
- Create: `Sources/Middleware/ApplicationToken/Scope.swift`
- Create: `Sources/MiddlewareTesting/ApplicationTokenTestSigner.swift` (new library product `MiddlewareTesting`)
- Modify: `Package.swift` (add `MiddlewareTesting` target + product, depends on `Middleware`, `jose-swift`, `_CryptoExtras` from swift-crypto; add swift-crypto `"3.0.0"..<"4.0.0"` as a direct dependency)
- Test: `Tests/MiddlewareTests/ApplicationTokenVerificationTests.swift`

**Interfaces:**
- Produces:
  - `public struct ApplicationTokenClaims: Sendable, Equatable { public let applicationId: String; public let clientId: String; public let scope: [String]; public let issuer: String; public let expiresAt: Date }`
  - `public enum ApplicationTokenError: Error, Equatable { case malformed, unsupportedAlgorithm, wrongType, unknownKey, badSignature, wrongIssuer, wrongAudience, expired, missingClaim(String) }`
  - `public enum ApplicationTokenConfigurationError: Error, Equatable { case keySetUnreadable, keyWithoutKid, emptyKeySet, missingIssuer, missingAudience }`
  - `public struct ApplicationTokenVerification: Sendable { public init(publicKeys: [JWK], issuer: String, audience: String, now: @escaping @Sendable () -> Date = { Date() }) throws(ApplicationTokenConfigurationError); public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) throws(ApplicationTokenConfigurationError) -> ApplicationTokenVerification?; public func verify(compactString: String) throws(ApplicationTokenError) -> ApplicationTokenClaims }`
  - `public enum Scope { public static let all = "*"; public static let notificationSend = "notification:send"; public static func grants(_ held: [String], _ required: String) -> Bool }`
  - `MiddlewareTesting`: `public struct ApplicationTokenTestSigner: Sendable { public static let defaultIssuer = "https://oidc.test"; public static let defaultAudience = "mendesky-services"; public init(kid: String = "app-test-1", issuer: String = defaultIssuer); public var publicKey: JWK { get }; public static func keySetBase64(_ signers: [ApplicationTokenTestSigner]) -> String; public func token(sub: String, clientId: String? = "client-1", scope: String? = "*", audience: [String]? = [defaultAudience], expiresIn: TimeInterval = 900, typ: String? = "at+jwt", kid: String?? = .none, issuer: String? = nil) -> String }` — `nil` for `clientId`/`scope`/`audience`/`typ` omits that field; `kid: .some(nil)` omits the header `kid`, `.none` uses the signer's own.

- [ ] **Step 1: Write the failing tests**

```swift
@Test func verifiesAValidToken() throws {
    let signer = ApplicationTokenTestSigner()
    let v = try ApplicationTokenVerification(publicKeys: [signer.publicKey], issuer: "https://oidc.test", audience: "mendesky-services")
    let claims = try v.verify(compactString: signer.token(sub: "3F2A9C1E-7B4D-4C1A-9E2F-0A1B2C3D4E5F", scope: "* notification:send"))
    #expect(claims.applicationId == "3f2a9c1e-7b4d-4c1a-9e2f-0a1b2c3d4e5f")
    #expect(claims.clientId == "client-1")
    #expect(claims.scope == ["*", "notification:send"])
}
@Test func rejectsWrongIssuer()      // issuer: "https://other" → .wrongIssuer
@Test func rejectsMissingType()      // typ: nil → .wrongType
@Test func rejectsExpiredAtTheBoundary() // now = exp exactly → .expired
@Test func rejectsAnotherKeysSignature() // second signer with the same kid but its own key → .badSignature
@Test func rejectsAlgNone()          // hand-built "eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.<claims>." → .unsupportedAlgorithm
@Test func rejectsFiveSegmentJWE()   // "a.b.c.d.e" → .malformed
@Test func rejectsMissingClientId()  // claims without client_id → .missingClaim("client_id")
@Test func rejectsMissingScope()     // claims without scope → .missingClaim("scope")
@Test func rejectsWrongAudience()    // audience: ["other"] → .wrongAudience; audience: nil → .wrongAudience
@Test func acceptsAudienceAsString() // aud: "mendesky-services" (string, not array) → passes
@Test func rejectsIdTokenShape()     // typ: "JWT", clientId: nil, scope: nil, audience: ["outline-client"] → rejected (.wrongType first)
@Test func picksKeyByKid()           // signers A (kid a) and B (kid b) both configured → tokens from both pass
@Test func rejectsUnknownKid()       // token from signer C (kid c) not configured → .unknownKey
@Test func rejectsMissingKid()       // kid: .some(nil) → .unknownKey
@Test func keyWithoutKidIsAConfigurationError() // init with a JWK lacking kid → throws .keyWithoutKid
@Test func fromEnvironmentIsNilWithoutKeys()     // [:] → nil
@Test func fromEnvironmentThrowsWithoutIssuerOrAudience() // only MENDESKY_APP_TOKEN_JWKS set → .missingIssuer; + issuer → .missingAudience
@Test func scopeGrants() {
    #expect(Scope.grants(["*"], Scope.notificationSend))
    #expect(Scope.grants(["notification:send"], Scope.notificationSend))
    #expect(!Scope.grants(["other"], Scope.notificationSend))
    #expect(!Scope.grants([], Scope.notificationSend))
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `swift test --filter ApplicationTokenVerificationTests`
Expected: build failure, `ApplicationTokenVerification` not found.

- [ ] **Step 3: Implement**

`verify`: split on `.` — not exactly 3 segments → `.malformed`; parse with `JWS(jwsString:)`; `alg` must be `RS256` else `.unsupportedAlgorithm`; `typ` must be `at+jwt` or `application/at+jwt` (case-insensitive) else `.wrongType`; header `kid` must match a configured key else `.unknownKey`; `jws.verify(key:)` with that key false → `.badSignature`; decode claims JSON; check `iss`, then `aud` (string or array) contains the audience, then `exp > now()` (strictly), then non-blank `sub` and `client_id`, then `scope` present; `scope` split on spaces, empty entries dropped. `init` stores keys by `kid` (missing `kid` → `.keyWithoutKid`, empty list → `.emptyKeySet`). `fromEnvironment`: neither JWKS variable → `nil`; otherwise read the set (base64 or file; unreadable → `.keySetUnreadable`), then issuer and audience must be non-blank. The signer generates one RSA-2048 key per instance with `_RSA.Signing.PrivateKey(keySize: .bits2048)` and signs with jose-swift.

- [ ] **Step 4: Run to verify they pass**

Run: `swift test --filter ApplicationTokenVerificationTests`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add Package.swift Sources/Middleware/ApplicationToken Sources/MiddlewareTesting Tests/MiddlewareTests/ApplicationTokenVerificationTests.swift
git commit -m "feat: verify OIDCContext application tokens (RS256 at+jwt) and add Scope"
```

### Task 2: Caller identity

**Files:**
- Create: `Sources/Middleware/ApplicationToken/Caller.swift`
- Test: folded into Task 3's tests

**Interfaces:**
- Produces: `public enum CallerIdentity: Sendable, Equatable { case user(userId: String, clientId: String); case application(ApplicationTokenClaims) }` and `public enum Caller { @TaskLocal public static var current: CallerIdentity? }`

- [ ] **Step 1: Add the two types** (no logic; Task 3 sets the value).
- [ ] **Step 2: Build** — Run: `swift build` — Expected: success.
- [ ] **Step 3: Commit** — `git commit -am "feat: Caller.current task-local identity"`

### Task 3: BearerTokenAuthenticationMiddleware accepts application tokens on opted-in routes

**Files:**
- Modify: `Sources/Middleware/BearerTokenAuthentication/BearerTokenAuthenticationMiddleware.swift`
- Test: `Tests/MiddlewareTests/BearerApplicationTokenTests.swift`

**Interfaces:**
- Consumes: Task 1 `ApplicationTokenVerification`, Task 2 `Caller`.
- Produces (new initializers; the two existing ones keep their signatures and behavior):
  - `public init(validators: [any WhitelistValidator] = [], acceptsApplication: @escaping @Sendable (Request) -> Bool) throws` — loads both `AccessTokenVerification.fromEnvironment()` and `ApplicationTokenVerification.fromEnvironment()`.
  - `public init(verification: AccessTokenVerification, applicationTokens: ApplicationTokenVerification?, validators: [any WhitelistValidator] = [], acceptsApplication: @escaping @Sendable (Request) -> Bool)`
  - The existing initializers behave as `acceptsApplication: { _ in false }`.

- [ ] **Step 1: Write the failing tests** (HummingbirdTesting router with one route that echoes `Caller.current`)

```swift
@Test func applicationTokenOnOptedInRoutePasses()      // GET /open with signer token → 200, body "application:<lowercased sub>"
@Test func applicationTokenNeedsNoOperatorId()          // same request without operatorId header → 200
@Test func applicationTokenOnOtherRouteIs401()          // GET /closed (not opted in) → 401
@Test func applicationTokenWithoutConfiguredKeyIs401()  // applicationTokens: nil → 401
@Test func badApplicationTokenIs401()                   // wrong key → 401
@Test func userTokenStillRequiresOperatorId()           // existing JWE path unchanged; Caller.current == .user(...)
@Test func undecryptableJWEIs401AndNotLogged()          // garbage 5-segment token → 401; captured log output does not contain the token string
```

Use a capturing `LogHandler` for the last test (bootstrap a per-test `Logger` via an injectable logger property if needed — add `logger` as an init parameter with the current label as default).

- [ ] **Step 2: Run to verify they fail**

Run: `swift test --filter BearerApplicationTokenTests`
Expected: compile failure on the new initializers.

- [ ] **Step 3: Implement**

In `handle`: after whitelist/OPTIONS and bearer extraction, count `.` segments. 3 segments → if `applicationTokens != nil && acceptsApplication(input)` verify and run `next` inside `Caller.$current.withValue(.application(claims))`; any other 3-segment case or a verify error → 401 with body `"application token rejected."`. 5 segments → current user path, with `next` inside `Caller.$current.withValue(.user(userId:clientId:))`. Both `catch` branches → 401, log only the error type (`"\(type(of: error))"`), no `accesstoken` metadata.

- [ ] **Step 4: Run all tests**

Run: `swift test`
Expected: all pass, including the existing `MiddlewareTests` and `PermissionMiddlewareTests`.

- [ ] **Step 5: Commit** — `git commit -am "feat: bearer middleware accepts application tokens on opted-in routes; never log tokens"`

### Task 4: PermissionMiddleware refuses application callers; docs

**Files:**
- Test: `Tests/MiddlewareTests/PermissionMiddlewareTests.swift` (add one test)
- Modify: `README.md`, `README.en.md`, `CLAUDE.md` (environment variables, key rotation with several `kid`s, `Caller`, `Scope`, `MiddlewareTesting`; state that `jti` gives no replay protection and a disabled client's tokens last until `exp`)

- [ ] **Step 1: Write the test** — `applicationTokenOnRuledRouteIsRefused`: a request whose bearer is a signer token on a path that a `PermissionRule` matches → status is 401 and the provider is never called. (Current code already refuses because the token does not decrypt as JWE; the test pins it.)
- [ ] **Step 2: Run** — `swift test --filter PermissionMiddlewareTests` — Expected: pass.
- [ ] **Step 3: Update the READMEs and CLAUDE.md** with the four new environment variables (`MENDESKY_APP_TOKEN_JWKS` / `_JWKS_PATH`, `_ISSUER`, `_AUDIENCE`), how to rotate (add the new key, deploy, switch OIDCContext, remove the old key), the opt-in initializer, `Caller.current`, `Scope.grants`, and `MiddlewareTesting.ApplicationTokenTestSigner`.
- [ ] **Step 4: Commit** — `git commit -am "test: permission middleware refuses application tokens; docs for application tokens"`

After merge: tag `1.3.0` (new public API; existing behavior changes only in failure status/logging).
