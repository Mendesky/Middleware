import Testing
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import CryptoKit
import JSONWebKey
import JSONWebEncryption
import JSONWebAlgorithms
@testable import Middleware

// MARK: - Test token plumbing (mirrors IdentityContext's JWETokenGenerator defaults)

/// One EC P-256 key reused to both encrypt (public part) and decrypt (private part) test tokens.
private let recipientKey: JWK = P256.KeyAgreement.PrivateKey().jwkRepresentation

private func makeVerification() -> AccessTokenVerification {
    AccessTokenVerification(recipientKey: recipientKey)!
}

private func makeToken(userId: String, expiresIn: TimeInterval = 3600) throws -> String {
    let payload = AccessTokenPayload(authorizationId: "a", userId: userId, clientId: "c", scope: [], expiresAt: Date(timeIntervalSinceNow: expiresIn))
    let data = try JSONEncoder().encode(payload)
    let jwe = try JWE(payload: data, keyManagementAlg: .ecdhESA256KW, encryptionAlgorithm: .a256GCM, recipientKey: recipientKey)
    return jwe.compactSerialization
}

private func bearer(_ token: String) -> HTTPFields {
    var headers = HTTPFields()
    headers[.authorization] = "Bearer \(token)"
    return headers
}

// MARK: - PermissionsProvider doubles

private func providerReturning(_ permissions: [String]) -> any PermissionsProvider {
    ClosurePermissionsProvider { _ in permissions }
}

private struct FailingProvider: PermissionsProvider {
    struct Boom: Error {}
    func permissions(forUserId userId: String) async throws -> [String] { throw Boom() }
}

// MARK: - App under test

private func makeApp(rules: [PermissionRule], provider: any PermissionsProvider) -> some ApplicationProtocol {
    let router = Router()
    router.add(middleware: PermissionMiddleware(rules: rules, provider: provider, verification: makeVerification()))
    router.get("quotations/:id") { _, _ in "ok" }
    router.get("public/info") { _, _ in "ok" }
    router.get("secure") { _, _ in "ok" }
    return Application(router: router)
}

/// PathValidator's String init is a *literal* match; use the Regex initializer for patterns.
private func pathRule(_ pattern: String, methods: Set<HTTPRequest.Method>? = nil, requires: [String]) throws -> PermissionRule {
    PermissionRule(PathValidator(try Regex(pattern)), methods: methods, requires: requires)
}

@Suite struct PermissionMiddlewareTests {
    /// 有所需權限 → 放行。
    /// 規則要求 `business:read`，provider 回傳的權限集合含 `business:read`，
    /// 帶著有效 token 打受保護路由 → 預期 200 OK（成功通過 middleware 進到 handler）。
    @Test func allowsWhenProviderReturnsRequiredPermission() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning(["business:read", "other:thing"]))
        let token = try makeToken(userId: "u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(token))
            #expect(res.status == .ok)
        }
    }

    /// 缺所需權限 → 擋下。
    /// token 有效，但 provider 回傳的權限不含 `business:read` → 預期 403 Forbidden
    /// （已認證、但沒有這個權限，屬「授權」失敗，不是「認證」失敗）。
    @Test func forbidsWhenProviderLacksRequiredPermission() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning(["something:else"]))
        let token = try makeToken(userId: "u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(token))
            #expect(res.status == .forbidden)
        }
    }

    /// 命中規則但沒帶 token → 401。
    /// 路由有權限規則，但請求沒有 Authorization header（拿不到可信的 userId）→ 預期 401 Unauthorized。
    /// 此情況不會去呼叫 provider（連是誰都不知道，無從查權限）。
    @Test func unauthorizedWhenTokenMissing() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning(["business:read"]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get)  // 沒有 Authorization header
            #expect(res.status == .unauthorized)
        }
    }

    /// provider（IAMContext 查詢）失敗 → fail-closed 不放行，回 502。
    /// 查不到權限時寧可擋下也不放行；用 502 Bad Gateway 而非 503，
    /// 是要把「上游依賴故障」跟「本服務自身故障」在 log/告警上區分開。
    @Test func badGatewayWhenProviderFails() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: FailingProvider())
        let token = try makeToken(userId: "u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(token))
            #expect(res.status == .badGateway)
        }
    }

    /// 沒有規則涵蓋的路由 → 直接放行。
    /// `/public/info` 不符合任何規則 → middleware 不介入（不需 token、也不會去查 provider）→ 預期 200。
    @Test func passesWhenNoRuleCoversPath() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        // 不帶 token、provider 不會被呼叫；非受保護路由仍應放行。
        let app = makeApp(rules: [rule], provider: providerReturning([]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/public/info", method: .get)
            #expect(res.status == .ok)
        }
    }

    /// HTTP method 過濾：規則只管 GET，對同路徑的 POST 不適用。
    /// 規則 `methods: [.get]`，但打的是 POST → 不被此規則涵蓋，middleware 不介入。
    /// （沒註冊 POST handler，最終由 router 回 404；重點是「不會被權限擋成 401/403」。）
    @Test func methodFilterExcludesNonMatchingVerb() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning([]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .post)  // 規則只涵蓋 GET
            #expect(res.status != .unauthorized)
            #expect(res.status != .forbidden)
        }
    }

    /// OPTIONS（CORS preflight）一律略過權限檢查。
    /// 即使路徑命中規則、即使沒帶 token，OPTIONS 也不該被擋（不會 401/403）——
    /// 規則用不限 method 的 `/secure`，故意湊出「會命中」的條件來驗證 OPTIONS 仍被略過。
    @Test func skipsOptionsEvenWhenRuleMatches() async throws {
        let rule = try pathRule("/secure", requires: ["x"])  // 不限 method
        let app = makeApp(rules: [rule], provider: providerReturning([]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/secure", method: .options)  // 沒帶 token
            #expect(res.status != .unauthorized)
            #expect(res.status != .forbidden)
        }
    }

    /// 一條規則列多個權限時採 AND（要全部具備才放行）。
    /// 規則要求 `business:read` + `business:write`，但 provider 只回 `business:read`
    /// （缺 `business:write`）→ 預期 403。
    @Test func multipleRequiredPermissionsNeedAll() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read", "business:write"])
        let app = makeApp(rules: [rule], provider: providerReturning(["business:read"]))  // 缺 business:write
        let token = try makeToken(userId: "u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(token))
            #expect(res.status == .forbidden)
        }
    }

    /// 過期 token → 401。
    /// 受保護路由帶了一個 expiresAt 已過去的 token；自解密回 nil → 拿不到可信 userId → 401（不查 provider）。
    @Test func unauthorizedWhenTokenExpired() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning(["business:read"]))
        let expired = try makeToken(userId: "u1", expiresIn: -10)  // already expired
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(expired))
            #expect(res.status == .unauthorized)
        }
    }

    /// 格式錯誤 / 無法解密的 token → 401。
    /// 帶 `Authorization: Bearer <garbage>`；解密丟錯被 try? 吞成 nil → 401。
    @Test func unauthorizedWhenTokenMalformed() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning(["business:read"]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer("not-a-valid-jwe"))
            #expect(res.status == .unauthorized)
        }
    }
}
