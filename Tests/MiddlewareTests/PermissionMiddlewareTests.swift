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

private func makeToken(userId: String) throws -> String {
    let payload = AccessTokenPayload(authorizationId: "a", userId: userId, clientId: "c", scope: [], expiresAt: Date(timeIntervalSinceNow: 3600))
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
    @Test func allowsWhenProviderReturnsRequiredPermission() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning(["business:read", "other:thing"]))
        let token = try makeToken(userId: "u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(token))
            #expect(res.status == .ok)
        }
    }

    @Test func forbidsWhenProviderLacksRequiredPermission() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning(["something:else"]))
        let token = try makeToken(userId: "u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(token))
            #expect(res.status == .forbidden)
        }
    }

    @Test func unauthorizedWhenTokenMissing() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning(["business:read"]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get)  // no Authorization header
            #expect(res.status == .unauthorized)
        }
    }

    @Test func badGatewayWhenProviderFails() async throws {
        // fail-closed: provider error must not allow the request through; 502 (upstream dependency failed).
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: FailingProvider())
        let token = try makeToken(userId: "u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(token))
            #expect(res.status == .badGateway)
        }
    }

    @Test func passesWhenNoRuleCoversPath() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        // No token, provider not consulted — an unprotected path must still pass.
        let app = makeApp(rules: [rule], provider: providerReturning([]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/public/info", method: .get)
            #expect(res.status == .ok)
        }
    }

    @Test func methodFilterExcludesNonMatchingVerb() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read"])
        let app = makeApp(rules: [rule], provider: providerReturning([]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .post)  // rule covers GET only
            #expect(res.status != .unauthorized)
            #expect(res.status != .forbidden)
        }
    }

    @Test func skipsOptionsEvenWhenRuleMatches() async throws {
        let rule = try pathRule("/secure", requires: ["x"])  // any method
        let app = makeApp(rules: [rule], provider: providerReturning([]))
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/secure", method: .options)  // no token
            #expect(res.status != .unauthorized)
            #expect(res.status != .forbidden)
        }
    }

    @Test func multipleRequiredPermissionsNeedAll() async throws {
        let rule = try pathRule("/quotations/.+", methods: [.get], requires: ["business:read", "business:write"])
        let app = makeApp(rules: [rule], provider: providerReturning(["business:read"]))  // missing business:write
        let token = try makeToken(userId: "u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/123", method: .get, headers: bearer(token))
            #expect(res.status == .forbidden)
        }
    }
}
