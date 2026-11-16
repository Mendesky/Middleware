import Testing
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import NIOCore
import RegexBuilder
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import JSONWebKey
import JSONWebEncryption
@testable import Middleware

// Hummingbird's router splits the path on "/" and drops empty segments (Trie+resolve.swift),
// so `/a/b/`, `//a/b` and `/a//b` reach the same handler as `/a/b`. PathValidator must match
// the same way, otherwise a rule or whitelist written for `/a/b` is skipped by those variants.

private func request(_ path: String) -> Request {
    Request(
        head: HTTPRequest(method: .get, scheme: nil, authority: nil, path: path),
        body: RequestBody(buffer: ByteBuffer())
    )
}

private let variants = ["/a/b", "/a/b/", "//a/b", "/a//b", "/a/b//", "//a//b//"]

private let recipientKey: JWK = P256.KeyAgreement.PrivateKey().jwkRepresentation

private func userToken(_ userId: String) throws -> String {
    let payload = AccessTokenPayload(authorizationId: "a", userId: userId, clientId: "c", scope: [], expiresAt: Date(timeIntervalSinceNow: 3600))
    let jwe = try JWE(payload: try JSONEncoder().encode(payload), keyManagementAlg: .ecdhESA256KW, encryptionAlgorithm: .a256GCM, recipientKey: recipientKey)
    return jwe.compactSerialization
}

private func bearer(_ token: String) -> HTTPFields {
    var h = HTTPFields()
    h[.authorization] = "Bearer \(token)"
    return h
}

@Suite struct PathValidatorTests {
    @Test(arguments: variants) func stringInitMatchesVariants(path: String) {
        #expect(PathValidator("/a/b").isWhitelisted(request(path)))
    }

    @Test(arguments: variants) func regexInitMatchesVariants(path: String) throws {
        #expect(PathValidator(try Regex("/a/.+")).isWhitelisted(request(path)))
    }

    @Test(arguments: variants) func builderInitMatchesVariants(path: String) {
        let validator = PathValidator { "/a/"; OneOrMore(.word) }
        #expect(validator.isWhitelisted(request(path)))
    }

    @Test func rootVariantsMatchRoot() {
        for path in ["/", "//", "///"] {
            #expect(PathValidator("/").isWhitelisted(request(path)))
        }
    }

    @Test func differentPathsStillDoNotMatch() {
        #expect(!PathValidator("/a/b").isWhitelisted(request("/a/b/c")))
        #expect(!PathValidator("/a/b").isWhitelisted(request("/a")))
        #expect(!PathValidator("/a/b").isWhitelisted(request("/ab")))
    }

    /// Router does not decode percent-encoding or resolve dot segments; neither may the validator.
    @Test func doesNotDecodeOrResolveDotSegments() {
        #expect(!PathValidator("/a/b").isWhitelisted(request("/a/./b")))
        #expect(!PathValidator("/a/b").isWhitelisted(request("/a/c/../b")))
        #expect(!PathValidator("/a/b").isWhitelisted(request("/a/%62")))
    }

    // MARK: end to end

    private func permissionApp(provider: any PermissionsProvider) -> some ApplicationProtocol {
        let rule = PermissionRule(PathValidator("/quotations/1"), methods: [.get], requires: ["business:read"])
        let router = Router()
        router.add(middleware: PermissionMiddleware(rules: [rule], provider: provider, verification: AccessTokenVerification(recipientKey: recipientKey)!))
        router.get("quotations/:id") { _, _ in "ok" }
        return Application(router: router)
    }

    @Test(arguments: ["/quotations/1", "/quotations/1/", "//quotations/1", "/quotations//1"])
    func permissionRuleForbidsCallerLackingPermission(uri: String) async throws {
        let app = permissionApp(provider: ClosurePermissionsProvider { _ in ["other:thing"] })
        let token = try userToken("u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: uri, method: .get, headers: bearer(token))
            #expect(res.status == .forbidden)
        }
    }

    @Test(arguments: ["/quotations/1", "/quotations/1/", "//quotations/1", "/quotations//1"])
    func permissionRuleAllowsCallerWithPermission(uri: String) async throws {
        let app = permissionApp(provider: ClosurePermissionsProvider { _ in ["business:read"] })
        let token = try userToken("u1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: uri, method: .get, headers: bearer(token))
            #expect(res.status == .ok)
        }
    }

    @Test(arguments: ["/health", "/health/", "//health", "/health//"])
    func whitelistedPathVariantsSkipAuthentication(uri: String) async throws {
        let router = Router()
        router.add(middleware: BearerTokenAuthenticationMiddleware(
            verification: AccessTokenVerification(recipientKey: recipientKey)!,
            validators: [PathValidator("/health")]))
        router.get("health") { _, _ in "ok" }
        router.get("secure") { _, _ in "ok" }
        let app = Application(router: router)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: uri, method: .get)  // no token
            #expect(res.status == .ok)
            let secure = try await client.execute(uri: "/secure", method: .get)
            #expect(secure.status == .unauthorized)
        }
    }
}
