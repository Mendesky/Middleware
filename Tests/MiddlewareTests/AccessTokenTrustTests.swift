import Testing
import Foundation
import JSONWebKey
@testable import Middleware
import MiddlewareTesting

private let ic = ApplicationTokenTestSigner(kid: "ic-1", issuer: "https://identity.test")
private let oc = ApplicationTokenTestSigner(kid: "oc-1")
private let audience = ApplicationTokenTestSigner.defaultAudience

private func expectError(_ expected: AccessTokenTrustError, _ body: () throws -> Void) {
    do {
        try body()
        Issue.record("expected \(expected), but construction succeeded")
    } catch {
        #expect(error as? AccessTokenTrustError == expected)
    }
}

private func trust(_ issuers: [TrustedIssuer], audience: String = audience) throws -> AccessTokenTrust {
    try AccessTokenTrust(audience: audience, issuers: issuers)
}

private func json(_ object: [String: Any]) -> Data {
    // swiftlint:disable:next force_try
    try! JSONSerialization.data(withJSONObject: object)
}

private func jwkObject(_ key: JWK) -> [String: Any] {
    // swiftlint:disable:next force_try
    try! JSONSerialization.jsonObject(with: JSONEncoder().encode(key)) as! [String: Any]
}

private func trustJSON(keys: [[String: Any]], callerTypes: [String] = ["application"]) -> Data {
    json([
        "audience": audience,
        "issuers": [["issuer": "https://oidc.test", "callerTypes": callerTypes, "keys": ["keys": keys]]],
    ])
}

@Suite struct AccessTokenTrustTests {
    @Test func acceptsTheSpecShape() throws {
        let trust = try trust([
            ic.trustedIssuer(callerTypes: [.user]),
            oc.trustedIssuer(callerTypes: [.application, .delegatedUser], actors: ["mendesky-mcp-server"]),
        ])
        #expect(trust.issuers.map(\.issuer) == ["https://identity.test", "https://oidc.test"])
        #expect(trust.issuer(named: "https://oidc.test")?.actors == ["mendesky-mcp-server"])
        #expect(trust.issuer(named: "https://nobody.test") == nil)
        #expect(trust.key(issuer: "https://oidc.test", kid: "oc-1") != nil)
        #expect(trust.key(issuer: "https://identity.test", kid: "oc-1") == nil)
    }

    @Test func noUserIssuerIsFine() throws {
        _ = try trust([oc.trustedIssuer(callerTypes: [.application])])
    }

    @Test func fromEnvironmentIsNilWhenUnset() throws {
        #expect(try AccessTokenTrust.fromEnvironment([:]) == nil)
        #expect(try AccessTokenTrust.fromEnvironment(["MENDESKY_ACCESS_TOKEN_TRUST": "  "]) == nil)
    }

    @Test func fromEnvironmentLoadsBase64AndPrefersPath() throws {
        let icBase64 = ApplicationTokenTestSigner.trustBase64(issuers: [ic.trustedIssuer(callerTypes: [.user])])
        let fromBase64 = try AccessTokenTrust.fromEnvironment(["MENDESKY_ACCESS_TOKEN_TRUST": icBase64])
        #expect(fromBase64?.issuers.map(\.issuer) == ["https://identity.test"])

        let ocBase64 = ApplicationTokenTestSigner.trustBase64(issuers: [oc.trustedIssuer(callerTypes: [.application])])
        let file = FileManager.default.temporaryDirectory.appending(path: "trust-\(UUID().uuidString).json")
        try #require(Data(base64Encoded: ocBase64)).write(to: file)
        defer { try? FileManager.default.removeItem(at: file) }
        let fromPath = try AccessTokenTrust.fromEnvironment([
            "MENDESKY_ACCESS_TOKEN_TRUST": icBase64,
            "MENDESKY_ACCESS_TOKEN_TRUST_PATH": file.path,
        ])
        #expect(fromPath?.issuers.map(\.issuer) == ["https://oidc.test"])
    }

    @Test func unreadableTrustRefuses() {
        expectError(.unreadable) { _ = try AccessTokenTrust.fromEnvironment(["MENDESKY_ACCESS_TOKEN_TRUST": "%%%"]) }
        expectError(.unreadable) {
            _ = try AccessTokenTrust.fromEnvironment(["MENDESKY_ACCESS_TOKEN_TRUST_PATH": "/nonexistent/trust.json"])
        }
        expectError(.unreadable) {
            _ = try AccessTokenTrust.fromEnvironment(["MENDESKY_ACCESS_TOKEN_TRUST": Data("{}".utf8).base64EncodedString()])
        }
    }

    @Test func oldApplicationTokenVariablesRefuseToStart() {
        expectError(.renamedVariable("MENDESKY_APP_TOKEN_JWKS")) {
            _ = try AccessTokenTrust.fromEnvironment(["MENDESKY_APP_TOKEN_JWKS": "x"])
        }
        let valid = ApplicationTokenTestSigner.trustBase64(issuers: [oc.trustedIssuer(callerTypes: [.application])])
        expectError(.renamedVariable("MENDESKY_APP_TOKEN_ISSUER")) {
            _ = try AccessTokenTrust.fromEnvironment([
                "MENDESKY_APP_TOKEN_ISSUER": "x", "MENDESKY_ACCESS_TOKEN_TRUST": valid,
            ])
        }
    }

    @Test func renamedVariableDescriptionNamesTheReplacements() {
        let text = String(describing: AccessTokenTrustError.renamedVariable("MENDESKY_APP_TOKEN_JWKS"))
        #expect(text.contains("MENDESKY_APP_TOKEN_JWKS"))
        #expect(text.contains("MENDESKY_ACCESS_TOKEN_TRUST_PATH"))
        #expect(text.replacingOccurrences(of: "MENDESKY_ACCESS_TOKEN_TRUST_PATH", with: "").contains("MENDESKY_ACCESS_TOKEN_TRUST"))
    }

    @Test func missingAudienceRefuses() {
        expectError(.missingAudience) { _ = try trust([oc.trustedIssuer(callerTypes: [.application])], audience: "  ") }
    }

    @Test func noIssuersRefuses() {
        expectError(.noIssuers) { _ = try trust([]) }
    }

    @Test func blankIssuerRefuses() {
        let blank = TrustedIssuer(issuer: " ", callerTypes: [.application], publicKeys: [oc.publicKey])
        expectError(.blankIssuer) { _ = try trust([blank]) }
    }

    @Test func twoUserIssuersRefuse() {
        expectError(.multipleUserIssuers) {
            _ = try trust([ic.trustedIssuer(callerTypes: [.user]), oc.trustedIssuer(callerTypes: [.user])])
        }
    }

    @Test func userIssuerAllowingAnythingElseRefuses() {
        expectError(.userIssuerAllowsOtherCallerTypes(issuer: "https://identity.test")) {
            _ = try trust([ic.trustedIssuer(callerTypes: [.user, .application])])
        }
    }

    @Test func delegatedUserWithoutActorsRefuses() {
        expectError(.delegatedUserWithoutActors(issuer: "https://oidc.test")) {
            _ = try trust([oc.trustedIssuer(callerTypes: [.delegatedUser], actors: [])])
        }
    }

    @Test func duplicateIssuerRefuses() {
        expectError(.duplicateIssuer("https://oidc.test")) {
            _ = try trust([oc.trustedIssuer(callerTypes: [.application]), oc.trustedIssuer(callerTypes: [.application])])
        }
    }

    @Test func kidUnderTwoIssuersRefuses() {
        let a = ApplicationTokenTestSigner(kid: "k", issuer: "https://a.test")
        let b = ApplicationTokenTestSigner(kid: "k", issuer: "https://b.test")
        expectError(.duplicateKid("k")) {
            _ = try trust([a.trustedIssuer(callerTypes: [.application]), b.trustedIssuer(callerTypes: [.application])])
        }
    }

    @Test func emptyCallerTypesRefuses() {
        expectError(.noCallerTypes(issuer: "https://oidc.test")) { _ = try trust([oc.trustedIssuer(callerTypes: [])]) }
    }

    @Test func unknownCallerTypeRefuses() {
        let data = trustJSON(keys: [jwkObject(oc.publicKey)], callerTypes: ["robot"])
        expectError(.unknownCallerType("robot")) { _ = try AccessTokenTrust(json: data) }
    }

    @Test func privateKeyMaterialRefuses() throws {
        var key = oc.publicKey
        key.d = Data(repeating: 1, count: 256)
        let data = try JSONEncoder().encode(key)
        // Proves decoding keeps `d`, so the rejection below is not vacuous.
        #expect(try JSONDecoder().decode(JWK.self, from: data).d != nil)
        expectError(.privateKeyMaterial(kid: "oc-1")) { _ = try AccessTokenTrust(json: trustJSON(keys: [jwkObject(key)])) }
        expectError(.privateKeyMaterial(kid: "oc-1")) {
            _ = try trust([TrustedIssuer(issuer: "https://oidc.test", callerTypes: [.application], publicKeys: [key])])
        }
    }

    @Test func crtOnlyPrivateMemberRefuses() {
        // jose-swift drops dp/dq/qi when decoding, so this only works by checking the raw JSON members.
        for member in ["dp", "dq", "qi", "p", "q"] {
            var key = jwkObject(oc.publicKey)
            key[member] = "AQAB"
            expectError(.privateKeyMaterial(kid: "oc-1")) { _ = try AccessTokenTrust(json: trustJSON(keys: [key])) }
        }
    }

    @Test func shortKeyRefuses() {
        let key = JWK(keyType: .rsa, algorithm: "RS256", keyID: "short", e: Data([1, 0, 1]), n: Data(repeating: 0xC1, count: 128))
        expectError(.keyTooShort(kid: "short")) {
            _ = try trust([TrustedIssuer(issuer: "https://oidc.test", callerTypes: [.application], publicKeys: [key])])
        }
    }

    @Test func leadingZeroBytesDoNotCountTowardKeyLength() {
        let key = JWK(
            keyType: .rsa, algorithm: "RS256", keyID: "padded",
            e: Data([1, 0, 1]), n: Data([0, 0]) + Data(repeating: 0xC1, count: 128)
        )
        expectError(.keyTooShort(kid: "padded")) {
            _ = try trust([TrustedIssuer(issuer: "https://oidc.test", callerTypes: [.application], publicKeys: [key])])
        }
    }

    @Test func nonRSAOrOtherAlgRefuses() throws {
        let ec = JWK(keyType: .ellipticCurve, keyID: "ec", x: Data(repeating: 1, count: 32), y: Data(repeating: 2, count: 32))
        expectError(.unsupportedKey(kid: "ec")) {
            _ = try trust([TrustedIssuer(issuer: "https://oidc.test", callerTypes: [.application], publicKeys: [ec])])
        }
        var rs512 = oc.publicKey
        rs512.algorithm = "RS512"
        expectError(.unsupportedKey(kid: "oc-1")) {
            _ = try trust([TrustedIssuer(issuer: "https://oidc.test", callerTypes: [.application], publicKeys: [rs512])])
        }
    }

    @Test func keyWithoutKidRefuses() {
        var key = oc.publicKey
        key.keyID = nil
        expectError(.keyWithoutKid(issuer: "https://oidc.test")) {
            _ = try trust([TrustedIssuer(issuer: "https://oidc.test", callerTypes: [.application], publicKeys: [key])])
        }
    }

    @Test func emptyKeySetRefuses() {
        expectError(.emptyKeySet(issuer: "https://oidc.test")) {
            _ = try trust([TrustedIssuer(issuer: "https://oidc.test", callerTypes: [.application], publicKeys: [])])
        }
    }
}
