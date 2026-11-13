import Testing
import Foundation
import JSONWebKey
import Middleware
import MiddlewareTesting

private let issuer = ApplicationTokenTestSigner.defaultIssuer
private let audience = ApplicationTokenTestSigner.defaultAudience
private let appId = "3F2A9C1E-7B4D-4C1A-9E2F-0A1B2C3D4E5F"

private func verification(
    _ signers: [ApplicationTokenTestSigner],
    now: @escaping @Sendable () -> Date = { Date() }
) throws -> ApplicationTokenVerification {
    try ApplicationTokenVerification(publicKeys: signers.map(\.publicKey), issuer: issuer, audience: audience, now: now)
}

private func base64URL(_ string: String) -> String {
    Data(string.utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func expectError(_ expected: ApplicationTokenError, _ v: ApplicationTokenVerification, _ token: String) {
    do {
        _ = try v.verify(compactString: token)
        Issue.record("expected \(expected), but verification succeeded")
    } catch {
        #expect(error == expected)
    }
}

@Suite struct ApplicationTokenVerificationTests {
    @Test func verifiesAValidToken() throws {
        let signer = ApplicationTokenTestSigner()
        let v = try verification([signer])
        let claims = try v.verify(compactString: signer.token(sub: appId, scope: "* notification:send"))
        #expect(claims.applicationId == "3f2a9c1e-7b4d-4c1a-9e2f-0a1b2c3d4e5f")
        #expect(claims.clientId == "client-1")
        #expect(claims.scope == ["*", "notification:send"])
        #expect(claims.issuer == issuer)
    }

    @Test func rejectsWrongIssuer() throws {
        let signer = ApplicationTokenTestSigner()
        expectError(.wrongIssuer, try verification([signer]), signer.token(sub: appId, issuer: "https://other"))
    }

    @Test func rejectsMissingType() throws {
        let signer = ApplicationTokenTestSigner()
        expectError(.wrongType, try verification([signer]), signer.token(sub: appId, typ: nil))
    }

    @Test func rejectsExpiredAtTheBoundary() throws {
        let signer = ApplicationTokenTestSigner()
        let token = signer.token(sub: appId)
        let claims = try verification([signer]).verify(compactString: token)
        let atExpiry = try verification([signer], now: { claims.expiresAt })
        expectError(.expired, atExpiry, token)
        let justBefore = try verification([signer], now: { claims.expiresAt.addingTimeInterval(-1) })
        #expect(throws: Never.self) { try justBefore.verify(compactString: token) }
    }

    @Test func rejectsAnotherKeysSignature() throws {
        let configured = ApplicationTokenTestSigner(kid: "same")
        let impostor = ApplicationTokenTestSigner(kid: "same")
        expectError(.badSignature, try verification([configured]), impostor.token(sub: appId))
    }

    @Test func rejectsAlgNone() throws {
        let signer = ApplicationTokenTestSigner()
        let claims = base64URL(#"{"iss":"\#(issuer)","aud":["\#(audience)"],"sub":"x","client_id":"c","scope":"*","exp":99999999999}"#)
        expectError(.unsupportedAlgorithm, try verification([signer]), "eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.\(claims).")
    }

    private func claimsJSON(exp: Int = 99999999999) -> String {
        #"{"iss":"\#(issuer)","aud":["\#(audience)"],"sub":"x","client_id":"c","scope":"*","exp":\#(exp)}"#
    }

    private func expectRejected(_ v: ApplicationTokenVerification, _ token: String) {
        do {
            _ = try v.verify(compactString: token)
            Issue.record("token was accepted")
        } catch {}
    }

    @Test func rejectsDuplicateAlgHeaderNoneFirstUnsigned() throws {
        let signer = ApplicationTokenTestSigner()
        let header = base64URL(#"{"alg":"none","typ":"at+jwt","kid":"\#(signer.publicKey.keyID!)","alg":"RS256"}"#)
        let payload = base64URL(claimsJSON())
        expectRejected(try verification([signer]), "\(header).\(payload).")
        expectRejected(try verification([signer]), "\(header).\(payload).AAAA")
    }

    @Test func rejectsDuplicateAlgHeaderRS256FirstUnsigned() throws {
        let signer = ApplicationTokenTestSigner()
        let header = base64URL(#"{"alg":"RS256","typ":"at+jwt","kid":"\#(signer.publicKey.keyID!)","alg":"none"}"#)
        let payload = base64URL(claimsJSON())
        expectRejected(try verification([signer]), "\(header).\(payload).")
        expectRejected(try verification([signer]), "\(header).\(payload).AAAA")
    }

    @Test func rejectsDuplicateAlgHeaderRS256FirstEvenWhenSigned() throws {
        let signer = ApplicationTokenTestSigner()
        let kid = signer.publicKey.keyID!
        let token = signer.rawToken(
            headerJSON: #"{"alg":"RS256","typ":"at+jwt","kid":"\#(kid)","alg":"none"}"#, payloadJSON: claimsJSON())
        expectRejected(try verification([signer]), token)
    }

    @Test func rejectsDuplicateAlgHeaderNoneFirstEvenWhenSigned() throws {
        let signer = ApplicationTokenTestSigner()
        let kid = signer.publicKey.keyID!
        let token = signer.rawToken(
            headerJSON: #"{"alg":"none","typ":"at+jwt","kid":"\#(kid)","alg":"RS256"}"#, payloadJSON: claimsJSON())
        expectRejected(try verification([signer]), token)
    }

    @Test func rejectsHS256() throws {
        let signer = ApplicationTokenTestSigner()
        let kid = signer.publicKey.keyID!
        let token = signer.rawToken(headerJSON: #"{"alg":"HS256","typ":"at+jwt","kid":"\#(kid)"}"#, payloadJSON: claimsJSON())
        expectError(.unsupportedAlgorithm, try verification([signer]), token)
    }

    @Test func duplicateKidIsAConfigurationError() {
        let a = ApplicationTokenTestSigner(kid: "dup")
        let b = ApplicationTokenTestSigner(kid: "dup")
        #expect(throws: ApplicationTokenConfigurationError.duplicateKid) {
            try ApplicationTokenVerification(publicKeys: [a.publicKey, b.publicKey], issuer: issuer, audience: audience)
        }
    }

    @Test func nonRSAKeyIsAConfigurationError() {
        let ec = JWK(keyType: .ellipticCurve, algorithm: "ES256", keyID: "ec")
        #expect(throws: ApplicationTokenConfigurationError.unsupportedKey) {
            try ApplicationTokenVerification(publicKeys: [ec], issuer: issuer, audience: audience)
        }
    }

    @Test func rsaKeyWithOtherAlgIsAConfigurationError() {
        var key = ApplicationTokenTestSigner().publicKey
        key.algorithm = "RS512"
        #expect(throws: ApplicationTokenConfigurationError.unsupportedKey) {
            try ApplicationTokenVerification(publicKeys: [key], issuer: issuer, audience: audience)
        }
    }

    @Test func fromEnvironmentTrimsIssuerAndAudience() throws {
        let signer = ApplicationTokenTestSigner()
        let v = try #require(try ApplicationTokenVerification.fromEnvironment([
            "MENDESKY_APP_TOKEN_JWKS": ApplicationTokenTestSigner.keySetBase64([signer]),
            "MENDESKY_APP_TOKEN_ISSUER": issuer + "\n",
            "MENDESKY_APP_TOKEN_AUDIENCE": " " + audience + "\n",
        ]))
        #expect(throws: Never.self) { try v.verify(compactString: signer.token(sub: appId)) }
    }

    @Test func rejectsFiveSegmentJWE() throws {
        expectError(.malformed, try verification([ApplicationTokenTestSigner()]), "a.b.c.d.e")
    }

    @Test func rejectsMissingClientId() throws {
        let signer = ApplicationTokenTestSigner()
        expectError(.missingClaim("client_id"), try verification([signer]), signer.token(sub: appId, clientId: nil))
    }

    @Test func rejectsMissingScope() throws {
        let signer = ApplicationTokenTestSigner()
        expectError(.missingClaim("scope"), try verification([signer]), signer.token(sub: appId, scope: nil))
    }

    @Test func rejectsWrongAudience() throws {
        let signer = ApplicationTokenTestSigner()
        let v = try verification([signer])
        expectError(.wrongAudience, v, signer.token(sub: appId, audience: ["other"]))
        expectError(.wrongAudience, v, signer.token(sub: appId, audience: nil))
    }

    @Test func acceptsAudienceAsString() throws {
        let signer = ApplicationTokenTestSigner()
        let claims = try verification([signer]).verify(compactString: signer.token(sub: appId, audienceAsString: true))
        #expect(claims.clientId == "client-1")
    }

    @Test func rejectsIdTokenShape() throws {
        let signer = ApplicationTokenTestSigner()
        let token = signer.token(sub: appId, clientId: nil, scope: nil, audience: ["outline-client"], typ: "JWT")
        expectError(.wrongType, try verification([signer]), token)
    }

    @Test func picksKeyByKid() throws {
        let a = ApplicationTokenTestSigner(kid: "a")
        let b = ApplicationTokenTestSigner(kid: "b")
        let v = try verification([a, b])
        #expect(throws: Never.self) { try v.verify(compactString: a.token(sub: appId)) }
        #expect(throws: Never.self) { try v.verify(compactString: b.token(sub: appId)) }
    }

    @Test func rejectsUnknownKid() throws {
        let c = ApplicationTokenTestSigner(kid: "c")
        expectError(.unknownKey, try verification([ApplicationTokenTestSigner(kid: "a")]), c.token(sub: appId))
    }

    @Test func rejectsMissingKid() throws {
        let signer = ApplicationTokenTestSigner()
        expectError(.unknownKey, try verification([signer]), signer.token(sub: appId, kid: .some(nil)))
    }

    @Test func keyWithoutKidIsAConfigurationError() throws {
        var key = ApplicationTokenTestSigner().publicKey
        key.keyID = nil
        #expect(throws: ApplicationTokenConfigurationError.keyWithoutKid) {
            try ApplicationTokenVerification(publicKeys: [key], issuer: issuer, audience: audience)
        }
    }

    @Test func emptyKeySetIsAConfigurationError() {
        #expect(throws: ApplicationTokenConfigurationError.emptyKeySet) {
            try ApplicationTokenVerification(publicKeys: [], issuer: issuer, audience: audience)
        }
    }

    @Test func fromEnvironmentIsNilWithoutKeys() throws {
        #expect(try ApplicationTokenVerification.fromEnvironment([:]) == nil)
    }

    @Test func fromEnvironmentThrowsWithoutIssuerOrAudience() throws {
        let jwks = ApplicationTokenTestSigner.keySetBase64([ApplicationTokenTestSigner()])
        #expect(throws: ApplicationTokenConfigurationError.missingIssuer) {
            try ApplicationTokenVerification.fromEnvironment(["MENDESKY_APP_TOKEN_JWKS": jwks])
        }
        #expect(throws: ApplicationTokenConfigurationError.missingAudience) {
            try ApplicationTokenVerification.fromEnvironment(
                ["MENDESKY_APP_TOKEN_JWKS": jwks, "MENDESKY_APP_TOKEN_ISSUER": issuer])
        }
    }

    @Test func fromEnvironmentLoadsFromBase64AndFile() throws {
        let signer = ApplicationTokenTestSigner()
        let jwks = ApplicationTokenTestSigner.keySetBase64([signer])
        let base = ["MENDESKY_APP_TOKEN_ISSUER": issuer, "MENDESKY_APP_TOKEN_AUDIENCE": audience]

        let fromBase64 = try #require(try ApplicationTokenVerification.fromEnvironment(base.merging(["MENDESKY_APP_TOKEN_JWKS": jwks]) { $1 }))
        #expect(throws: Never.self) { try fromBase64.verify(compactString: signer.token(sub: appId)) }

        let path = FileManager.default.temporaryDirectory.appending(path: "jwks-\(UUID().uuidString).json")
        try Data(base64Encoded: jwks)!.write(to: path)
        defer { try? FileManager.default.removeItem(at: path) }
        let fromFile = try #require(try ApplicationTokenVerification.fromEnvironment(base.merging(["MENDESKY_APP_TOKEN_JWKS_PATH": path.path()]) { $1 }))
        #expect(throws: Never.self) { try fromFile.verify(compactString: signer.token(sub: appId)) }
    }

    @Test func fromEnvironmentReportsUnreadableKeySet() {
        #expect(throws: ApplicationTokenConfigurationError.keySetUnreadable) {
            try ApplicationTokenVerification.fromEnvironment(["MENDESKY_APP_TOKEN_JWKS_PATH": "/nonexistent/jwks.json"])
        }
    }

    @Test func scopeGrants() {
        #expect(Scope.grants(["*"], Scope.notificationSend))
        #expect(Scope.grants(["notification:send"], Scope.notificationSend))
        #expect(!Scope.grants(["other"], Scope.notificationSend))
        #expect(!Scope.grants([], Scope.notificationSend))
    }
}
