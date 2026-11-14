import Foundation
import HTTPTypes
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import JSONWebKey
import JSONWebEncryption
import MiddlewareTesting
@testable import Middleware

// Shared by the bearer, legacy-JWE and permission-chain tests.

/// Signs first-party (IdentityContext) tokens.
let ic = ApplicationTokenTestSigner(kid: "ic-1", issuer: "https://identity.test")
/// Signs OIDCContext tokens (application and delegated user).
let oc = ApplicationTokenTestSigner(kid: "oc-1", issuer: "https://oidc.test")

/// The usual trust: `ic` issues `user`, `oc` issues `application` and `delegatedUser` for `ocActors`.
func icOcTrust(ocActors: [String] = ["mendesky-mcp-server"]) throws -> AccessTokenTrust {
    try AccessTokenTrust(audience: ApplicationTokenTestSigner.defaultAudience, issuers: [
        ic.trustedIssuer(callerTypes: [.user]),
        oc.trustedIssuer(callerTypes: [.application, .delegatedUser], actors: ocActors),
    ])
}

/// Recipient key for the legacy JWE user tokens made by `jweUserToken`.
let testRecipientKey: JWK = P256.KeyAgreement.PrivateKey().jwkRepresentation

/// A legacy JWE user token (5 segments) for `testRecipientKey`.
func jweUserToken(userId: String, clientId: String = "c") throws -> String {
    let payload = AccessTokenPayload(
        authorizationId: "a", userId: userId, clientId: clientId, scope: [], expiresAt: Date(timeIntervalSinceNow: 3600))
    let jwe = try JWE(
        payload: try JSONEncoder().encode(payload), keyManagementAlg: .ecdhESA256KW, encryptionAlgorithm: .a256GCM,
        recipientKey: testRecipientKey)
    return jwe.compactSerialization
}

/// `Authorization: Bearer <token>`, plus `operatorId` when given.
func headers(_ token: String, operatorId: String? = nil) -> HTTPFields {
    var h = HTTPFields()
    h[.authorization] = "Bearer \(token)"
    if let operatorId { h[.init("operatorId")!] = operatorId }
    return h
}

/// A one-line rendering of `Caller.current`, for handlers to echo back.
func describe(_ caller: CallerIdentity?) -> String {
    switch caller {
    case .application(let c): "application:\(c.applicationId)"
    case .user(let u, let c): "user:\(u):\(c)"
    case .delegatedUser(let d): "delegated:\(d.userId):\(d.clientId):\(d.actor):\(d.originClient ?? "-")"
    case nil: "none"
    }
}
