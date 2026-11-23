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

// Shared by the bearer, JWE-removal and permission-chain tests.

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

/// The 1.x JWE access token payload; Middleware no longer has this type.
private struct LegacyJWEPayload: Encodable {
    let authorizationId: String
    let userId: String
    let clientId: String
    let scope: [String]
    let expiresAt: Date
}

/// A genuine legacy JWE user token (5 segments, ECDH-ES), as IdentityContext minted before 2.0, encrypted to a
/// throwaway key. 2.0 must refuse it without trying to decrypt it.
func jweUserToken(userId: String, clientId: String = "c", expiresIn: TimeInterval = 3600) throws -> String {
    let payload = LegacyJWEPayload(
        authorizationId: "a", userId: userId, clientId: clientId, scope: [], expiresAt: Date(timeIntervalSinceNow: expiresIn))
    let recipientKey: JWK = P256.KeyAgreement.PrivateKey().jwkRepresentation
    let jwe = try JWE(
        payload: try JSONEncoder().encode(payload), keyManagementAlg: .ecdhESA256KW, encryptionAlgorithm: .a256GCM,
        recipientKey: recipientKey)
    return jwe.compactSerialization
}

/// `Authorization: Bearer <token>`, plus `operatorId` and `applicationId` when given.
func headers(_ token: String, operatorId: String? = nil, applicationId: String? = nil) -> HTTPFields {
    var h = HTTPFields()
    h[.authorization] = "Bearer \(token)"
    if let operatorId { h[.init("operatorId")!] = operatorId }
    if let applicationId { h[.init("applicationId")!] = applicationId }
    return h
}

/// `applicationId` of the `.delegatedUser` tokens in these tests: the actor (`act.sub`).
let mcpActor = "mendesky-mcp-server"

/// A one-line rendering of `Caller.current`, for handlers to echo back.
func describe(_ caller: CallerIdentity?) -> String {
    switch caller {
    case .application(let c): "application:\(c.applicationId)"
    case .user(let u, let c): "user:\(u):\(c)"
    case .delegatedUser(let d): "delegated:\(d.userId):\(d.clientId):\(d.actor):\(d.originClient ?? "-")"
    case nil: "none"
    }
}
