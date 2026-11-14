import Foundation
import JSONWebAlgorithms
import JSONWebKey

/// Why a signed access token was rejected. Associated values are claim names only, never token content.
public enum AccessTokenError: Error, Equatable {
    case malformed
    case unsupportedAlgorithm
    case wrongType
    case untrustedIssuer
    case unknownKey
    case badSignature
    case wrongAudience
    case expired
    case missingClaim(String)
    /// `sub_type` is neither `user` nor `application`.
    case unsupportedSubjectType
    /// An `application` token carries `act`.
    case unexpectedActor
    /// The issuer is not trusted for this kind of caller.
    case callerTypeNotAllowed
    /// `act.sub` is not one of the issuer's actors.
    case actorNotAllowed
    /// A delegated token's `scope` contains `*`.
    case wildcardScopeInDelegatedToken
}

/// Verifies RS256 `at+jwt` access tokens from the issuers in an `AccessTokenTrust`, and says who the caller is:
/// a first-party user, an application, or a user delegated to an actor.
public struct SignedAccessTokenVerification: Sendable {
    public let trust: AccessTokenTrust
    private let now: @Sendable () -> Date

    public init(trust: AccessTokenTrust, now: @escaping @Sendable () -> Date = { Date() }) {
        self.trust = trust
        self.now = now
    }

    public func verify(compactString: String) throws(AccessTokenError) -> CallerIdentity {
        let segments = compactString.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3,
              let headerData = base64URLDecode(segments[0]),
              let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any]
        else { throw .malformed }

        // Parsers disagree on duplicate keys (first vs last wins), so a header naming `"alg"` twice is refused outright.
        guard String(decoding: headerData, as: UTF8.self).components(separatedBy: "\"alg\"").count <= 2 else {
            throw .malformed
        }
        // Header checks come first, so e.g. an `alg: none` token never reaches signature verification.
        guard header["alg"] as? String == "RS256" else { throw .unsupportedAlgorithm }
        guard let typ = (header["typ"] as? String)?.lowercased(),
              typ == "at+jwt" || typ == "application/at+jwt"
        else { throw .wrongType }
        guard let kid = header["kid"] as? String else { throw .unknownKey }

        // Before the signature is checked, only the (unverified) `iss` is read, and only to choose the key:
        // the kid must belong to that issuer, so one issuer's key can never vouch for another issuer's token.
        guard let payloadData = base64URLDecode(segments[1]),
              let claims = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any]
        else { throw .malformed }
        guard let issuerName = claims["iss"] as? String, let trusted = trust.issuer(named: issuerName) else {
            throw .untrustedIssuer
        }
        guard let key = trust.key(issuer: issuerName, kid: kid) else { throw .unknownKey }

        // Verify the RS256 signature directly over the ASCII bytes of "<header>.<payload>". jose-swift's `JWS.verify`
        // is not used: it re-parses the header and accepts `alg: none`. The algorithm is the constant RS256, never
        // taken from the token.
        guard let signature = base64URLDecode(segments[2]) else { throw .malformed }
        let signingInput = Data("\(segments[0]).\(segments[1])".utf8)
        guard let verifier = SigningAlgorithm.RS256.cryptoVerifier else { throw .unsupportedAlgorithm }
        let valid: Bool
        do { valid = try verifier.verify(data: signingInput, signature: signature, key: key) } catch { throw .badSignature }
        guard valid else { throw .badSignature }

        // Signature verified: the claims below are the issuer's.
        let audiences: [String]
        if let single = claims["aud"] as? String {
            audiences = [single]
        } else if let many = claims["aud"] as? [String] {
            audiences = many
        } else {
            audiences = []
        }
        guard audiences.contains(trust.audience) else { throw .wrongAudience }

        guard let exp = (claims["exp"] as? NSNumber)?.doubleValue else { throw .missingClaim("exp") }
        let expiresAt = Date(timeIntervalSince1970: exp)
        guard expiresAt > now() else { throw .expired }

        guard let sub = nonBlank(claims["sub"] as? String) else { throw .missingClaim("sub") }
        guard let subType = nonBlank(claims["sub_type"] as? String) else { throw .missingClaim("sub_type") }
        guard let clientId = nonBlank(claims["client_id"] as? String) else { throw .missingClaim("client_id") }
        guard let scopeClaim = claims["scope"] as? String else { throw .missingClaim("scope") }
        let scope = scopeClaim.split(whereSeparator: \.isWhitespace).map(String.init)

        guard subType == "user" || subType == "application" else { throw .unsupportedSubjectType }
        var actor: String?
        var originClient: String?
        if let act = claims["act"] {
            guard let act = act as? [String: Any], let actSub = nonBlank(act["sub"] as? String) else {
                throw .missingClaim("act.sub")
            }
            actor = actSub
            originClient = nonBlank((act["act"] as? [String: Any])?["sub"] as? String)
        }
        if subType == "application", actor != nil { throw .unexpectedActor }

        let callerType: CallerType = subType == "application" ? .application : actor == nil ? .user : .delegatedUser
        guard trusted.callerTypes.contains(callerType) else { throw .callerTypeNotAllowed }

        switch callerType {
        case .user:
            // Verbatim: compared character for character with the `operatorId` header.
            return .user(userId: sub, clientId: clientId)
        case .application:
            return .application(ApplicationTokenClaims(
                applicationId: sub.lowercased(), clientId: clientId, scope: scope, issuer: issuerName,
                expiresAt: expiresAt
            ))
        case .delegatedUser:
            guard let actor, trusted.actors.contains(actor) else { throw .actorNotAllowed }
            guard !scope.contains(Scope.all) else { throw .wildcardScopeInDelegatedToken }
            return .delegatedUser(DelegatedUserClaims(
                userId: sub, clientId: clientId, actor: actor, originClient: originClient, scope: scope,
                issuer: issuerName, expiresAt: expiresAt
            ))
        }
    }
}

/// Decodes unpadded base64url (RFC 7515 §2).
func base64URLDecode(_ value: Substring) -> Data? {
    var s = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    while s.count % 4 != 0 { s += "=" }
    return Data(base64Encoded: s)
}
