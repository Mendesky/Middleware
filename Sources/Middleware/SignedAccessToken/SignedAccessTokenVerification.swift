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
        guard segments.count == 3, let headerSegment = jsonObjectSegment(segments[0]) else { throw .malformed }
        let header = headerSegment.object

        // Parsers disagree on duplicate keys (first vs last wins), so a header naming `"alg"` twice is refused outright.
        // A JSON escape could spell a second `alg` without the literal text (`"\u0061lg"`), so backslashes are refused
        // too. The one exception is `\/`: Foundation's JSON writers emit `application/at+jwt` as `application\/at+jwt`,
        // and `/` cannot spell `alg`. (Removing `\/` pairs leaves a stray backslash from `\\/`, which is refused.)
        let rawHeader = String(decoding: headerSegment.data, as: UTF8.self)  // UTF-8, checked by `jsonObjectSegment`.
        guard !rawHeader.replacingOccurrences(of: "\\/", with: "").contains("\\"),
              rawHeader.components(separatedBy: "\"alg\"").count <= 2
        else { throw .malformed }
        // Header checks come first, so e.g. an `alg: none` token never reaches signature verification.
        guard header["alg"] as? String == "RS256" else { throw .unsupportedAlgorithm }
        guard let typ = (header["typ"] as? String)?.lowercased(),
              typ == "at+jwt" || typ == "application/at+jwt"
        else { throw .wrongType }
        guard let kid = header["kid"] as? String else { throw .unknownKey }
        // The header is exactly {alg, typ, kid}: `crit`, `jwk`, `x5u`, `b64`, ... are never accepted.
        guard Set(header.keys) == ["alg", "typ", "kid"] else { throw .malformed }

        // Before the signature is checked, only the (unverified) `iss` is read, and only to choose the key:
        // the kid must belong to that issuer, so one issuer's key can never vouch for another issuer's token.
        guard let claims = jsonObjectSegment(segments[1])?.object else { throw .malformed }
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
            guard !scope.contains(where: { $0.contains("*") }) else { throw .wildcardScopeInDelegatedToken }
            return .delegatedUser(DelegatedUserClaims(
                userId: sub, clientId: clientId, actor: actor, originClient: originClient, scope: scope,
                issuer: issuerName, expiresAt: expiresAt
            ))
        }
    }
}

/// Decodes a header or payload segment: strict base64url, then a JSON object. The bytes must be UTF-8 (RFC 7515 §4,
/// §5.2) beginning with `{` and containing no NUL. `JSONSerialization` would otherwise auto-detect UTF-16/UTF-32 (with
/// or without a BOM), and the raw-text header checks, which read UTF-8, would not see what the parser sees.
private func jsonObjectSegment(_ segment: Substring) -> (data: Data, object: [String: Any])? {
    guard let data = base64URLDecode(segment),
          data.first == 0x7B, !data.contains(0x00), String(data: data, encoding: .utf8) != nil,
          let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    else { return nil }
    return (data, object)
}

/// Decodes unpadded base64url (RFC 7515 §2), strictly: only `[A-Za-z0-9_-]`, no `=` padding, and only the canonical
/// spelling (unused trailing bits zero), so one signed token has exactly one accepted string form.
func base64URLDecode(_ value: Substring) -> Data? {
    let isBase64URL: (UInt8) -> Bool = {
        (0x41...0x5A).contains($0) || (0x61...0x7A).contains($0) || (0x30...0x39).contains($0)  // A-Z a-z 0-9
            || $0 == 0x2D || $0 == 0x5F  // - _
    }
    guard value.utf8.allSatisfy(isBase64URL), value.utf8.count % 4 != 1 else { return nil }
    var padded = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    padded += String(repeating: "=", count: (4 - padded.utf8.count % 4) % 4)
    guard let data = Data(base64Encoded: padded), base64URLEncode(data) == value else { return nil }
    return data
}

private func base64URLEncode(_ data: Data) -> String {
    data.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}
