import Foundation
import JSONWebAlgorithms
import JSONWebKey

public struct ApplicationTokenClaims: Sendable, Equatable {
    /// The token's `sub`, lowercased.
    public let applicationId: String
    public let clientId: String
    public let scope: [String]
    public let issuer: String
    public let expiresAt: Date

    public init(applicationId: String, clientId: String, scope: [String], issuer: String, expiresAt: Date) {
        self.applicationId = applicationId
        self.clientId = clientId
        self.scope = scope
        self.issuer = issuer
        self.expiresAt = expiresAt
    }
}

public enum ApplicationTokenError: Error, Equatable {
    case malformed
    case unsupportedAlgorithm
    case wrongType
    case unknownKey
    case badSignature
    case wrongIssuer
    case wrongAudience
    case expired
    case missingClaim(String)
}

public enum ApplicationTokenConfigurationError: Error, Equatable {
    case keySetUnreadable
    case keyWithoutKid
    case emptyKeySet
    case missingIssuer
    case missingAudience
    /// Two keys in the set share a `kid`.
    case duplicateKid
    /// A key that is not an RSA key, or whose `alg` is present and not `RS256`.
    case unsupportedKey
}

/// Verifies application tokens issued by OIDCContext: RS256 compact JWS with `typ: at+jwt`,
/// checked against a locally configured JWK Set (no runtime `/jwks` fetch).
public struct ApplicationTokenVerification: Sendable {
    private let keysByKid: [String: JWK]
    public let issuer: String
    public let audience: String
    /// The configured key ids, sorted.
    public var kids: [String] { keysByKid.keys.sorted() }
    private let now: @Sendable () -> Date

    public init(
        publicKeys: [JWK],
        issuer: String,
        audience: String,
        now: @escaping @Sendable () -> Date = { Date() }
    ) throws(ApplicationTokenConfigurationError) {
        guard !publicKeys.isEmpty else { throw .emptyKeySet }
        var byKid: [String: JWK] = [:]
        for key in publicKeys {
            guard let kid = key.keyID, !kid.isEmpty else { throw .keyWithoutKid }
            guard key.keyType == .rsa, key.n != nil, key.e != nil,
                  key.algorithm == nil || key.algorithm == "RS256"
            else { throw .unsupportedKey }
            guard byKid[kid] == nil else { throw .duplicateKid }
            byKid[kid] = key
        }
        self.keysByKid = byKid
        self.issuer = issuer
        self.audience = audience
        self.now = now
    }

    /// Builds a verification from `MENDESKY_APP_TOKEN_JWKS` (base64 of a JWK Set JSON) or
    /// `MENDESKY_APP_TOKEN_JWKS_PATH` (file holding it), plus `MENDESKY_APP_TOKEN_ISSUER` and
    /// `MENDESKY_APP_TOKEN_AUDIENCE`. Returns `nil` when neither key variable is set (feature off).
    public static func fromEnvironment(
        _ env: [String: String] = ProcessInfo.processInfo.environment
    ) throws(ApplicationTokenConfigurationError) -> ApplicationTokenVerification? {
        let path = nonBlank(env["MENDESKY_APP_TOKEN_JWKS_PATH"])
        let base64 = nonBlank(env["MENDESKY_APP_TOKEN_JWKS"])
        guard path != nil || base64 != nil else { return nil }

        let data: Data
        if let path {
            guard let read = try? Data(contentsOf: URL(filePath: path)) else { throw .keySetUnreadable }
            data = read
        } else if let base64, let decoded = Data(base64Encoded: base64) {
            data = decoded
        } else {
            throw .keySetUnreadable
        }
        guard let set = try? JSONDecoder().decode(KeySet.self, from: data) else { throw .keySetUnreadable }

        guard let issuer = trimmedNonBlank(env["MENDESKY_APP_TOKEN_ISSUER"]) else { throw .missingIssuer }
        guard let audience = trimmedNonBlank(env["MENDESKY_APP_TOKEN_AUDIENCE"]) else { throw .missingAudience }
        return try ApplicationTokenVerification(publicKeys: set.keys, issuer: issuer, audience: audience)
    }

    public func verify(compactString: String) throws(ApplicationTokenError) -> ApplicationTokenClaims {
        let segments = compactString.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3,
              let headerData = Self.base64URLDecode(String(segments[0])),
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
        guard let kid = header["kid"] as? String, let key = keysByKid[kid] else { throw .unknownKey }

        // Verify the RS256 signature directly over the ASCII bytes of "<header>.<payload>", with the key chosen by
        // the kid above. jose-swift's `JWS.verify` is not used: it re-parses the header and accepts `alg: none`.
        guard let signature = Self.base64URLDecode(String(segments[2])),
              let payloadData = Self.base64URLDecode(String(segments[1]))
        else { throw .malformed }
        let signingInput = Data("\(segments[0]).\(segments[1])".utf8)
        // The algorithm is the constant RS256, never taken from the token.
        guard let verifier = SigningAlgorithm.RS256.cryptoVerifier else { throw .unsupportedAlgorithm }
        let valid: Bool
        do { valid = try verifier.verify(data: signingInput, signature: signature, key: key) } catch { throw .badSignature }
        guard valid else { throw .badSignature }

        guard let claims = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any] else {
            throw .malformed
        }
        guard claims["iss"] as? String == issuer else { throw .wrongIssuer }
        let audiences: [String]
        if let single = claims["aud"] as? String {
            audiences = [single]
        } else if let many = claims["aud"] as? [String] {
            audiences = many
        } else {
            audiences = []
        }
        guard audiences.contains(audience) else { throw .wrongAudience }

        guard let exp = (claims["exp"] as? NSNumber)?.doubleValue else { throw .missingClaim("exp") }
        let expiresAt = Date(timeIntervalSince1970: exp)
        guard expiresAt > now() else { throw .expired }

        guard let sub = Self.nonBlank(claims["sub"] as? String) else { throw .missingClaim("sub") }
        guard let clientId = Self.nonBlank(claims["client_id"] as? String) else { throw .missingClaim("client_id") }
        guard let scope = claims["scope"] as? String else { throw .missingClaim("scope") }

        return ApplicationTokenClaims(
            applicationId: sub.lowercased(),
            clientId: clientId,
            scope: scope.split(separator: " ").map(String.init),
            issuer: issuer,
            expiresAt: expiresAt
        )
    }

    private struct KeySet: Decodable {
        let keys: [JWK]
    }

    private static func nonBlank(_ value: String?) -> String? {
        guard let value, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
        return value
    }

    private static func trimmedNonBlank(_ value: String?) -> String? {
        guard let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines), !trimmed.isEmpty else { return nil }
        return trimmed
    }

    private static func base64URLDecode(_ value: String) -> Data? {
        var s = value.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }
}
