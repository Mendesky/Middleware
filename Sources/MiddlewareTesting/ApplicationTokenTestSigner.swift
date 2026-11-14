import Foundation
import _CryptoExtras
import JSONWebKey
import Middleware

/// Mints RS256 `at+jwt` application tokens for tests, the way OIDCContext would.
/// Each instance owns a fresh RSA-2048 key.
public struct ApplicationTokenTestSigner: Sendable {
    public static let defaultIssuer = "https://oidc.test"
    public static let defaultAudience = "mendesky-services"

    private let kid: String
    private let issuer: String
    private let privateKey: _RSA.Signing.PrivateKey
    public let publicKey: JWK

    public init(kid: String = "app-test-1", issuer: String = defaultIssuer) {
        self.kid = kid
        self.issuer = issuer
        // swiftlint:disable:next force_try
        let key = try! _RSA.Signing.PrivateKey(keySize: .bits2048)
        self.privateKey = key
        // jose-swift parses the PKCS#8 PEM into a JWK; only its public n/e are kept.
        // swiftlint:disable:next force_try
        let full = try! JWK(pem: key.pkcs8PEMRepresentation)
        self.publicKey = JWK(keyType: .rsa, algorithm: "RS256", keyID: kid, e: full.e, n: full.n)
    }

    /// Base64 of a JWK Set JSON holding these signers' public keys (the `MENDESKY_APP_TOKEN_JWKS` format).
    public static func keySetBase64(_ signers: [ApplicationTokenTestSigner]) -> String {
        struct Set: Encodable { let keys: [JWK] }
        // swiftlint:disable:next force_try
        let data = try! JSONEncoder().encode(Set(keys: signers.map(\.publicKey)))
        return data.base64EncodedString()
    }

    /// This signer as a trusted issuer: its own issuer and public key, with the given caller types and actors.
    public func trustedIssuer(callerTypes: Set<CallerType>, actors: [String] = []) -> TrustedIssuer {
        TrustedIssuer(issuer: issuer, callerTypes: callerTypes, actors: actors, publicKeys: [publicKey])
    }

    /// Base64 of the trust configuration JSON (the `MENDESKY_ACCESS_TOKEN_TRUST` format), `callerTypes` sorted.
    public static func trustBase64(audience: String = defaultAudience, issuers: [TrustedIssuer]) -> String {
        struct KeySet: Encodable { let keys: [JWK] }
        struct Entry: Encodable {
            let issuer: String
            let callerTypes: [String]
            let actors: [String]
            let keys: KeySet
        }
        struct Document: Encodable {
            let audience: String
            let issuers: [Entry]
        }
        let document = Document(audience: audience, issuers: issuers.map {
            Entry(
                issuer: $0.issuer, callerTypes: $0.callerTypes.map(\.rawValue).sorted(), actors: $0.actors,
                keys: KeySet(keys: $0.publicKeys)
            )
        })
        // swiftlint:disable:next force_try
        return try! JSONEncoder().encode(document).base64EncodedString()
    }

    /// `nil` for `clientId`/`scope`/`audience`/`typ`/`subType` omits that field; `kid: .some(nil)` omits the header
    /// `kid`, `.none` uses the signer's own. `audienceAsString` emits `aud` as a bare string (first entry) instead of
    /// an array. `actors` builds a nested `act` claim, outermost first (`["a", "b"]` gives
    /// `{"sub": "a", "act": {"sub": "b"}}`); empty omits `act`.
    public func token(
        sub: String,
        clientId: String? = "client-1",
        scope: String? = "*",
        audience: [String]? = [defaultAudience],
        expiresIn: TimeInterval = 900,
        typ: String? = "at+jwt",
        kid kidOverride: String?? = .none,
        issuer issuerOverride: String? = nil,
        audienceAsString: Bool = false,
        subType: String? = "application",
        actors: [String] = []
    ) -> String {
        var header: [String: Any] = ["alg": "RS256"]
        if let typ { header["typ"] = typ }
        switch kidOverride {
        case .none: header["kid"] = kid
        case .some(.some(let other)): header["kid"] = other
        case .some(.none): break
        }

        let issuedAt = Date().timeIntervalSince1970
        var claims: [String: Any] = [
            "iss": issuerOverride ?? issuer,
            "sub": sub,
            "iat": Int(issuedAt),
            "exp": Int(issuedAt + expiresIn),
            "jti": UUID().uuidString,
        ]
        if let clientId { claims["client_id"] = clientId }
        if let scope { claims["scope"] = scope }
        if let audience { claims["aud"] = audienceAsString ? audience.first as Any : audience }
        if let subType { claims["sub_type"] = subType }
        let act = actors.reversed().reduce(nil as [String: Any]?) { inner, actor in
            var level: [String: Any] = ["sub": actor]
            if let inner { level["act"] = inner }
            return level
        }
        if let act { claims["act"] = act }

        // swiftlint:disable:next force_try
        let headerData = try! JSONSerialization.data(withJSONObject: header)
        // swiftlint:disable:next force_try
        let payloadData = try! JSONSerialization.data(withJSONObject: claims)
        return signed(header: headerData, payload: payloadData)
    }

    /// Signs `<base64url(headerJSON)>.<base64url(payloadJSON)>` with this signer's key (RS256) without any header
    /// validation, so tests can craft hostile headers (duplicate `alg`, odd `typ`, ...).
    public func rawToken(headerJSON: String, payloadJSON: String) -> String {
        signed(header: Data(headerJSON.utf8), payload: Data(payloadJSON.utf8))
    }

    /// Compact RS256 JWS over the given header and payload bytes. Signs with the BoringSSL-backed `_RSA` key
    /// (RSASSA-PKCS1-v1_5 over SHA-256, i.e. RS256): jose-swift's pure-Swift RS256 signer is far too slow for tests.
    private func signed(header: Data, payload: Data) -> String {
        let input = "\(Self.base64URL(header)).\(Self.base64URL(payload))"
        // swiftlint:disable:next force_try
        let signature = try! privateKey.signature(for: Data(input.utf8), padding: .insecurePKCS1v1_5)
        return "\(input).\(Self.base64URL(signature.rawRepresentation))"
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

/// The signer for first-party (IdentityContext) tokens in service tests; same type, a less misleading name.
public typealias AccessTokenTestSigner = ApplicationTokenTestSigner
