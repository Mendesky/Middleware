import Foundation
import _CryptoExtras
import JSONWebAlgorithms
import JSONWebKey
import JSONWebSignature

/// Mints RS256 `at+jwt` application tokens for tests, the way OIDCContext would.
/// Each instance owns a fresh RSA-2048 key.
public struct ApplicationTokenTestSigner: Sendable {
    public static let defaultIssuer = "https://oidc.test"
    public static let defaultAudience = "mendesky-services"

    private let kid: String
    private let issuer: String
    private let privateJWK: JWK
    public let publicKey: JWK

    public init(kid: String = "app-test-1", issuer: String = defaultIssuer) {
        self.kid = kid
        self.issuer = issuer
        // swiftlint:disable:next force_try
        let key = try! _RSA.Signing.PrivateKey(keySize: .bits2048)
        // jose-swift parses the PKCS#8 PEM into a JWK carrying the private parts.
        // swiftlint:disable:next force_try
        var full = try! JWK(pem: key.pkcs8PEMRepresentation)
        full.keyID = kid
        full.algorithm = "RS256"
        // p/q are dropped: jose-swift rejects the primes it parsed itself; n/e/d sign fine.
        full.p = nil; full.q = nil; full.dp = nil; full.dq = nil; full.qi = nil
        self.privateJWK = full
        self.publicKey = JWK(keyType: .rsa, algorithm: "RS256", keyID: kid, e: full.e, n: full.n)
    }

    /// Base64 of a JWK Set JSON holding these signers' public keys (the `MENDESKY_APP_TOKEN_JWKS` format).
    public static func keySetBase64(_ signers: [ApplicationTokenTestSigner]) -> String {
        struct Set: Encodable { let keys: [JWK] }
        // swiftlint:disable:next force_try
        let data = try! JSONEncoder().encode(Set(keys: signers.map(\.publicKey)))
        return data.base64EncodedString()
    }

    /// `nil` for `clientId`/`scope`/`audience`/`typ` omits that field; `kid: .some(nil)` omits the header `kid`,
    /// `.none` uses the signer's own. `audienceAsString` emits `aud` as a bare string (first entry) instead of an array.
    public func token(
        sub: String,
        clientId: String? = "client-1",
        scope: String? = "*",
        audience: [String]? = [defaultAudience],
        expiresIn: TimeInterval = 900,
        typ: String? = "at+jwt",
        kid kidOverride: String?? = .none,
        issuer issuerOverride: String? = nil,
        audienceAsString: Bool = false
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

        // swiftlint:disable:next force_try
        let jws = try! JWS(
            payload: JSONSerialization.data(withJSONObject: claims),
            protectedHeaderData: JSONSerialization.data(withJSONObject: header),
            key: privateJWK
        )
        return jws.compactSerialization
    }

    /// Signs `<base64url(headerJSON)>.<base64url(payloadJSON)>` with this signer's key (RS256) without any header
    /// validation, so tests can craft hostile headers (duplicate `alg`, odd `typ`, ...).
    public func rawToken(headerJSON: String, payloadJSON: String) -> String {
        func b64(_ data: Data) -> String {
            data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        let input = "\(b64(Data(headerJSON.utf8))).\(b64(Data(payloadJSON.utf8)))"
        // swiftlint:disable:next force_try
        let signature = try! SigningAlgorithm.RS256.cryptoSigner!.sign(data: Data(input.utf8), key: privateJWK)
        return "\(input).\(b64(signature))"
    }
}
