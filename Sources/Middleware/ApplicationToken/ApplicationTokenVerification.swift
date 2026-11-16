import Foundation
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

/// Verifies application tokens issued by OIDCContext: a `SignedAccessTokenVerification` that trusts exactly one issuer,
/// for `application` callers only, with a locally configured key set (no runtime `/jwks` fetch). All parsing and
/// checks live in the core; this type only maps its results and errors onto the application-token surface.
public struct ApplicationTokenVerification: Sendable {
    /// The shared core, configured with the one issuer and `application` only.
    let signed: SignedAccessTokenVerification
    public let issuer: String
    public let audience: String
    /// The configured key ids, sorted.
    public var kids: [String] { signed.trust.issuers.flatMap(\.publicKeys).compactMap(\.keyID).sorted() }

    public init(
        publicKeys: [JWK],
        issuer: String,
        audience: String,
        now: @escaping @Sendable () -> Date = { Date() }
    ) throws(ApplicationTokenConfigurationError) {
        let trust: AccessTokenTrust
        do {
            trust = try AccessTokenTrust(
                audience: audience,
                issuers: [TrustedIssuer(issuer: issuer, callerTypes: [.application], publicKeys: publicKeys)]
            )
        } catch {
            throw Self.configurationError(error)
        }
        self.signed = SignedAccessTokenVerification(trust: trust, now: now)
        self.issuer = issuer
        self.audience = audience
    }

    public func verify(compactString: String) throws(ApplicationTokenError) -> ApplicationTokenClaims {
        let identity: CallerIdentity
        do {
            identity = try signed.verify(compactString: compactString)
        } catch {
            throw Self.tokenError(error)
        }
        // The only trusted issuer is allowed `application` alone, so no other identity can come back.
        guard case .application(let claims) = identity else { throw .wrongType }
        return claims
    }

    private static func configurationError(_ error: AccessTokenTrustError) -> ApplicationTokenConfigurationError {
        switch error {
        case .missingAudience: .missingAudience
        case .blankIssuer: .missingIssuer
        case .emptyKeySet: .emptyKeySet
        case .keyWithoutKid: .keyWithoutKid
        case .duplicateKid: .duplicateKid
        case .unsupportedKey, .keyTooShort, .privateKeyMaterial: .unsupportedKey
        // Not reachable with one issuer that allows exactly `application`, or from the programmatic initializer
        // (no JSON, no environment); mapped to the nearest configuration error rather than crashing.
        case .unreadable, .noIssuers, .duplicateIssuer, .noCallerTypes, .unknownCallerType, .multipleUserIssuers,
             .userIssuerAllowsOtherCallerTypes, .delegatedUserWithoutActors, .renamedVariable:
            .unsupportedKey
        }
    }

    private static func tokenError(_ error: AccessTokenError) -> ApplicationTokenError {
        switch error {
        case .malformed: .malformed
        case .unsupportedAlgorithm: .unsupportedAlgorithm
        case .wrongType: .wrongType
        case .untrustedIssuer: .wrongIssuer
        case .unknownKey: .unknownKey
        case .badSignature: .badSignature
        case .wrongAudience: .wrongAudience
        case .expired: .expired
        case .missingClaim(let name): .missingClaim(name)
        case .unsupportedSubjectType, .unexpectedActor, .callerTypeNotAllowed, .actorNotAllowed,
             .wildcardScopeInDelegatedToken:
            .wrongType
        }
    }
}
