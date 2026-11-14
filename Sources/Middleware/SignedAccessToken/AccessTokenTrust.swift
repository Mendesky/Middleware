import Foundation
import JSONWebKey

/// The kinds of caller a trusted issuer may vouch for. The raw value is the JSON string in the trust configuration.
public enum CallerType: String, Sendable, Hashable, CaseIterable {
    case user
    case application
    case delegatedUser
}

/// One issuer Middleware trusts to sign `at+jwt` access tokens, with the keys it signs with.
/// The initializer does not validate; `AccessTokenTrust` does, once, at startup.
public struct TrustedIssuer: Sendable {
    public let issuer: String
    public let callerTypes: Set<CallerType>
    /// Client ids allowed to act on behalf of a user (`act.sub`). Only meaningful with `.delegatedUser`.
    public let actors: [String]
    public let publicKeys: [JWK]

    public init(issuer: String, callerTypes: Set<CallerType>, actors: [String] = [], publicKeys: [JWK]) {
        self.issuer = issuer
        self.callerTypes = callerTypes
        self.actors = actors
        self.publicKeys = publicKeys
    }
}

/// Startup configuration errors. Associated values are configuration values or variable names, never key material.
public enum AccessTokenTrustError: Error, Equatable, CustomStringConvertible {
    case unreadable
    case missingAudience
    case noIssuers
    case blankIssuer
    case duplicateIssuer(String)
    case noCallerTypes(issuer: String)
    case unknownCallerType(String)
    case multipleUserIssuers
    case userIssuerAllowsOtherCallerTypes(issuer: String)
    case delegatedUserWithoutActors(issuer: String)
    case emptyKeySet(issuer: String)
    case keyWithoutKid(issuer: String)
    case duplicateKid(String)
    case privateKeyMaterial(kid: String)
    case unsupportedKey(kid: String)
    case keyTooShort(kid: String)
    /// A pre-unification application-token variable is set; it is no longer read.
    case renamedVariable(String)

    public var description: String {
        switch self {
        case .unreadable: "access token trust configuration is unreadable or malformed"
        case .missingAudience: "access token trust configuration has no audience"
        case .noIssuers: "access token trust configuration lists no issuers"
        case .blankIssuer: "access token trust configuration has an issuer with a blank name"
        case .duplicateIssuer(let issuer): "issuer \(issuer) is listed more than once"
        case .noCallerTypes(let issuer): "issuer \(issuer) allows no caller types"
        case .unknownCallerType(let type): "unknown caller type \(type)"
        case .multipleUserIssuers: "more than one issuer is allowed to issue user tokens"
        case .userIssuerAllowsOtherCallerTypes(let issuer):
            "issuer \(issuer) may issue user tokens and so must allow no other caller type"
        case .delegatedUserWithoutActors(let issuer): "issuer \(issuer) allows delegatedUser but lists no actors"
        case .emptyKeySet(let issuer): "issuer \(issuer) has no keys"
        case .keyWithoutKid(let issuer): "issuer \(issuer) has a key without a kid"
        case .duplicateKid(let kid): "kid \(kid) appears more than once"
        case .privateKeyMaterial(let kid): "key \(kid) contains private key material"
        case .unsupportedKey(let kid): "key \(kid) is not an RSA key usable with RS256"
        case .keyTooShort(let kid): "key \(kid) is shorter than 2048 bits"
        case .renamedVariable(let name):
            "\(name) is no longer read; use MENDESKY_ACCESS_TOKEN_TRUST or MENDESKY_ACCESS_TOKEN_TRUST_PATH"
        }
    }
}

/// Which issuers Middleware trusts for `at+jwt` access tokens, validated at construction so a bad configuration
/// stops the service from starting instead of weakening verification.
public struct AccessTokenTrust: Sendable {
    public let audience: String
    public let issuers: [TrustedIssuer]
    private let issuersByName: [String: TrustedIssuer]
    private let keysByKid: [String: (issuer: String, key: JWK)]

    public init(audience: String, issuers: [TrustedIssuer]) throws(AccessTokenTrustError) {
        try self.init(audience: audience, issuers: issuers, rawPrivateMembers: nil)
    }

    /// Parses the trust JSON (`{"audience": ..., "issuers": [{"issuer", "callerTypes", "actors", "keys": {"keys": [...]}}]}`).
    public init(json: Data) throws(AccessTokenTrustError) {
        guard let document = try? JSONDecoder().decode(Document.self, from: json) else { throw .unreadable }
        var issuers: [TrustedIssuer] = []
        for entry in document.issuers {
            var callerTypes: Set<CallerType> = []
            for name in entry.callerTypes {
                guard let type = CallerType(rawValue: name) else { throw .unknownCallerType(name) }
                callerTypes.insert(type)
            }
            issuers.append(TrustedIssuer(
                issuer: entry.issuer, callerTypes: callerTypes, actors: entry.actors ?? [], publicKeys: entry.keys.keys
            ))
        }
        // The raw parse must succeed and mirror the typed one; if the two parsers disagree, refuse rather than guess.
        guard let raw = Self.rawPrivateMembers(in: json),
              raw.count == issuers.count,
              zip(raw, issuers).allSatisfy({ $0.count == $1.publicKeys.count })
        else { throw .unreadable }
        try self.init(audience: document.audience, issuers: issuers, rawPrivateMembers: raw)
    }

    /// Reads `MENDESKY_ACCESS_TOKEN_TRUST_PATH` (a file; wins) or `MENDESKY_ACCESS_TOKEN_TRUST` (base64 JSON).
    /// Returns `nil` when neither is set (feature off). Any pre-unification application-token variable
    /// (the four names listed below) makes this throw `.renamedVariable`, so an old deployment fails loudly instead of silently losing a path.
    public static func fromEnvironment(
        _ env: [String: String] = ProcessInfo.processInfo.environment
    ) throws(AccessTokenTrustError) -> AccessTokenTrust? {
        for name in [
            "MENDESKY_APP_TOKEN_JWKS", "MENDESKY_APP_TOKEN_JWKS_PATH",
            "MENDESKY_APP_TOKEN_ISSUER", "MENDESKY_APP_TOKEN_AUDIENCE",
        ] where nonBlank(env[name]) != nil {
            throw .renamedVariable(name)
        }

        let path = nonBlank(env["MENDESKY_ACCESS_TOKEN_TRUST_PATH"])
        let base64 = nonBlank(env["MENDESKY_ACCESS_TOKEN_TRUST"])
        guard path != nil || base64 != nil else { return nil }

        let data: Data
        if let path {
            guard let read = try? Data(contentsOf: URL(filePath: path)) else { throw .unreadable }
            data = read
        } else if let base64, let decoded = Data(base64Encoded: base64) {
            data = decoded
        } else {
            throw .unreadable
        }
        return try AccessTokenTrust(json: data)
    }

    func issuer(named name: String) -> TrustedIssuer? { issuersByName[name] }

    /// The key with this `kid`, only if it belongs to `issuer`.
    func key(issuer: String, kid: String) -> JWK? {
        guard let entry = keysByKid[kid], entry.issuer == issuer else { return nil }
        return entry.key
    }

    // MARK: Validation

    /// `rawPrivateMembers[issuerIndex][keyIndex]` is true when that key's raw JSON carried a private member.
    /// It is `nil` for the Swift initializer, where the `JWK` properties are checked instead.
    private init(
        audience: String, issuers: [TrustedIssuer], rawPrivateMembers: [[Bool]]?
    ) throws(AccessTokenTrustError) {
        guard nonBlank(audience) != nil else { throw .missingAudience }
        guard !issuers.isEmpty else { throw .noIssuers }

        var byName: [String: TrustedIssuer] = [:]
        var byKid: [String: (issuer: String, key: JWK)] = [:]
        for (issuerIndex, trusted) in issuers.enumerated() {
            let name = trusted.issuer
            guard nonBlank(name) != nil else { throw .blankIssuer }
            guard byName[name] == nil else { throw .duplicateIssuer(name) }
            guard !trusted.callerTypes.isEmpty else { throw .noCallerTypes(issuer: name) }
            if trusted.callerTypes.contains(.delegatedUser), trusted.actors.allSatisfy({ nonBlank($0) == nil }) {
                throw .delegatedUserWithoutActors(issuer: name)
            }
            guard !trusted.publicKeys.isEmpty else { throw .emptyKeySet(issuer: name) }

            for (keyIndex, key) in trusted.publicKeys.enumerated() {
                // Printable ASCII without `"` or `\`: anything else is escaped in the token header, so the
                // verifier would reject every token and startup would give no hint.
                guard let kid = key.keyID, !kid.isEmpty,
                      kid.utf8.allSatisfy({ (0x21...0x7E).contains($0) && $0 != 0x22 && $0 != 0x5C })
                else { throw .keyWithoutKid(issuer: name) }
                let rawPrivate: Bool
                if let rawPrivateMembers {
                    guard rawPrivateMembers.indices.contains(issuerIndex),
                          rawPrivateMembers[issuerIndex].indices.contains(keyIndex)
                    else { throw .unreadable }
                    rawPrivate = rawPrivateMembers[issuerIndex][keyIndex]
                } else {
                    rawPrivate = false
                }
                if rawPrivate || key.d != nil || key.p != nil || key.q != nil
                    || key.dp != nil || key.dq != nil || key.qi != nil {
                    throw .privateKeyMaterial(kid: kid)
                }
                guard key.keyType == .rsa, let modulus = key.n, let exponent = key.e, Self.isUsableExponent(exponent),
                      key.algorithm == nil || key.algorithm == "RS256",
                      key.publicKeyUse == nil || key.publicKeyUse == .signature
                else { throw .unsupportedKey(kid: kid) }
                // Exact bit length: leading zero bytes add nothing, and a top byte below 0x80 leaves bits unused.
                let significant = modulus.drop(while: { $0 == 0 })
                guard let top = significant.first,
                      (significant.count - 1) * 8 + (8 - top.leadingZeroBitCount) >= 2048
                else { throw .keyTooShort(kid: kid) }
                guard byKid[kid] == nil else { throw .duplicateKid(kid) }
                byKid[kid] = (name, key)
            }
            byName[name] = trusted
        }

        let userIssuers = issuers.filter { $0.callerTypes.contains(.user) }
        guard userIssuers.count <= 1 else { throw .multipleUserIssuers }
        if let only = userIssuers.first, only.callerTypes != [.user] {
            throw .userIssuerAllowsOtherCallerTypes(issuer: only.issuer)
        }

        self.audience = audience
        self.issuers = issuers
        self.issuersByName = byName
        self.keysByKid = byKid
    }

    // MARK: JSON

    private struct Document: Decodable {
        struct Entry: Decodable {
            let issuer: String
            let callerTypes: [String]
            let actors: [String]?
            let keys: KeySet
        }
        struct KeySet: Decodable { let keys: [JWK] }

        let audience: String
        let issuers: [Entry]
    }

    /// An RSA public exponent must be an odd integer of at least 3; `e = 1` would let anyone forge signatures.
    private static func isUsableExponent(_ exponent: Data) -> Bool {
        let significant = exponent.drop(while: { $0 == 0 })
        guard let last = significant.last, last & 1 == 1 else { return false }
        return significant.count > 1 || last >= 3
    }

    private static let privateMemberNames: Set<String> = ["d", "p", "q", "dp", "dq", "qi"]

    /// jose-swift's JWK decoding drops `dp`/`dq`/`qi`, so the decoded JWKs cannot reveal them. Looks at the raw
    /// member names of every key instead. 
    /// Returns `nil` when the raw parse fails or has an unexpected shape.
    private static func rawPrivateMembers(in json: Data) -> [[Bool]]? {
        guard let root = (try? JSONSerialization.jsonObject(with: json)) as? [String: Any],
              let issuers = root["issuers"] as? [[String: Any]]
        else { return nil }
        var result: [[Bool]] = []
        for issuer in issuers {
            guard let keys = (issuer["keys"] as? [String: Any])?["keys"] as? [[String: Any]] else { return nil }
            result.append(keys.map { !privateMemberNames.isDisjoint(with: $0.keys) })
        }
        return result
    }
}

// MARK: Shared string helpers (shared with the verification code)

func nonBlank(_ value: String?) -> String? {
    guard let value, !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return nil }
    return value
}
