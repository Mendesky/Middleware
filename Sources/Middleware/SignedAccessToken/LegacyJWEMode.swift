import Foundation

/// What `BearerTokenAuthenticationMiddleware` does with legacy JWE user tokens (`MENDESKY_LEGACY_JWE`).
public enum LegacyJWEMode: String, Sendable {
    /// Accept JWE tokens (default).
    case accept
    /// Accept JWE tokens, logging each one at warning level.
    case warn
    /// Refuse JWE tokens with `401`.
    case reject

    /// Reads `MENDESKY_LEGACY_JWE`: `accept` (default; unset or blank), `warn` or `reject`, case-insensitive.
    /// Any other value throws, so the service refuses to start.
    public static func fromEnvironment(
        _ env: [String: String] = ProcessInfo.processInfo.environment
    ) throws(LegacyJWEModeError) -> LegacyJWEMode {
        guard let raw = env["MENDESKY_LEGACY_JWE"] else { return .accept }
        let normalized = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized.isEmpty { return .accept }
        guard let mode = LegacyJWEMode(rawValue: normalized) else { throw LegacyJWEModeError(value: raw) }
        return mode
    }
}

/// `MENDESKY_LEGACY_JWE` holds a value other than `accept`, `warn` or `reject`.
public struct LegacyJWEModeError: Error, Equatable {
    /// The configured value, as set.
    public let value: String
}

extension LegacyJWEModeError: CustomStringConvertible {
    public var description: String {
        "MENDESKY_LEGACY_JWE must be one of accept, warn, reject (got \"\(value)\")"
    }
}
