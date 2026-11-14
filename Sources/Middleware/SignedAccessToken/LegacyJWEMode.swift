import Foundation

/// What `BearerTokenAuthenticationMiddleware` does with legacy JWE user tokens (`MENDESKY_LEGACY_JWE`).
public enum LegacyJWEMode: String, Sendable {
    /// Accept JWE tokens (default).
    case accept
    /// Accept JWE tokens, logging each one at warning level.
    case warn
    /// Refuse JWE tokens with `401`.
    case reject

    /// Reads `MENDESKY_LEGACY_JWE`.
    // TODO(Task 5): parse `MENDESKY_LEGACY_JWE` (accept | warn | reject; blank = accept; other values throw).
    // Until then every environment yields `.accept`, which is the behaviour before this setting existed.
    public static func fromEnvironment(
        _ env: [String: String] = ProcessInfo.processInfo.environment
    ) throws(LegacyJWEModeError) -> LegacyJWEMode {
        .accept
    }
}

/// `MENDESKY_LEGACY_JWE` holds a value other than `accept`, `warn` or `reject`.
public struct LegacyJWEModeError: Error, Equatable {
    /// The configured value, as set.
    public let value: String
}
