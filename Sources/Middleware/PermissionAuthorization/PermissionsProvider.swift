//
//  PermissionsProvider.swift
//  Middleware
//
//  Port for fetching a user's current permissions. `PermissionMiddleware` depends on this
//  abstraction so the package does not hard-depend on IAMContext: the consumer injects an
//  adapter (e.g. an IAMContext `getPermissions` HTTP client) once that endpoint exists.
//

/// Supplies the set of permission strings a user currently holds (e.g. `"audit:read"`).
public protocol PermissionsProvider: Sendable {
    /// - Parameter userId: trusted user id (PermissionMiddleware obtains it from the decrypted token).
    /// - Returns: the user's permissions; an empty array means "no permissions".
    func permissions(forUserId userId: String) async throws -> [String]
}

/// A closure-backed `PermissionsProvider`, convenient for wiring and tests.
public struct ClosurePermissionsProvider: PermissionsProvider {
    private let fetch: @Sendable (String) async throws -> [String]

    public init(_ fetch: @escaping @Sendable (String) async throws -> [String]) {
        self.fetch = fetch
    }

    public func permissions(forUserId userId: String) async throws -> [String] {
        try await fetch(userId)
    }
}
