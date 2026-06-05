//
//  CachingPermissionsProvider.swift
//  Middleware
//
//  A TTL-caching decorator over any `PermissionsProvider`, so the upstream (e.g. IAMContext) is not
//  called on every request. Successful lookups are cached per userId for `ttl`; failures are NOT
//  cached, so a transient upstream blip won't get stuck. Uses a monotonic clock (ContinuousClock)
//  so wall-clock changes don't affect expiry.
//
//  Note: this does not coalesce concurrent cold-cache lookups for the same userId — under a burst,
//  a few duplicate upstream calls may occur until the first result is cached. That's a correctness-safe
//  optimisation gap, not a bug.
//

public actor CachingPermissionsProvider: PermissionsProvider {
    private let upstream: any PermissionsProvider
    private let ttl: Duration
    private let clock: ContinuousClock

    private struct Entry {
        let permissions: [String]
        let storedAt: ContinuousClock.Instant
    }
    private var cache: [String: Entry] = [:]

    /// - Parameters:
    ///   - upstream: the real provider (e.g. an IAMContext getPermissions adapter).
    ///   - ttl: how long a successful lookup stays fresh. Default 60s.
    public init(wrapping upstream: any PermissionsProvider, ttl: Duration = .seconds(60)) {
        self.upstream = upstream
        self.ttl = ttl
        self.clock = ContinuousClock()
    }

    public func permissions(forUserId userId: String) async throws -> [String] {
        let now = clock.now
        if let entry = cache[userId], entry.storedAt.duration(to: now) < ttl {
            return entry.permissions
        }
        let fresh = try await upstream.permissions(forUserId: userId)
        cache[userId] = Entry(permissions: fresh, storedAt: now)
        return fresh
    }

    /// Drops all cached entries (e.g. on a known global permission change).
    public func invalidateAll() {
        cache.removeAll()
    }

    /// Drops the cached entry for one user (e.g. right after that user's permissions change).
    public func invalidate(userId: String) {
        cache[userId] = nil
    }
}
