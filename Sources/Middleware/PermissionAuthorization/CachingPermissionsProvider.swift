//
//  CachingPermissionsProvider.swift
//  Middleware
//
//  A TTL-caching decorator over any `PermissionsProvider`, so the upstream (e.g. IAMContext) is not
//  called on every request. Uses a monotonic clock (ContinuousClock) so wall-clock changes don't
//  affect expiry. Thrown failures are never cached, so a transient upstream blip won't get stuck.
//
//  Bounding & freshness:
//  - `maxEntries` caps memory: on insert, expired entries are swept first, then the oldest is dropped.
//    Expired entries are also evicted lazily when the same userId is looked up again.
//  - Empty results (e.g. a 404 → []) use a separate, shorter `negativeTTL` so a just-provisioned user
//    isn't stuck being denied for the full positive `ttl`. Pass `negativeTTL: nil` to not cache empties
//    at all (every lookup of a no-permission user then hits the upstream).
//
//  Note: this does not coalesce concurrent cold-cache lookups for the same userId — under a burst,
//  a few duplicate upstream calls may occur until the first result is cached. That's a correctness-safe
//  optimisation gap, not a bug.
//

public actor CachingPermissionsProvider: PermissionsProvider {
    private let upstream: any PermissionsProvider
    private let ttl: Duration
    private let negativeTTL: Duration?
    private let maxEntries: Int
    private let clock: ContinuousClock

    private struct Entry {
        let permissions: [String]
        let storedAt: ContinuousClock.Instant
    }
    private var cache: [String: Entry] = [:]

    /// - Parameters:
    ///   - upstream: the real provider (e.g. an IAMContext getPermissions adapter).
    ///   - ttl: how long a non-empty (granted) lookup stays fresh. Default 60s.
    ///   - negativeTTL: how long an empty result ([]) stays fresh; `nil` = don't cache empties.
    ///     Kept short by default so a newly-granted user isn't denied for the full `ttl`. Default 10s.
    ///   - maxEntries: hard cap on cached users; beyond it, expired-then-oldest entries are evicted.
    public init(wrapping upstream: any PermissionsProvider,
                ttl: Duration = .seconds(60),
                negativeTTL: Duration? = .seconds(10),
                maxEntries: Int = 10_000) {
        self.upstream = upstream
        self.ttl = ttl
        self.negativeTTL = negativeTTL
        self.maxEntries = max(1, maxEntries)
        self.clock = ContinuousClock()
    }

    public func permissions(forUserId userId: String) async throws -> [String] {
        let now = clock.now

        if let entry = cache[userId] {
            if let freshness = cacheableTTL(for: entry.permissions),
               entry.storedAt.duration(to: now) < freshness {
                return entry.permissions
            }
            cache[userId] = nil   // expired -> evict (bounds growth for re-looked-up users)
        }

        let fresh = try await upstream.permissions(forUserId: userId)

        if let freshness = cacheableTTL(for: fresh), freshness > .zero {
            evictIfAtCapacity(for: userId, now: now)
            cache[userId] = Entry(permissions: fresh, storedAt: now)
        }
        return fresh
    }

    /// The freshness window for a result, or `nil` if it should not be cached at all.
    private func cacheableTTL(for permissions: [String]) -> Duration? {
        permissions.isEmpty ? negativeTTL : ttl
    }

    /// Make room for a *new* key when the cache is at capacity: drop expired entries first,
    /// then the oldest, until there is space.
    private func evictIfAtCapacity(for userId: String, now: ContinuousClock.Instant) {
        guard cache[userId] == nil, cache.count >= maxEntries else { return }
        for (key, entry) in cache {
            if let freshness = cacheableTTL(for: entry.permissions),
               entry.storedAt.duration(to: now) >= freshness {
                cache[key] = nil
            }
        }
        while cache.count >= maxEntries,
              let oldest = cache.min(by: { $0.value.storedAt < $1.value.storedAt })?.key {
            cache[oldest] = nil
        }
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
