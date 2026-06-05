import Testing
import Foundation
@testable import Middleware

/// Counts upstream calls and records the userIds it was asked about.
private actor CountingProvider: PermissionsProvider {
    private(set) var callCount = 0
    private(set) var seenUserIds: [String] = []
    private let toReturn: [String]

    init(returning toReturn: [String]) { self.toReturn = toReturn }

    func permissions(forUserId userId: String) async throws -> [String] {
        callCount += 1
        seenUserIds.append(userId)
        return toReturn
    }
}

@Suite struct CachingPermissionsProviderTests {
    @Test func cachesWithinTTLSoUpstreamIsCalledOnce() async throws {
        let upstream = CountingProvider(returning: ["business:read"])
        let cache = CachingPermissionsProvider(wrapping: upstream, ttl: .seconds(60))

        let a = try await cache.permissions(forUserId: "u1")
        let b = try await cache.permissions(forUserId: "u1")
        let c = try await cache.permissions(forUserId: "u1")

        #expect(a == ["business:read"])
        #expect(b == ["business:read"])
        #expect(c == ["business:read"])
        #expect(await upstream.callCount == 1)  // only the first call hit upstream
    }

    @Test func cachesPerUserId() async throws {
        let upstream = CountingProvider(returning: ["x"])
        let cache = CachingPermissionsProvider(wrapping: upstream, ttl: .seconds(60))

        _ = try await cache.permissions(forUserId: "u1")
        _ = try await cache.permissions(forUserId: "u2")
        _ = try await cache.permissions(forUserId: "u1")  // cached

        #expect(await upstream.callCount == 2)  // one per distinct user
        #expect(await upstream.seenUserIds == ["u1", "u2"])
    }

    @Test func refetchesAfterTTLExpires() async throws {
        let upstream = CountingProvider(returning: ["x"])
        let cache = CachingPermissionsProvider(wrapping: upstream, ttl: .milliseconds(100))

        _ = try await cache.permissions(forUserId: "u1")
        try await Task.sleep(for: .milliseconds(300))  // let the entry expire (generous margin)
        _ = try await cache.permissions(forUserId: "u1")

        #expect(await upstream.callCount == 2)  // expired -> refetched
    }

    @Test func invalidateForcesRefetch() async throws {
        let upstream = CountingProvider(returning: ["x"])
        let cache = CachingPermissionsProvider(wrapping: upstream, ttl: .seconds(60))

        _ = try await cache.permissions(forUserId: "u1")
        await cache.invalidate(userId: "u1")
        _ = try await cache.permissions(forUserId: "u1")

        #expect(await upstream.callCount == 2)
    }
}
