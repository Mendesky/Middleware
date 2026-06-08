import Testing
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import CryptoKit
import JSONWebKey
import JSONWebEncryption
import JSONWebAlgorithms
@testable import Middleware

// Live end-to-end against a running IAMContext. Skipped unless IAM_BASE_URL is set, e.g.:
//   IAM_BASE_URL=http://localhost:24202 swift test --filter LiveIAMIntegrationTests
// Exercises the real chain: PermissionMiddleware -> HTTP PermissionsProvider -> IAMContext getPermissions.

private enum LiveIAM {
    static var baseURL: String? { ProcessInfo.processInfo.environment["IAM_BASE_URL"] }
}

/// A real `PermissionsProvider` that calls IAMContext `GET /employee-access/permissions/{userId}`.
/// 404 (no profile) is treated as "no permissions" ([]); other non-200s are errors (-> 502 in the middleware).
private struct HTTPPermissionsProvider: PermissionsProvider {
    let baseURL: String

    func permissions(forUserId userId: String) async throws -> [String] {
        let url = URL(string: "\(baseURL)/employee-access/permissions/\(userId)")!
        let (data, response) = try await URLSession.shared.data(from: url)
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        switch status {
        case 200: return try JSONDecoder().decode([String].self, from: data)
        case 404: return []
        default: throw URLError(.badServerResponse)
        }
    }
}

// MARK: - token plumbing (one EC key for both encrypt + decrypt)

private let recipientKey: JWK = P256.KeyAgreement.PrivateKey().jwkRepresentation

private func makeVerification() -> AccessTokenVerification { AccessTokenVerification(recipientKey: recipientKey)! }

private func makeToken(userId: String) throws -> String {
    let payload = AccessTokenPayload(authorizationId: "a", userId: userId, clientId: "c", scope: [], expiresAt: Date(timeIntervalSinceNow: 3600))
    let data = try JSONEncoder().encode(payload)
    let jwe = try JWE(payload: data, keyManagementAlg: .ecdhESA256KW, encryptionAlgorithm: .a256GCM, recipientKey: recipientKey)
    return jwe.compactSerialization
}

private func bearer(_ token: String) -> HTTPFields {
    var headers = HTTPFields()
    headers[.authorization] = "Bearer \(token)"
    return headers
}

// MARK: - IAMContext seeding helpers

private func seedProfile(baseURL: String, employeeAccessId: String, userId: String) async throws {
    var req = URLRequest(url: URL(string: "\(baseURL)/employee-access/\(employeeAccessId)/create-user-access-profile")!)
    req.httpMethod = "POST"
    req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    req.setValue("seed-op", forHTTPHeaderField: "operatorId")
    req.httpBody = try JSONEncoder().encode(["userId": userId, "department": "engineering", "jobTitle": "engineer"])
    _ = try await URLSession.shared.data(for: req)
}

/// Polls until the projection has ingested the seeded profile (eventual consistency, ~1-2s observed).
private func waitForPermissions(baseURL: String, userId: String) async throws -> [String] {
    let provider = HTTPPermissionsProvider(baseURL: baseURL)
    for _ in 0..<20 {  // up to ~10s
        let perms = try await provider.permissions(forUserId: userId)
        if !perms.isEmpty { return perms }
        try await Task.sleep(for: .milliseconds(500))
    }
    return []
}

private func makeApp(baseURL: String) throws -> some ApplicationProtocol {
    let rule = PermissionRule(PathValidator(try Regex("/quotations/.+")), methods: [.get], requires: ["business:read"])
    let router = Router()
    router.add(middleware: PermissionMiddleware(rules: [rule], provider: HTTPPermissionsProvider(baseURL: baseURL), verification: makeVerification()))
    router.get("quotations/:id") { _, _ in "ok" }
    return Application(router: router)
}

@Suite struct LiveIAMIntegrationTests {
    @Test(.enabled(if: LiveIAM.baseURL != nil))
    func allowsWhenIAMGrantsThePermission() async throws {
        let base = LiveIAM.baseURL!
        let suffix = UUID().uuidString.prefix(8)
        let userId = "u-\(suffix)", empId = "emp-\(suffix)"

        try await seedProfile(baseURL: base, employeeAccessId: empId, userId: userId)
        let perms = try await waitForPermissions(baseURL: base, userId: userId)
        #expect(perms.contains("business:read"))  // default allPermissions includes it

        let app = try makeApp(baseURL: base)
        let token = try makeToken(userId: userId)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/1", method: .get, headers: bearer(token))
            #expect(res.status == .ok)
        }
    }

    @Test(.enabled(if: LiveIAM.baseURL != nil))
    func forbidsWhenUserHasNoProfileInIAM() async throws {
        let base = LiveIAM.baseURL!
        let userId = "ghost-\(UUID().uuidString.prefix(8))"  // never seeded -> IAM 404 -> [] -> denied

        let app = try makeApp(baseURL: base)
        let token = try makeToken(userId: userId)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/quotations/1", method: .get, headers: bearer(token))
            #expect(res.status == .forbidden)
        }
    }
}
