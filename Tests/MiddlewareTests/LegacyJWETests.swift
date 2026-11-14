import Testing
import Foundation
import Hummingbird
import HummingbirdTesting
import Logging
import MiddlewareTesting
@testable import Middleware

private func makeApp(mode: LegacyJWEMode, logger: Logger) throws -> some ApplicationProtocol {
    let router = Router()
    router.add(middleware: BearerTokenAuthenticationMiddleware(
        verification: AccessTokenVerification(recipientKey: testRecipientKey)!,
        trust: try icOcTrust(),
        legacyJWE: mode,
        serviceName: "TestService",
        logger: logger
    ))
    router.get("items/:id") { _, _ in describe(Caller.current) }
    return Application(router: router)
}

private let userId = "user-7f3a9"

/// Log lines that carry the given message.
private func lines(_ store: CapturingLogHandler.Store, containing text: String) -> [String] {
    store.all.split(separator: "\n").map(String.init).filter { $0.contains(text) }
}

@Suite struct LegacyJWETests {
    @Test func modeFromEnvironment() throws {
        #expect(try LegacyJWEMode.fromEnvironment([:]) == .accept)
        #expect(try LegacyJWEMode.fromEnvironment(["MENDESKY_LEGACY_JWE": " "]) == .accept)
        #expect(try LegacyJWEMode.fromEnvironment(["MENDESKY_LEGACY_JWE": "accept"]) == .accept)
        #expect(try LegacyJWEMode.fromEnvironment(["MENDESKY_LEGACY_JWE": "warn"]) == .warn)
        #expect(try LegacyJWEMode.fromEnvironment(["MENDESKY_LEGACY_JWE": " Reject\n"]) == .reject)
        #expect(throws: LegacyJWEModeError(value: "bogus")) {
            try LegacyJWEMode.fromEnvironment(["MENDESKY_LEGACY_JWE": "bogus"])
        }
    }

    @Test func acceptedJWELogsLegacyCounterWithoutTokenOrUserId() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(mode: .accept, logger: logger)
        let jwe = try jweUserToken(userId: userId, clientId: "")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/items/42", method: .get, headers: headers(jwe, operatorId: userId))
            #expect(res.status == .ok)
        }
        let counted = lines(store, containing: "legacy-jwe-accepted")
        #expect(counted.count == 1)
        let line = try #require(counted.first)
        for expected in ["notice", "{id}", "TestService", "clientId"] { #expect(line.contains(expected)) }
        // Exactly the allowed metadata keys.
        let keys = line.matches(of: /"(\w+)":/).map { String($0.output.1) }
        #expect(Set(keys) == ["clientId", "route", "service"] && keys.count == 3)
        #expect(!store.all.contains(jwe))
        #expect(!store.all.contains(userId))
        #expect(!store.all.contains("/items/42"))
    }

    @Test func warnModeLogsAtWarning() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(mode: .warn, logger: logger)
        let jwe = try jweUserToken(userId: userId, clientId: "")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/items/42", method: .get, headers: headers(jwe, operatorId: userId))
            #expect(res.status == .ok)
        }
        let line = try #require(lines(store, containing: "legacy-jwe-accepted").first)
        #expect(line.hasPrefix("warning"))
    }

    @Test func rejectModeRefusesJWEButAcceptsSignedTokens() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(mode: .reject, logger: logger)
        let jwe = try jweUserToken(userId: userId, clientId: "")
        try await app.test(.router) { client in
            let refused = try await client.execute(uri: "/items/42", method: .get, headers: headers(jwe, operatorId: userId))
            #expect(refused.status == .unauthorized)
            let signed = ic.token(sub: userId, clientId: "mendesky-first-party", subType: "user")
            let ok = try await client.execute(uri: "/items/42", method: .get, headers: headers(signed, operatorId: userId))
            #expect(ok.status == .ok)
        }
        let rejected = try #require(lines(store, containing: "legacy-jwe-rejected").first)
        #expect(rejected.contains("{id}") && rejected.contains("TestService"))
        #expect(!store.all.contains(jwe))
        #expect(!store.all.contains(userId))
        #expect(lines(store, containing: "legacy-jwe-accepted").isEmpty)
    }

    @Test func rejectedJWEIsNotCounted() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(mode: .accept, logger: logger)
        let jwe = try jweUserToken(userId: userId, clientId: "")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/items/42", method: .get, headers: headers(jwe, operatorId: "someone-else"))
            #expect(res.status == .badRequest)
        }
        #expect(!store.all.contains("legacy-jwe-accepted"))
    }

    @Test func invalidModeRefusesToStart() {
        #expect(throws: LegacyJWEModeError(value: "off")) {
            try BearerTokenAuthenticationMiddleware(
                environment: ["MENDESKY_LEGACY_JWE": "off"], validators: [], accepting: [])
        }
    }
}
