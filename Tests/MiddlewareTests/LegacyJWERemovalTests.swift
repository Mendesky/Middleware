import Testing
import Foundation
import Hummingbird
import HummingbirdTesting
import Logging
import MiddlewareTesting
@testable import Middleware

// Middleware 2.0: legacy JWE access tokens are gone. A 5-segment token is refused without being decrypted, the trust
// configuration is required, and the 1.x JWE variables are ignored with one startup warning.

private actor HandlerCalls {
    private(set) var count = 0
    func record() { count += 1 }
}

private func makeApp(logger: Logger, calls: HandlerCalls) throws -> some ApplicationProtocol {
    let router = Router()
    router.add(middleware: BearerTokenAuthenticationMiddleware(
        trust: try icOcTrust(),
        serviceName: "TestService",
        logger: logger
    ))
    router.get("items/:id") { _, _ in
        await calls.record()
        return describe(Caller.current)
    }
    return Application(router: router)
}

private let userId = "user-7f3a9"

private func firstPartyToken(_ sub: String = userId) -> String {
    ic.token(sub: sub, clientId: "mendesky-first-party", subType: "user")
}

/// Log lines that carry the given text.
private func lines(_ store: CapturingLogHandler.Store, containing text: String) -> [String] {
    store.all.split(separator: "\n").map(String.init).filter { $0.contains(text) }
}

/// A trust configuration in which `ic` issues first-party user tokens, as `MENDESKY_ACCESS_TOKEN_TRUST` holds it.
private let trustEnvironment = [
    "MENDESKY_ACCESS_TOKEN_TRUST": ApplicationTokenTestSigner.trustBase64(issuers: [ic.trustedIssuer(callerTypes: [.user])])
]

/// Every 1.x legacy JWE variable, each set to a value that must never reach the log.
private let legacyEnvironment = [
    "MENDESKY_AUTH_RECIPIENT_JWK": "secret-recipient-jwk",
    "MENDESKY_AUTH_RECIPIENT_JWK_PATH": "/secret/recipient.json",
    "MENDESKY_AUTH_SENDER_JWK": "secret-sender-jwk",
    "MENDESKY_AUTH_SENDER_JWK_PATH": "/secret/sender.json",
    "MENDESKY_AUTH_PASSWORD": "secret-password",
    "MENDESKY_LEGACY_JWE": "accept",
]

@Suite struct LegacyJWERemovalTests {
    @Test func fiveSegmentTokenIs401WithoutReachingTheHandler() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let calls = HandlerCalls()
        let app = try makeApp(logger: logger, calls: calls)
        let jwe = try jweUserToken(userId: userId)
        #expect(jwe.split(separator: ".", omittingEmptySubsequences: false).count == 5)
        try await app.test(.router) { client in
            for token in [jwe, "aaaa.bbbb.cccc.dddd.eeee"] {
                let res = try await client.execute(uri: "/items/42", method: .get, headers: headers(token, operatorId: userId))
                #expect(res.status == .unauthorized)
                #expect(String(buffer: res.body) == "access token rejected.")
            }
        }
        #expect(await calls.count == 0)

        let rejected = lines(store, containing: "Bearer token rejected: legacy JWE access tokens are no longer accepted")
        #expect(rejected.count == 2)
        let line = try #require(rejected.first)
        #expect(line.hasPrefix("notice"))
        #expect(line.contains("{id}") && line.contains("TestService"))
        // Exactly route and service: never the token, the userId or the concrete path.
        let keys = line.matches(of: /"(\w+)":/).map { String($0.output.1) }
        #expect(Set(keys) == ["route", "service"] && keys.count == 2)
        #expect(!store.all.contains(jwe))
        #expect(!store.all.contains("aaaa"))
        #expect(!store.all.contains(userId))
        #expect(!store.all.contains("/items/42"))
        #expect(!store.all.contains("legacy-jwe"))
    }

    @Test func otherSegmentCountsKeepTheirMessage() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(logger: logger, calls: HandlerCalls())
        try await app.test(.router) { client in
            for token in ["a.b", "a.b.c.d", "a.b.c.d.e.f"] {
                let res = try await client.execute(uri: "/items/42", method: .get, headers: headers(token, operatorId: userId))
                #expect(res.status == .unauthorized)
                #expect(String(buffer: res.body) == "access token rejected.")
            }
        }
        #expect(lines(store, containing: "neither a signed access token nor a JWE").count == 3)
        #expect(lines(store, containing: "legacy JWE").isEmpty)
    }

    @Test func signedFirstPartyTokenStillPasses() async throws {
        let calls = HandlerCalls()
        let app = try makeApp(logger: Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }, calls: calls)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/items/42", method: .get, headers: headers(firstPartyToken(), operatorId: userId))
            #expect(res.status == .ok)
            #expect(String(buffer: res.body) == "user:\(userId):mendesky-first-party")
        }
        #expect(await calls.count == 1)
    }

    @Test func callerHeaderMismatchIsStill400() async throws {
        let calls = HandlerCalls()
        let app = try makeApp(logger: Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }, calls: calls)
        try await app.test(.router) { client in
            let other = try await client.execute(uri: "/items/42", method: .get, headers: headers(firstPartyToken(), operatorId: "someone-else"))
            #expect(other.status == .badRequest)
            let missing = try await client.execute(uri: "/items/42", method: .get, headers: headers(firstPartyToken()))
            #expect(missing.status == .badRequest)
            let wrongApplication = try await client.execute(
                uri: "/items/42", method: .get, headers: headers(firstPartyToken(), operatorId: userId, applicationId: "other-app"))
            #expect(wrongApplication.status == .badRequest)
        }
        #expect(await calls.count == 0)
    }

    @Test func missingTrustRefusesToStart() {
        for environment in [[:], ["MENDESKY_ACCESS_TOKEN_TRUST": " ", "MENDESKY_ACCESS_TOKEN_TRUST_PATH": ""], legacyEnvironment] {
            #expect(throws: BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured) {
                try BearerTokenAuthenticationMiddleware(environment: environment, validators: [], accepting: [])
            }
        }
    }

    @Test func missingTrustErrorNamesTheVariables() {
        let description = BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured.description
        #expect(description.contains("MENDESKY_ACCESS_TOKEN_TRUST"))
        #expect(description.contains("MENDESKY_ACCESS_TOKEN_TRUST_PATH"))
    }

    @Test func leftoverLegacyVariablesAreNamedInOneWarningAndIgnored() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let environment = trustEnvironment.merging(legacyEnvironment) { a, _ in a }
        let middleware = try BearerTokenAuthenticationMiddleware(
            environment: environment, validators: [], accepting: [], logger: logger)

        let warnings = lines(store, containing: "Ignored since Middleware 2.0")
        #expect(warnings.count == 1)
        let warning = try #require(warnings.first)
        #expect(warning.hasPrefix("warning"))
        for name in legacyEnvironment.keys { #expect(warning.contains(name), "\(name)") }
        for value in legacyEnvironment.values where value != "accept" { #expect(!store.all.contains(value), "\(value)") }
        #expect(lines(store, containing: "Signed access tokens enabled: audience=").count == 1)

        // Still works: the variables change nothing.
        let router = Router()
        router.add(middleware: middleware)
        router.get("items/:id") { _, _ in describe(Caller.current) }
        try await Application(router: router).test(.router) { client in
            let ok = try await client.execute(uri: "/items/42", method: .get, headers: headers(firstPartyToken(), operatorId: userId))
            #expect(ok.status == .ok)
            let jwe = try await client.execute(
                uri: "/items/42", method: .get, headers: headers(try jweUserToken(userId: userId), operatorId: userId))
            #expect(jwe.status == .unauthorized)
        }
    }

    @Test func onlyTheLegacyVariablesThatAreSetAreNamed() throws {
        let (logger, store) = CapturingLogHandler.logger()
        let environment = trustEnvironment.merging(["MENDESKY_AUTH_PASSWORD": "pw"]) { a, _ in a }
        _ = try BearerTokenAuthenticationMiddleware(environment: environment, validators: [], accepting: [], logger: logger)
        let warning = try #require(lines(store, containing: "Ignored since Middleware 2.0").first)
        #expect(warning.contains("MENDESKY_AUTH_PASSWORD"))
        #expect(!warning.contains("MENDESKY_AUTH_RECIPIENT_JWK"))
        #expect(!warning.contains("MENDESKY_LEGACY_JWE"))
    }

    @Test func noLegacyVariablesNoWarning() throws {
        let (logger, store) = CapturingLogHandler.logger()
        _ = try BearerTokenAuthenticationMiddleware(environment: trustEnvironment, validators: [], accepting: [], logger: logger)
        #expect(lines(store, containing: "Ignored since Middleware 2.0").isEmpty)
        #expect(!store.all.contains("warning"))
        #expect(lines(store, containing: "Signed access tokens enabled: audience=").count == 1)
    }
}
