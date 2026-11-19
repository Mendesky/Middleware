import Testing
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import MiddlewareTesting
@testable import Middleware

private struct BoomError: Error, CustomStringConvertible {
    let secret: String
    var description: String { "boom \(secret)" }
}

/// `ic` issues first-party users; `signer` issues application tokens unless `configured` is false (then it is not
/// trusted at all). Routes under `/open` accept application tokens (the older `acceptsApplication:` spelling).
private func makeApp(
    signer: ApplicationTokenTestSigner,
    configured: Bool = true,
    logger: Logger = Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }
) throws -> some ApplicationProtocol {
    let issuers = [ic.trustedIssuer(callerTypes: [.user])]
        + (configured ? [signer.trustedIssuer(callerTypes: [.application])] : [])
    let router = Router()
    router.add(middleware: BearerTokenAuthenticationMiddleware(
        trust: try AccessTokenTrust(audience: ApplicationTokenTestSigner.defaultAudience, issuers: issuers),
        accepting: [.application(where: { $0.uri.path.hasPrefix("/open") })],
        logger: logger
    ))
    router.get("open") { _, _ in describe(Caller.current) }
    router.get("open/missing") { _, _ -> String in throw HTTPError(.notFound) }
    router.get("closed") { _, _ in describe(Caller.current) }
    router.get("open/boom") { _, _ -> String in throw BoomError(secret: "request-data-secret") }
    router.get("closed/boom") { _, _ -> String in throw BoomError(secret: "request-data-secret") }
    router.get("closed/missing") { _, _ -> String in throw HTTPError(.notFound) }
    return Application(router: router)
}

@Suite struct BearerApplicationTokenTests {
    let signer = ApplicationTokenTestSigner()

    @Test func plainHandlerErrorsAre503WithGenericBodyAndNoDescriptionLogged() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(signer: signer, logger: logger)
        let user = ic.token(sub: "u1", clientId: "mendesky-first-party", subType: "user")
        let appToken = signer.token(sub: "app-1")
        try await app.test(.router) { client in
            let u = try await client.execute(uri: "/closed/boom", method: .get, headers: headers(user, operatorId: "u1"))
            #expect(u.status == .serviceUnavailable)
            #expect(String(buffer: u.body) == "service unavailable.")
            let a = try await client.execute(
                uri: "/open/boom", method: .get, headers: headers(appToken, operatorId: "app-1", applicationId: "app-1"))
            #expect(a.status == .serviceUnavailable)
            #expect(String(buffer: a.body) == "service unavailable.")
        }
        #expect(store.all.contains("BoomError"))
        #expect(!store.all.contains("request-data-secret"))
        #expect(!store.all.contains(user))
        #expect(!store.all.contains(appToken))
    }

    @Test func rejectedApplicationTokenLogsTheErrorCaseButNotTheToken() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(signer: signer, logger: logger)
        let token = signer.token(sub: "app-1", issuer: "https://other")
        // The signature is checked before the route, so a valid token is needed to reach the route decision.
        let valid = signer.token(sub: "app-1")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(token))
            #expect(res.status == .unauthorized)
            let closed = try await client.execute(uri: "/closed", method: .get, headers: headers(valid))
            #expect(closed.status == .unauthorized)
        }
        #expect(store.all.contains("untrustedIssuer"))
        #expect(store.all.contains("did not opt in"))
        #expect(!store.all.contains(token))
        #expect(!store.all.contains(valid))
    }

    @Test func untrustedApplicationIssuerLogsWhy() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(signer: signer, configured: false, logger: logger)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(signer.token(sub: "app-1")))
            #expect(res.status == .unauthorized)
        }
        #expect(store.all.contains("untrustedIssuer"))
    }

    @Test func applicationTokenOnOptedInRoutePasses() async throws {
        let app = try makeApp(signer: signer)
        let token = signer.token(sub: "ABCDEF01-0000-0000-0000-000000000001")
        let applicationId = "abcdef01-0000-0000-0000-000000000001"
        try await app.test(.router) { client in
            let res = try await client.execute(
                uri: "/open", method: .get, headers: headers(token, operatorId: applicationId, applicationId: applicationId))
            #expect(res.status == .ok)
            #expect(String(buffer: res.body) == "application:abcdef01-0000-0000-0000-000000000001")
        }
    }

    @Test func applicationTokenWithoutCallerHeadersIs400() async throws {
        let app = try makeApp(signer: signer)
        let token = signer.token(sub: "app-1")
        try await app.test(.router) { client in
            let none = try await client.execute(uri: "/open", method: .get, headers: headers(token))
            #expect(none.status == .badRequest)
            let whoever = try await client.execute(
                uri: "/open", method: .get, headers: headers(token, operatorId: "whoever", applicationId: "app-1"))
            #expect(whoever.status == .badRequest)
        }
    }

    @Test func applicationTokenOnOtherRouteIs401() async throws {
        let app = try makeApp(signer: signer)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/closed", method: .get, headers: headers(signer.token(sub: "app-1")))
            #expect(res.status == .unauthorized)
        }
    }

    @Test func applicationTokenWithoutConfiguredKeyIs401() async throws {
        let app = try makeApp(signer: signer, configured: false)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(signer.token(sub: "app-1")))
            #expect(res.status == .unauthorized)
        }
    }

    @Test func badApplicationTokenIs401() async throws {
        let app = try makeApp(signer: signer)
        let other = ApplicationTokenTestSigner()
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(other.token(sub: "app-1")))
            #expect(res.status == .unauthorized)
        }
    }

    @Test func userTokenStillRequiresOperatorId() async throws {
        let app = try makeApp(signer: signer)
        let token = ic.token(sub: "u1", clientId: "mendesky-first-party", subType: "user")
        try await app.test(.router) { client in
            let missing = try await client.execute(uri: "/open", method: .get, headers: headers(token))
            #expect(missing.status == .badRequest)
            let mismatch = try await client.execute(uri: "/open", method: .get, headers: headers(token, operatorId: "u2"))
            #expect(mismatch.status == .badRequest)
            let ok = try await client.execute(uri: "/closed", method: .get, headers: headers(token, operatorId: "u1"))
            #expect(ok.status == .ok)
            #expect(String(buffer: ok.body) == "user:u1:mendesky-first-party")
        }
    }

    @Test func fiveSegmentTokenIs401AndNotLogged() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(signer: signer, logger: logger)
        let garbage = "aaaa.bbbb.cccc.dddd.eeee"
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/closed", method: .get, headers: headers(garbage, operatorId: "u1"))
            #expect(res.status == .unauthorized)
        }
        #expect(!store.all.contains(garbage))
        #expect(!store.all.contains("aaaa"))
    }

    @Test func downstreamHTTPResponseErrorsKeepTheirStatus() async throws {
        let app = try makeApp(signer: signer)
        let user = ic.token(sub: "u1", clientId: "mendesky-first-party", subType: "user")
        try await app.test(.router) { client in
            let u = try await client.execute(uri: "/closed/missing", method: .get, headers: headers(user, operatorId: "u1"))
            #expect(u.status == .notFound)
            let a = try await client.execute(
                uri: "/open/missing", method: .get,
                headers: headers(signer.token(sub: "app-1"), operatorId: "app-1", applicationId: "app-1"))
            #expect(a.status == .notFound)
        }
    }
}
