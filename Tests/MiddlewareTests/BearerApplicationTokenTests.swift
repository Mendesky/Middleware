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

private func makeApp(
    signer: ApplicationTokenTestSigner,
    configured: Bool = true,
    logger: Logger = Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }
) -> some ApplicationProtocol {
    let applicationTokens = configured
        ? try? ApplicationTokenVerification(publicKeys: [signer.publicKey], issuer: ApplicationTokenTestSigner.defaultIssuer, audience: ApplicationTokenTestSigner.defaultAudience)
        : nil
    let router = Router()
    router.add(middleware: BearerTokenAuthenticationMiddleware(
        verification: AccessTokenVerification(recipientKey: testRecipientKey)!,
        applicationTokens: applicationTokens,
        acceptsApplication: { $0.uri.path.hasPrefix("/open") },
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
        let app = makeApp(signer: signer, logger: logger)
        let user = try jweUserToken(userId: "u1")
        let appToken = signer.token(sub: "app-1")
        try await app.test(.router) { client in
            let u = try await client.execute(uri: "/closed/boom", method: .get, headers: headers(user, operatorId: "u1"))
            #expect(u.status == .serviceUnavailable)
            #expect(String(buffer: u.body) == "service unavailable.")
            let a = try await client.execute(uri: "/open/boom", method: .get, headers: headers(appToken))
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
        let app = makeApp(signer: signer, logger: logger)
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

    @Test func unconfiguredApplicationTokenLogsWhy() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = makeApp(signer: signer, configured: false, logger: logger)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(signer.token(sub: "app-1")))
            #expect(res.status == .unauthorized)
        }
        #expect(store.all.contains("not configured"))
    }

    @Test func applicationTokenOnOptedInRoutePasses() async throws {
        let app = makeApp(signer: signer)
        let token = signer.token(sub: "ABCDEF01-0000-0000-0000-000000000001")
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(token, operatorId: "whoever"))
            #expect(res.status == .ok)
            #expect(String(buffer: res.body) == "application:abcdef01-0000-0000-0000-000000000001")
        }
    }

    @Test func applicationTokenNeedsNoOperatorId() async throws {
        let app = makeApp(signer: signer)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(signer.token(sub: "app-1")))
            #expect(res.status == .ok)
        }
    }

    @Test func applicationTokenOnOtherRouteIs401() async throws {
        let app = makeApp(signer: signer)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/closed", method: .get, headers: headers(signer.token(sub: "app-1")))
            #expect(res.status == .unauthorized)
        }
    }

    @Test func applicationTokenWithoutConfiguredKeyIs401() async throws {
        let app = makeApp(signer: signer, configured: false)
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(signer.token(sub: "app-1")))
            #expect(res.status == .unauthorized)
        }
    }

    @Test func badApplicationTokenIs401() async throws {
        let app = makeApp(signer: signer)
        let other = ApplicationTokenTestSigner()
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(other.token(sub: "app-1")))
            #expect(res.status == .unauthorized)
        }
    }

    @Test func userTokenStillRequiresOperatorId() async throws {
        let app = makeApp(signer: signer)
        let token = try jweUserToken(userId: "u1")
        try await app.test(.router) { client in
            let missing = try await client.execute(uri: "/open", method: .get, headers: headers(token))
            #expect(missing.status == .badRequest)
            let mismatch = try await client.execute(uri: "/open", method: .get, headers: headers(token, operatorId: "u2"))
            #expect(mismatch.status == .badRequest)
            let ok = try await client.execute(uri: "/closed", method: .get, headers: headers(token, operatorId: "u1"))
            #expect(ok.status == .ok)
            #expect(String(buffer: ok.body) == "user:u1:c")
        }
    }

    @Test func undecryptableJWEIs401AndNotLogged() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = makeApp(signer: signer, logger: logger)
        let garbage = "aaaa.bbbb.cccc.dddd.eeee"
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/closed", method: .get, headers: headers(garbage, operatorId: "u1"))
            #expect(res.status == .unauthorized)
        }
        #expect(!store.all.contains(garbage))
        #expect(!store.all.contains("aaaa"))
    }

    @Test func downstreamHTTPResponseErrorsKeepTheirStatus() async throws {
        let app = makeApp(signer: signer)
        let user = try jweUserToken(userId: "u1")
        try await app.test(.router) { client in
            let u = try await client.execute(uri: "/closed/missing", method: .get, headers: headers(user, operatorId: "u1"))
            #expect(u.status == .notFound)
            let a = try await client.execute(uri: "/open/missing", method: .get, headers: headers(signer.token(sub: "app-1")))
            #expect(a.status == .notFound)
        }
    }
}
