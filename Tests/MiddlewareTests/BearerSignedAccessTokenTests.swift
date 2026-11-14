import Testing
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import MiddlewareTesting
@testable import Middleware

private func makeApp(trust: AccessTokenTrust?, logger: Logger = Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }) throws -> some ApplicationProtocol {
    let router = Router()
    router.add(middleware: BearerTokenAuthenticationMiddleware(
        verification: AccessTokenVerification(recipientKey: testRecipientKey)!,
        trust: trust,
        accepting: [
            .application(PathValidator("/open")),
            .delegatedUser(PathValidator(try Regex("/quotes/.+")), methods: [.get], requiresScope: "quote:read"),
            .delegatedUser(PathValidator("/drafts"), requiresScope: "quote:write", actors: ["mendesky-mcp-server"]),
        ],
        serviceName: "TestService",
        logger: logger
    ))
    router.get("closed") { _, _ in describe(Caller.current) }
    router.get("open") { _, _ in describe(Caller.current) }
    router.get("quotes/:id") { _, _ in describe(Caller.current) }
    router.post("quotes/:id") { _, _ in describe(Caller.current) }
    router.get("drafts") { _, _ in describe(Caller.current) }
    return Application(router: router)
}

/// `ic` user, `oc` application + delegatedUser for two actors.
private func configuredTrust() throws -> AccessTokenTrust {
    try icOcTrust(ocActors: ["mendesky-mcp-server", "other-mcp"])
}

private func firstPartyUserToken(sub: String = "acc_1") -> String {
    ic.token(sub: sub, clientId: "mendesky-first-party", subType: "user")
}

private func delegatedToken(
    scope: String = "quote:read", actors: [String] = ["mendesky-mcp-server", "claude-connector"]
) -> String {
    oc.token(sub: "acc_1", clientId: "mendesky-mcp-server", scope: scope, subType: "user", actors: actors)
}

private func applicationToken() -> String {
    oc.token(sub: "app-1", scope: "notification:send")
}

@Suite struct BearerSignedAccessTokenTests {
    @Test func withoutTrustConfigBehaviourIsUnchanged() async throws {
        let app = try makeApp(trust: nil)
        let jwe = try jweUserToken(userId: "u1")
        try await app.test(.router) { client in
            let ok = try await client.execute(uri: "/closed", method: .get, headers: headers(jwe, operatorId: "u1"))
            #expect(ok.status == .ok)
            #expect(String(buffer: ok.body) == "user:u1:c")
            let noOperator = try await client.execute(uri: "/closed", method: .get, headers: headers(jwe))
            #expect(noOperator.status == .badRequest)
            let signed = try await client.execute(
                uri: "/open", method: .get, headers: headers(firstPartyUserToken(), operatorId: "acc_1"))
            #expect(signed.status == .unauthorized)
            let application = try await client.execute(uri: "/open", method: .get, headers: headers(applicationToken()))
            #expect(application.status == .unauthorized)
            let missing = try await client.execute(uri: "/closed", method: .get)
            #expect(missing.status == .unauthorized)
            let fourSegments = try await client.execute(uri: "/closed", method: .get, headers: headers("a.b.c.d"))
            #expect(fourSegments.status == .unauthorized)
        }
    }

    @Test func firstPartyUserTokenPassesEveryRouteWithOperatorId() async throws {
        let app = try makeApp(trust: configuredTrust())
        let token = firstPartyUserToken()
        try await app.test(.router) { client in
            for uri in ["/closed", "/open"] {
                let res = try await client.execute(uri: uri, method: .get, headers: headers(token, operatorId: "acc_1"))
                #expect(res.status == .ok)
                #expect(String(buffer: res.body) == "user:acc_1:mendesky-first-party")
            }
        }
    }

    @Test func firstPartyUserTokenRequiresOperatorId() async throws {
        let app = try makeApp(trust: configuredTrust())
        let token = firstPartyUserToken()
        try await app.test(.router) { client in
            let missing = try await client.execute(uri: "/closed", method: .get, headers: headers(token))
            #expect(missing.status == .badRequest)
            let mismatch = try await client.execute(uri: "/closed", method: .get, headers: headers(token, operatorId: "acc_2"))
            #expect(mismatch.status == .badRequest)
        }
    }

    @Test func firstPartyUserIdIsComparedVerbatim() async throws {
        let app = try makeApp(trust: configuredTrust())
        let token = firstPartyUserToken(sub: "Acc_1")
        try await app.test(.router) { client in
            let lower = try await client.execute(uri: "/closed", method: .get, headers: headers(token, operatorId: "acc_1"))
            #expect(lower.status == .badRequest)
            let exact = try await client.execute(uri: "/closed", method: .get, headers: headers(token, operatorId: "Acc_1"))
            #expect(exact.status == .ok)
            #expect(String(buffer: exact.body) == "user:Acc_1:mendesky-first-party")
        }
    }

    @Test func jweStillWorksWhenTrustIsConfigured() async throws {
        let app = try makeApp(trust: configuredTrust())
        let jwe = try jweUserToken(userId: "u1")
        try await app.test(.router) { client in
            let ok = try await client.execute(uri: "/closed", method: .get, headers: headers(jwe, operatorId: "u1"))
            #expect(ok.status == .ok)
            #expect(String(buffer: ok.body) == "user:u1:c")
            let noOperator = try await client.execute(uri: "/closed", method: .get, headers: headers(jwe))
            #expect(noOperator.status == .badRequest)
        }
    }

    @Test func otherSegmentCountsAre401WhenTrustIsConfigured() async throws {
        let app = try makeApp(trust: configuredTrust())
        try await app.test(.router) { client in
            for token in ["a.b", "a.b.c.d", "a.b.c.d.e.f"] {
                let res = try await client.execute(uri: "/open", method: .get, headers: headers(token, operatorId: "u1"))
                #expect(res.status == .unauthorized)
            }
        }
    }

    @Test func oidcUserTokenWithoutActIs401Everywhere() async throws {
        let app = try makeApp(trust: configuredTrust())
        let token = oc.token(sub: "acc_1", clientId: "mendesky-mcp-server", scope: "quote:read", subType: "user")
        try await app.test(.router) { client in
            for uri in ["/closed", "/open", "/quotes/1"] {
                let res = try await client.execute(uri: uri, method: .get, headers: headers(token, operatorId: "acc_1"))
                #expect(res.status == .unauthorized)
            }
        }
    }

    @Test func applicationTokenOnlyOnApplicationRoutes() async throws {
        let app = try makeApp(trust: configuredTrust())
        let token = applicationToken()
        try await app.test(.router) { client in
            let open = try await client.execute(uri: "/open", method: .get, headers: headers(token))
            #expect(open.status == .ok)
            #expect(String(buffer: open.body) == "application:app-1")
            for uri in ["/closed", "/quotes/1"] {
                let res = try await client.execute(uri: uri, method: .get, headers: headers(token))
                #expect(res.status == .unauthorized)
            }
        }
    }

    @Test func delegatedTokenOnOptedInRouteWithScopePasses() async throws {
        let app = try makeApp(trust: configuredTrust())
        try await app.test(.router) { client in
            let res = try await client.execute(
                uri: "/quotes/1", method: .get, headers: headers(delegatedToken(), operatorId: "acc_1"))
            #expect(res.status == .ok)
            #expect(String(buffer: res.body) == "delegated:acc_1:mendesky-mcp-server:mendesky-mcp-server:claude-connector")
        }
    }

    @Test func delegatedTokenWithoutRequiredScopeIs403() async throws {
        let app = try makeApp(trust: configuredTrust())
        try await app.test(.router) { client in
            // Exact match only: neither another scope nor a longer one with the same prefix satisfies `quote:read`.
            for scope in ["quote:list", "quote:read:all", ""] {
                let res = try await client.execute(
                    uri: "/quotes/1", method: .get, headers: headers(delegatedToken(scope: scope), operatorId: "acc_1"))
                #expect(res.status == .forbidden)
                #expect(String(buffer: res.body) == "insufficient scope.")
            }
        }
    }

    @Test func delegatedTokenOnOtherRoutesIs401() async throws {
        let app = try makeApp(trust: configuredTrust())
        let token = delegatedToken()
        try await app.test(.router) { client in
            for (uri, method) in [("/closed", HTTPRequest.Method.get), ("/open", .get), ("/quotes/1", .post)] {
                let res = try await client.execute(uri: uri, method: method, headers: headers(token, operatorId: "acc_1"))
                #expect(res.status == .unauthorized)
            }
        }
    }

    @Test func delegatedTokenRequiresOperatorId() async throws {
        let app = try makeApp(trust: configuredTrust())
        let token = delegatedToken()
        try await app.test(.router) { client in
            let missing = try await client.execute(uri: "/quotes/1", method: .get, headers: headers(token))
            #expect(missing.status == .badRequest)
            let mismatch = try await client.execute(uri: "/quotes/1", method: .get, headers: headers(token, operatorId: "acc_2"))
            #expect(mismatch.status == .badRequest)
        }
    }

    @Test func routeActorRestrictionRejectsOtherActor() async throws {
        let app = try makeApp(trust: configuredTrust())
        try await app.test(.router) { client in
            let other = try await client.execute(
                uri: "/drafts", method: .get,
                headers: headers(delegatedToken(scope: "quote:write", actors: ["other-mcp"]), operatorId: "acc_1"))
            #expect(other.status == .unauthorized)
            let allowed = try await client.execute(
                uri: "/drafts", method: .get,
                headers: headers(delegatedToken(scope: "quote:write", actors: ["mendesky-mcp-server"]), operatorId: "acc_1"))
            #expect(allowed.status == .ok)
            #expect(String(buffer: allowed.body) == "delegated:acc_1:mendesky-mcp-server:mendesky-mcp-server:-")
        }
    }

    @Test func signedTokenRejectionsNeverLogTheToken() async throws {
        let (logger, store) = CapturingLogHandler.logger()
        let app = try makeApp(trust: configuredTrust(), logger: logger)
        let stranger = ApplicationTokenTestSigner(kid: "x-1", issuer: "https://stranger.test")
        let rejected: [(uri: String, token: String)] = [
            ("/open", stranger.token(sub: "app-1")),
            ("/closed", oc.token(sub: "acc_1", clientId: "mendesky-mcp-server", scope: "quote:read", subType: "user")),
            ("/closed", applicationToken()),
            ("/closed", delegatedToken()),
            ("/quotes/1", delegatedToken(scope: "quote:list")),
        ]
        try await app.test(.router) { client in
            for (uri, token) in rejected {
                let res = try await client.execute(uri: uri, method: .get, headers: headers(token, operatorId: "acc_1"))
                #expect(res.status == .unauthorized || res.status == .forbidden)
            }
        }
        let log = store.all
        #expect(log.contains("untrustedIssuer"))
        #expect(log.contains("callerTypeNotAllowed"))
        #expect(log.contains("did not opt in to application tokens"))
        #expect(log.contains("did not opt in to delegated user tokens"))
        #expect(log.contains("insufficient scope"))
        for (_, token) in rejected {
            #expect(!log.contains(token))
        }
    }

    @Test func misconfiguredTrustRefusesToStart() {
        let env = ["MENDESKY_ACCESS_TOKEN_TRUST": ApplicationTokenTestSigner.trustBase64(issuers: [
            ic.trustedIssuer(callerTypes: [.user]), oc.trustedIssuer(callerTypes: [.user])])]
        #expect(throws: AccessTokenTrustError.multipleUserIssuers) {
            try BearerTokenAuthenticationMiddleware(environment: env, validators: [], accepting: [])
        }
    }

    @Test func renamedTrustVariableRefusesToStart() {
        #expect(throws: AccessTokenTrustError.renamedVariable("MENDESKY_APP_TOKEN_JWKS")) {
            try BearerTokenAuthenticationMiddleware(
                environment: ["MENDESKY_APP_TOKEN_JWKS": "x"], validators: [], accepting: [])
        }
    }
}
