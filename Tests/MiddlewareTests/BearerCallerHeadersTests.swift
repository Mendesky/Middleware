import Testing
import Foundation
import Hummingbird
import HummingbirdTesting
import HTTPTypes
import Logging
import MiddlewareTesting
@testable import Middleware

/// `Caller.current` and every `applicationId` header the handler sees, comma-joined (`-` when there is none).
private func echo(_ request: Request) -> String {
    let values = request.headers[values: CallerHeaders.applicationId]
    return "\(describe(Caller.current))|\(values.isEmpty ? "-" : values.joined(separator: ","))"
}

/// Bearer (ic user, oc application + delegatedUser), optionally followed by `ProxyHeaderReceiverMiddleware`.
private func makeApp(receiverKeys: [HTTPField.Name]? = nil) throws -> some ApplicationProtocol {
    let router = Router()
    router.add(middleware: BearerTokenAuthenticationMiddleware(
        verification: AccessTokenVerification(recipientKey: testRecipientKey)!,
        trust: try icOcTrust(ocActors: [mcpActor, "other-mcp"]),
        validators: [PathValidator("/public")],
        accepting: [
            .application(PathValidator("/open")),
            .delegatedUser(PathValidator("/open"), requiresScope: "quote:read"),
        ],
        serviceName: "TestService",
        logger: Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }
    ))
    if let receiverKeys {
        router.add(middleware: ProxyHeaderReceiverMiddleware(presetKeys: receiverKeys))
        router.get("open") { _, _ in
            SetHeaders.management.headers.map { "\($0.name.rawName)=\($0.value)" }.joined(separator: ";")
        }
    } else {
        router.get("open") { request, _ in echo(request) }
        router.get("public") { request, _ in echo(request) }
        router.on("open", method: .options) { request, _ in echo(request) }
    }
    return Application(router: router)
}

private let firstParty = CallerHeaders.firstPartyApplicationId
private let appSub = "ABCDEF01-0000-0000-0000-00000000000A"
private let appId = appSub.lowercased()

private func atJwtUser() -> String { ic.token(sub: "acc_1", clientId: "mendesky-first-party", subType: "user") }
private func applicationToken() -> String { oc.token(sub: appSub, scope: "notification:send") }
private func delegatedToken(clientId: String = mcpActor, actors: [String] = [mcpActor, "claude-connector"]) -> String {
    oc.token(sub: "acc_1", clientId: clientId, scope: "quote:read", subType: "user", actors: actors)
}

/// Every header given as (name, value) pairs, after `Authorization: Bearer <token>`; repeated names stay repeated.
private func rawHeaders(_ token: String, _ pairs: [(String, String)]) -> HTTPFields {
    var h = HTTPFields()
    h[.authorization] = "Bearer \(token)"
    for (name, value) in pairs { h.append(HTTPField(name: HTTPField.Name(name)!, value: value)) }
    return h
}

@Suite struct CallerHeadersTests {
    @Test func publicNames() {
        #expect(CallerHeaders.operatorId.rawName == "operatorId")
        #expect(CallerHeaders.applicationId.rawName == "applicationId")
        #expect(CallerHeaders.firstPartyApplicationId == "mendesky-first-party")
    }
}

@Suite struct BearerApplicationIdUserTests {
    /// The `.user` rule, for both a signed at+jwt and a legacy JWE.
    private func checkUser(token: String, userId: String, described: String) async throws {
        let app = try makeApp()
        try await app.test(.router) { client in
            let missing = try await client.execute(uri: "/open", method: .get, headers: headers(token, operatorId: userId))
            #expect(missing.status == .ok)
            #expect(String(buffer: missing.body) == "\(described)|\(firstParty)")

            let matching = try await client.execute(
                uri: "/open", method: .get, headers: headers(token, operatorId: userId, applicationId: firstParty))
            #expect(matching.status == .ok)
            #expect(String(buffer: matching.body) == "\(described)|\(firstParty)")

            for wrong in ["other-app", "MENDESKY-FIRST-PARTY", mcpActor, "", "mendesky-first-party-x"] {
                let res = try await client.execute(
                    uri: "/open", method: .get, headers: headers(token, operatorId: userId, applicationId: wrong))
                #expect(res.status == .badRequest, "applicationId \(wrong.debugDescription)")
            }

            // operatorId is still checked first and unchanged.
            let noOperator = try await client.execute(uri: "/open", method: .get, headers: headers(token, applicationId: firstParty))
            #expect(noOperator.status == .badRequest)
        }
    }

    @Test func signedUserApplicationIdIsOptionalAndFilledIn() async throws {
        try await checkUser(token: atJwtUser(), userId: "acc_1", described: "user:acc_1:mendesky-first-party")
    }

    @Test func jweUserApplicationIdIsOptionalAndFilledIn() async throws {
        try await checkUser(token: try jweUserToken(userId: "u1"), userId: "u1", described: "user:u1:c")
    }

    @Test func repeatedApplicationIdIsRefusedEvenWhenOneMatches() async throws {
        let app = try makeApp()
        try await app.test(.router) { client in
            let user = try await client.execute(uri: "/open", method: .get, headers: rawHeaders(atJwtUser(), [
                ("operatorId", "acc_1"), ("applicationId", firstParty), ("applicationId", firstParty)]))
            #expect(user.status == .badRequest)
            let application = try await client.execute(uri: "/open", method: .get, headers: rawHeaders(applicationToken(), [
                ("operatorId", appId), ("applicationId", appId), ("applicationId", "other")]))
            #expect(application.status == .badRequest)
        }
    }

    @Test func whitelistedPathsAndOptionsAreUntouched() async throws {
        let app = try makeApp()
        try await app.test(.router) { client in
            let open = try await client.execute(uri: "/public", method: .get)
            #expect(open.status == .ok)
            #expect(String(buffer: open.body) == "none|-")
            let foreign = try await client.execute(uri: "/public", method: .get, headers: rawHeaders("x", [("applicationId", "anything")]))
            #expect(String(buffer: foreign.body) == "none|anything")
            let preflight = try await client.execute(uri: "/open", method: .options)
            #expect(String(buffer: preflight.body) == "none|-")
        }
    }
}

@Suite struct BearerApplicationIdDelegatedUserTests {
    @Test func applicationIdMustBeTheActor() async throws {
        let app = try makeApp()
        let token = delegatedToken()
        try await app.test(.router) { client in
            let ok = try await client.execute(
                uri: "/open", method: .get, headers: headers(token, operatorId: "acc_1", applicationId: mcpActor))
            #expect(ok.status == .ok)
            #expect(String(buffer: ok.body) == "delegated:acc_1:\(mcpActor):\(mcpActor):claude-connector|\(mcpActor)")

            let missing = try await client.execute(uri: "/open", method: .get, headers: headers(token, operatorId: "acc_1"))
            #expect(missing.status == .badRequest)

            for wrong in ["claude-connector", firstParty, "Mendesky-MCP-Server", "other-mcp"] {
                let res = try await client.execute(
                    uri: "/open", method: .get, headers: headers(token, operatorId: "acc_1", applicationId: wrong))
                #expect(res.status == .badRequest, "applicationId \(wrong)")
            }

            let noOperator = try await client.execute(uri: "/open", method: .get, headers: headers(token, applicationId: mcpActor))
            #expect(noOperator.status == .badRequest)
        }
    }

    @Test func clientIdThatIsNotTheActorIsRefused() async throws {
        let app = try makeApp()
        let token = delegatedToken(clientId: "mendesky-web", actors: [mcpActor])
        try await app.test(.router) { client in
            let clientId = try await client.execute(
                uri: "/open", method: .get, headers: headers(token, operatorId: "acc_1", applicationId: "mendesky-web"))
            #expect(clientId.status == .badRequest)
            let actor = try await client.execute(
                uri: "/open", method: .get, headers: headers(token, operatorId: "acc_1", applicationId: mcpActor))
            #expect(actor.status == .ok)
        }
    }
}

@Suite struct BearerApplicationIdApplicationTests {
    @Test func bothHeadersMustBeTheApplicationId() async throws {
        let app = try makeApp()
        let token = applicationToken()
        try await app.test(.router) { client in
            let ok = try await client.execute(
                uri: "/open", method: .get, headers: headers(token, operatorId: appId, applicationId: appId))
            #expect(ok.status == .ok)
            #expect(String(buffer: ok.body) == "application:\(appId)|\(appId)")

            let refused: [(operatorId: String?, applicationId: String?)] = [
                (nil, appId),            // operatorId missing
                ("someone", appId),      // operatorId of another subject
                ("acc_1", appId),
                (appSub, appId),         // uppercase operatorId
                (appId, nil),            // applicationId missing
                (appId, appSub),         // uppercase applicationId
                (appId, "app-other"),
                (appId, firstParty),
                (nil, nil),
            ]
            for (operatorId, applicationId) in refused {
                let res = try await client.execute(
                    uri: "/open", method: .get, headers: headers(token, operatorId: operatorId, applicationId: applicationId))
                #expect(res.status == .badRequest, "operatorId \(operatorId ?? "nil") applicationId \(applicationId ?? "nil")")
            }
        }
    }

    @Test func deprecatedUserIdSatisfiesOperatorIdButNeverApplicationId() async throws {
        let app = try makeApp()
        let token = applicationToken()
        try await app.test(.router) { client in
            let ok = try await client.execute(
                uri: "/open", method: .get, headers: rawHeaders(token, [("userId", appId), ("applicationId", appId)]))
            #expect(ok.status == .ok)
            let wrongUserId = try await client.execute(
                uri: "/open", method: .get, headers: rawHeaders(token, [("userId", "someone"), ("applicationId", appId)]))
            #expect(wrongUserId.status == .badRequest)
            let userIdOnly = try await client.execute(
                uri: "/open", method: .get, headers: rawHeaders(token, [("operatorId", appId), ("userId", appId)]))
            #expect(userIdOnly.status == .badRequest)
        }
    }
}

@Suite struct ProxyHeaderApplicationIdForwardingTests {
    @Test func receiverAfterBearerCapturesTheFilledInFirstPartyApplicationId() async throws {
        let app = try makeApp(receiverKeys: [])
        try await app.test(.router) { client in
            let res = try await client.execute(uri: "/open", method: .get, headers: headers(atJwtUser(), operatorId: "acc_1"))
            #expect(res.status == .ok)
            #expect(String(buffer: res.body) == "applicationId=\(firstParty)")
        }
    }

    @Test func receiverCapturesTheCallersApplicationId() async throws {
        let app = try makeApp(receiverKeys: [])
        try await app.test(.router) { client in
            let application = try await client.execute(
                uri: "/open", method: .get, headers: headers(applicationToken(), operatorId: appId, applicationId: appId))
            #expect(String(buffer: application.body) == "applicationId=\(appId)")
            let delegated = try await client.execute(
                uri: "/open", method: .get, headers: headers(delegatedToken(), operatorId: "acc_1", applicationId: mcpActor))
            #expect(String(buffer: delegated.body) == "applicationId=\(mcpActor)")
        }
    }

    @Test func applicationIdListedInPresetKeysIsCapturedOnce() async throws {
        let app = try makeApp(receiverKeys: [CallerHeaders.operatorId, CallerHeaders.applicationId])
        try await app.test(.router) { client in
            let res = try await client.execute(
                uri: "/open", method: .get, headers: headers(applicationToken(), operatorId: appId, applicationId: appId))
            #expect(String(buffer: res.body) == "operatorId=\(appId);applicationId=\(appId)")
        }
    }
}

@Suite struct BearerRepeatedOperatorIdTests {
    /// Every caller type with the headers that are right for it besides `operatorId`.
    private func callers() throws -> [(name: String, token: String, operatorId: String, applicationId: String?)] {
        [
            ("jwe", try jweUserToken(userId: "u1"), "u1", nil),
            ("at+jwt user", atJwtUser(), "acc_1", nil),
            ("delegated", delegatedToken(), "acc_1", mcpActor),
            ("application", applicationToken(), appId, appId),
        ]
    }

    private func pairs(_ caller: (name: String, token: String, operatorId: String, applicationId: String?), _ first: [(String, String)]) -> HTTPFields {
        rawHeaders(caller.token, first + (caller.applicationId.map { [("applicationId", $0)] } ?? []))
    }

    @Test func repeatedOperatorIdIsRefusedEvenWhenOneMatches() async throws {
        let app = try makeApp()
        try await app.test(.router) { client in
            for c in try callers() {
                for second in [c.operatorId, "other"] {
                    let res = try await client.execute(
                        uri: "/open", method: .get, headers: pairs(c, [("operatorId", c.operatorId), ("operatorId", second)]))
                    #expect(res.status == .badRequest, "\(c.name) with second operatorId \(second)")
                }
            }
        }
    }

    @Test func repeatedUserIdWithoutOperatorIdIsRefused() async throws {
        let app = try makeApp()
        try await app.test(.router) { client in
            for c in try callers() {
                let res = try await client.execute(
                    uri: "/open", method: .get, headers: pairs(c, [("userId", c.operatorId), ("userId", c.operatorId)]))
                #expect(res.status == .badRequest, "\(c.name)")
            }
        }
    }

    @Test func repeatedUserIdIsIgnoredWhenOperatorIdIsPresent() async throws {
        let app = try makeApp()
        try await app.test(.router) { client in
            for c in try callers() {
                let res = try await client.execute(
                    uri: "/open", method: .get, headers: pairs(c, [("operatorId", c.operatorId), ("userId", "x"), ("userId", "y")]))
                #expect(res.status == .ok, "\(c.name)")
            }
        }
    }

    @Test func singleValuesBehaveAsBefore() async throws {
        let app = try makeApp()
        try await app.test(.router) { client in
            for c in try callers() {
                let viaOperatorId = try await client.execute(uri: "/open", method: .get, headers: pairs(c, [("operatorId", c.operatorId)]))
                #expect(viaOperatorId.status == .ok, "\(c.name)")
                let viaUserId = try await client.execute(uri: "/open", method: .get, headers: pairs(c, [("userId", c.operatorId)]))
                #expect(viaUserId.status == .ok, "\(c.name)")
                let wrong = try await client.execute(uri: "/open", method: .get, headers: pairs(c, [("operatorId", "other")]))
                #expect(wrong.status == .badRequest, "\(c.name)")
            }
        }
    }
}
