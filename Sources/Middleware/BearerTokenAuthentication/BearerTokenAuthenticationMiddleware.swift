//
//  BearerTokenAuthenticationMiddleware.swift
//  Identity
//
//  Created by Grady Zhuo on 2025/11/20.
//
import Foundation
import Logging
import Hummingbird
import HTTPTypes

public enum BearerTokenAuthenticationMiddlewareError: Error, Equatable {
    /// Neither `MENDESKY_ACCESS_TOKEN_TRUST` nor `MENDESKY_ACCESS_TOKEN_TRUST_PATH` is set. Since 2.0 the trust
    /// configuration is required: without it no access token could be verified.
    case accessTokenTrustNotConfigured
}

extension BearerTokenAuthenticationMiddlewareError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .accessTokenTrustNotConfigured:
            "access token trust is not configured: set MENDESKY_ACCESS_TOKEN_TRUST or MENDESKY_ACCESS_TOKEN_TRUST_PATH"
        }
    }
}

/// Authenticates the bearer token and runs the handler with `Caller.current` set.
///
/// Only signed `at+jwt` tokens (3 segments) are accepted, from the issuers in the access token trust configuration
/// (`MENDESKY_ACCESS_TOKEN_TRUST` / `MENDESKY_ACCESS_TOKEN_TRUST_PATH`, or `init(trust:...)`) → `.user`, `.application`
/// or `.delegatedUser`. Legacy JWE tokens (5 segments) are no longer accepted since 2.0 and are refused with `401`, as
/// is every other shape.
///
/// A `.user` passes every route; `.application` and `.delegatedUser` only routes opened by a `RouteAcceptance`
/// (`401` otherwise, `403` when a delegated user's scope lacks the route's required scope).
///
/// Admitted callers must then assert who they are in the `CallerHeaders`, compared exactly (`400` otherwise):
/// - `operatorId` (or the deprecated `userId` when `operatorId` is absent): the token's subject for `.user` and
///   `.delegatedUser`, the application id for `.application`. A repeated `operatorId` (or, when `operatorId` is
///   absent, a repeated `userId`) is refused.
/// - `applicationId`: the actor (`act.sub`) for `.delegatedUser`, the application id for `.application`. Optional
///   for `.user`: when absent, `applicationId: mendesky-first-party` is added to the request passed on; when present
///   it must be exactly that. A repeated `applicationId` header is refused.
public struct BearerTokenAuthenticationMiddleware: MiddlewareProtocol {
    public typealias Input = Request
    public typealias Output = Response
    public typealias Context = BasicRequestContext

    /// Variables read by 1.x for legacy JWE tokens. 2.0 ignores them; the environment initializers log one warning
    /// naming those still set, so they get removed (their key material should be deleted).
    static let ignoredLegacyVariables = [
        "MENDESKY_AUTH_RECIPIENT_JWK", "MENDESKY_AUTH_RECIPIENT_JWK_PATH",
        "MENDESKY_AUTH_SENDER_JWK", "MENDESKY_AUTH_SENDER_JWK_PATH",
        "MENDESKY_AUTH_PASSWORD", "MENDESKY_LEGACY_JWE",
    ]

    let logger: Logger
    let signed: SignedAccessTokenVerification
    let accepting: [RouteAcceptance]
    let validators: [any WhitelistValidator]
    let serviceName: String

    /// from environment
    /// MENDESKY_ACCESS_TOKEN_TRUST / MENDESKY_ACCESS_TOKEN_TRUST_PATH: (required) trusted `at+jwt` issuers;
    /// first-party user tokens are accepted on every route. Application and delegated user tokens need `accepting:`.
    /// Throws `BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured` when neither is set, and
    /// `AccessTokenTrustError` when the trust is invalid (or an old `MENDESKY_APP_TOKEN_*` variable is still set).
    /// The 1.x `MENDESKY_AUTH_*` / `MENDESKY_LEGACY_JWE` variables are ignored (one warning at startup when set).
    public init(validators: [any WhitelistValidator] = []) throws {
        try self.init(environment: ProcessInfo.processInfo.environment, validators: validators, accepting: [])
    }

    /// Reads the same environment as `init(validators:)` and opens the given routes to application and delegated
    /// user tokens. Throws when the trust configuration is missing or invalid (or any old pre-rename
    /// application-token variable is still set).
    public init(validators: [any WhitelistValidator] = [], accepting: [RouteAcceptance]) throws {
        try self.init(environment: ProcessInfo.processInfo.environment, validators: validators, accepting: accepting)
    }

    /// Also accepts application tokens on the routes for which `acceptsApplication` returns true (older spelling of
    /// `accepting: [.application(where:)]`; prefer `accepting:`). Reads the same environment as `init(validators:)`.
    /// Same as `init(validators:accepting: [.application(where:)])`.
    public init(validators: [any WhitelistValidator] = [], acceptsApplication: @escaping @Sendable (Request) -> Bool) throws {
        try self.init(
            environment: ProcessInfo.processInfo.environment,
            validators: validators,
            accepting: [.application(where: acceptsApplication)]
        )
    }

    /// Reads nothing from the environment.
    /// - Parameters:
    ///   - trust: issuers whose signed `at+jwt` are accepted.
    ///   - accepting: routes open to application and delegated user tokens (users pass every route).
    ///   - serviceName: reported in the rejected-JWE log.
    public init(
        trust: AccessTokenTrust,
        validators: [any WhitelistValidator] = [],
        accepting: [RouteAcceptance] = [],
        serviceName: String = ProcessInfo.processInfo.processName,
        logger: Logger = Logger(label: "IdentityContext.BearerTokenAuthenticationMiddleware")
    ) {
        self.signed = SignedAccessTokenVerification(trust: trust)
        self.validators = validators
        self.accepting = accepting
        self.serviceName = serviceName
        self.logger = logger
    }

    /// Loads the access token trust from `environment` (missing or invalid throws), warns once about any 1.x
    /// legacy JWE variable still set, and logs the trusted issuers.
    init(
        environment: [String: String],
        validators: [any WhitelistValidator],
        accepting: [RouteAcceptance],
        logger: Logger = Logger(label: "IdentityContext.BearerTokenAuthenticationMiddleware")
    ) throws {
        guard let trust = try AccessTokenTrust.fromEnvironment(environment) else {
            throw BearerTokenAuthenticationMiddlewareError.accessTokenTrustNotConfigured
        }
        self.init(trust: trust, validators: validators, accepting: accepting, logger: logger)

        // Names only: these variables held private key material and passwords.
        let ignored = Self.ignoredLegacyVariables.filter { environment[$0] != nil }
        if !ignored.isEmpty {
            logger.warning(
                "Ignored since Middleware 2.0 (legacy JWE access tokens are no longer accepted); remove: \(ignored.joined(separator: ", "))"
            )
        }

        let issuers = trust.issuers.map { issuer in
            let callerTypes = issuer.callerTypes.map(\.rawValue).sorted()
            let kids = issuer.publicKeys.compactMap(\.keyID).sorted()
            return "issuer=\(issuer.issuer) callerTypes=\(callerTypes) actors=\(issuer.actors) kids=\(kids)"
        }
        logger.notice("Signed access tokens enabled: audience=\(trust.audience); \(issuers.joined(separator: "; "))")
    }

    private func isWhitelisted(_ request: Request) -> Bool {
        validators.contains { $0.isWhitelisted(request) }
    }

    public func handle(_ input: HummingbirdCore.Request, context: BasicRequestContext, next: (HummingbirdCore.Request, BasicRequestContext) async throws -> HummingbirdCore.Response) async throws -> HummingbirdCore.Response {
        // Skip authentication for whitelisted paths and OPTIONS (CORS preflight)
        if input.method == .options || isWhitelisted(input) {
            return try await next(input, context)
        }

        guard let authorization = input.headers.first(where: { $0.name == .authorization }) else {
            let responseBodyString = "access token loss in header."
            let responseBody = ResponseBody(contentLength: responseBodyString.count) { writer in
                try await writer.write(.init(string: responseBodyString))
                try await writer.finish(nil)
            }
            return Response.init(status: .unauthorized, body: responseBody)
        }

        guard let token = AccessTokenVerification.bearerToken(fromHeaderValue: authorization.value) else {
            return Response.init(status: .badRequest)
        }

        let identity: CallerIdentity
        switch authenticate(token, route: context.endpointPath ?? "unknown") {
        case .rejected(let response): return response
        case .authenticated(let result): identity = result
        }

        switch accepting.admission(of: identity, for: input) {
        case .admitted:
            break
        case .notOptedIn:
            if case .delegatedUser = identity {
                logger.notice("Signed access token rejected: route did not opt in to delegated user tokens")
            } else {
                logger.notice("Signed access token rejected: route did not opt in to application tokens")
            }
            return Self.unauthorized("access token rejected.")
        case .insufficientScope:
            logger.notice("Signed access token rejected: insufficient scope")
            return Self.response(.forbidden, "insufficient scope.")
        }

        // Verify the caller-asserted identity headers agree with the token, so a caller cannot name someone else.
        // `operatorId` is canonical, `userId` the deprecated alias (never for `applicationId`); when both are sent
        // they must agree. Compared by UTF-8 bytes.
        guard let operatorId = AccessTokenVerification.operatorId(fromHeaders: input.headers),
              AccessTokenVerification.bytesEqual(operatorId, Self.expectedOperatorId(of: identity)),
              let request = Self.checkingApplicationId(of: identity, in: input)
        else {
            return Response(status: .badRequest)
        }

        // Downstream runs outside the verification, so its errors never become 401.
        do {
            return try await Caller.$current.withValue(identity) {
                try await next(request, context)
            }
        } catch let error as any HTTPResponseError {
            throw error
        } catch {
            // Same as before application tokens existed: other handler errors are a 503, but the body and
            // log carry only the error type (the description may include request data).
            logger.error("Downstream handler failed: \(type(of: error))")
            return Self.response(.serviceUnavailable, "service unavailable.")
        }
    }

    private enum Authentication {
        case authenticated(CallerIdentity)
        case rejected(Response)
    }

    /// Verifies the token by its shape: 3 segments = signed `at+jwt`; 5 = a legacy JWE, refused since 2.0 without
    /// being decrypted; anything else is refused. Never logs the token (or anything derived from it); the error case
    /// is enough to diagnose.
    private func authenticate(_ token: String, route: String) -> Authentication {
        switch token.split(separator: ".", omittingEmptySubsequences: false).count {
        case 3:
            do {
                return .authenticated(try signed.verify(compactString: token))
            } catch {
                // `AccessTokenError` cases carry no token data (`missingClaim` only a claim name).
                logger.notice("Signed access token verification failed: \(error)")
                return .rejected(Self.unauthorized("access token rejected."))
            }
        case 5:
            logger.notice("Bearer token rejected: legacy JWE access tokens are no longer accepted", metadata: [
                "route": .string(route), "service": .string(serviceName),
            ])
            return .rejected(Self.unauthorized("access token rejected."))
        default:
            logger.notice("Bearer token rejected: neither a signed access token nor a JWE")
            return .rejected(Self.unauthorized("access token rejected."))
        }
    }

    /// The value the `operatorId` header must equal, verbatim.
    private static func expectedOperatorId(of identity: CallerIdentity) -> String {
        switch identity {
        case .user(let userId, _): userId
        case .delegatedUser(let claims): claims.userId
        // Service accounts will replace this with the application's bound service account.
        case .application(let claims): claims.applicationId
        }
    }

    /// The value the `applicationId` header must equal, verbatim.
    private static func expectedApplicationId(of identity: CallerIdentity) -> String {
        switch identity {
        case .user: CallerHeaders.firstPartyApplicationId
        case .delegatedUser(let claims): claims.actor
        case .application(let claims): claims.applicationId
        }
    }

    /// The request to pass on when its `applicationId` header matches the caller, `nil` when it does not. A `.user`
    /// request without one gets `applicationId: mendesky-first-party` added, so handlers and a
    /// `ProxyHeaderReceiverMiddleware` placed after this middleware see it.
    private static func checkingApplicationId(of identity: CallerIdentity, in request: Request) -> Request? {
        let asserted = request.headers[values: CallerHeaders.applicationId]
        if asserted.isEmpty, case .user = identity {
            var head = request.head
            head.headerFields.append(HTTPField(name: CallerHeaders.applicationId, value: CallerHeaders.firstPartyApplicationId))
            return Request(head: head, body: request.body)
        }
        guard asserted.count == 1,
              AccessTokenVerification.bytesEqual(asserted[0], expectedApplicationId(of: identity))
        else { return nil }
        return request
    }

    private static func unauthorized(_ message: String) -> Response {
        response(.unauthorized, message)
    }

    private static func response(_ status: HTTPResponse.Status, _ message: String) -> Response {
        let body = ResponseBody(contentLength: message.utf8.count) { writer in
            try await writer.write(.init(string: message))
            try await writer.finish(nil)
        }
        return Response(status: status, body: body)
    }
}
