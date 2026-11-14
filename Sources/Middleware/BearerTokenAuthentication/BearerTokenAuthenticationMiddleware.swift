//
//  BearerTokenAuthenticationMiddleware.swift
//  Identity
//
//  Created by Grady Zhuo on 2025/11/20.
//
import Foundation
import Logging
import Hummingbird
import JSONWebKey
import JSONWebEncryption
import HTTPTypes
public enum BearerTokenAuthenticationMiddlewareError: Error {
    case  recipientKeyNotFoundInEnvironment
}

/// Authenticates the bearer token and runs the handler with `Caller.current` set.
///
/// - 5-segment tokens are legacy JWE user tokens (`MENDESKY_AUTH_*` keys) → `.user`.
/// - 3-segment tokens are signed `at+jwt` from the issuers in the access token trust configuration
///   (`MENDESKY_ACCESS_TOKEN_TRUST` / `MENDESKY_ACCESS_TOKEN_TRUST_PATH`) → `.user`, `.application` or
///   `.delegatedUser`; without a trust configuration they are refused with `401`.
///
/// A `.user` passes every route; `.application` and `.delegatedUser` only routes opened by a `RouteAcceptance`
/// (`401` otherwise, `403` when a delegated user's scope lacks the route's required scope). `.user` and
/// `.delegatedUser` callers must send an `operatorId` header equal to the token's subject (`400` otherwise).
public struct BearerTokenAuthenticationMiddleware: MiddlewareProtocol {
    public typealias Input = Request
    public typealias Output = Response
    public typealias Context = BasicRequestContext

    let logger: Logger
    let verification: AccessTokenVerification
    /// `nil` when no trust is configured: every 3-segment token is refused.
    let signed: SignedAccessTokenVerification?
    let legacyJWE: LegacyJWEMode
    let accepting: [RouteAcceptance]
    let validators: [any WhitelistValidator]
    let serviceName: String

    /// from environment
    /// MENDESKY_AUTH_RECIPIENT_JWK: The base64 json encoded string from JWK for recipient.
    /// MENDESKY_AUTH_RECIPIENT_JWK_PATH: The file path of JWK JSON context  for recipient.
    /// MENDESKY_AUTH_SENDER_JWK: (optional) The base64 json encoded string from JWK for sender.
    /// MENDESKY_AUTH_SENDER_JWK_PATH: (optional) The file path of JWK JSON context  for sender.
    /// MENDESKY_AUTH_PASSWORD: (optional) JWK password for AUTH if needed.
    /// MENDESKY_ACCESS_TOKEN_TRUST / MENDESKY_ACCESS_TOKEN_TRUST_PATH: (optional) trusted `at+jwt` issuers; when set,
    /// first-party user tokens are accepted on every route. Application and delegated user tokens need `accepting:`.
    public init(validators: [any WhitelistValidator] = []) throws {
        try self.init(environment: ProcessInfo.processInfo.environment, validators: validators, accepting: [])
    }

    /// Reads the same environment as `init(validators:)` and opens the given routes to application and delegated
    /// user tokens. Throws when the trust configuration is invalid (or any old pre-rename application-token variable is still set).
    public init(validators: [any WhitelistValidator] = [], accepting: [RouteAcceptance]) throws {
        try self.init(environment: ProcessInfo.processInfo.environment, validators: validators, accepting: accepting)
    }

    /// JWE user tokens only: no signed access tokens are trusted.
    public init(verification: AccessTokenVerification, validators: [any WhitelistValidator] = []) {
        self.init(verification: verification, trust: nil, validators: validators)
    }

    /// Also accepts application tokens on the routes for which `acceptsApplication` returns true (older spelling of
    /// `accepting: [.application(where:)]`; prefer `accepting:`).
    /// Trusted issuers come from `MENDESKY_ACCESS_TOKEN_TRUST` / `MENDESKY_ACCESS_TOKEN_TRUST_PATH`; when neither is
    /// set, every signed (3-segment) token is rejected. Same as `init(validators:accepting: [.application(where:)])`.
    public init(validators: [any WhitelistValidator] = [], acceptsApplication: @escaping @Sendable (Request) -> Bool) throws {
        try self.init(
            environment: ProcessInfo.processInfo.environment,
            validators: validators,
            accepting: [.application(where: acceptsApplication)]
        )
    }

    /// Accepts application tokens from the single issuer of `applicationTokens` on the routes for which
    /// `acceptsApplication` returns true; `nil` rejects every signed (3-segment) token.
    public init(
        verification: AccessTokenVerification,
        applicationTokens: ApplicationTokenVerification?,
        validators: [any WhitelistValidator] = [],
        acceptsApplication: @escaping @Sendable (Request) -> Bool,
        logger: Logger = Logger(label: "IdentityContext.BearerTokenAuthenticationMiddleware")
    ) {
        self.init(
            verification: verification,
            signed: applicationTokens?.signed,
            legacyJWE: .accept,
            validators: validators,
            accepting: [.application(where: acceptsApplication)],
            serviceName: ProcessInfo.processInfo.processName,
            logger: logger
        )
    }

    /// - Parameters:
    ///   - trust: issuers whose signed `at+jwt` are accepted; `nil` rejects every signed (3-segment) token.
    ///   - accepting: routes open to application and delegated user tokens (users pass every route).
    ///   - serviceName: reported in the legacy JWE counter log.
    public init(
        verification: AccessTokenVerification,
        trust: AccessTokenTrust?,
        legacyJWE: LegacyJWEMode = .accept,
        validators: [any WhitelistValidator] = [],
        accepting: [RouteAcceptance] = [],
        serviceName: String = ProcessInfo.processInfo.processName,
        logger: Logger = Logger(label: "IdentityContext.BearerTokenAuthenticationMiddleware")
    ) {
        self.init(
            verification: verification,
            signed: trust.map { SignedAccessTokenVerification(trust: $0) },
            legacyJWE: legacyJWE,
            validators: validators,
            accepting: accepting,
            serviceName: serviceName,
            logger: logger
        )
    }

    /// Loads, in order, the access token trust and the legacy JWE mode from `environment`, then the
    /// `MENDESKY_AUTH_*` JWE keys (from the process environment); any invalid setting throws.
    init(environment: [String: String], validators: [any WhitelistValidator], accepting: [RouteAcceptance]) throws {
        let trust = try AccessTokenTrust.fromEnvironment(environment)
        let legacyJWE = try LegacyJWEMode.fromEnvironment(environment)
        let verification = try AccessTokenVerification.fromEnvironment()
        self.init(verification: verification, trust: trust, legacyJWE: legacyJWE, validators: validators, accepting: accepting)
        logger.notice("Legacy JWE mode: \(legacyJWE.rawValue)")

        if let trust {
            let issuers = trust.issuers.map { issuer in
                let callerTypes = issuer.callerTypes.map(\.rawValue).sorted()
                let kids = issuer.publicKeys.compactMap(\.keyID).sorted()
                return "issuer=\(issuer.issuer) callerTypes=\(callerTypes) actors=\(issuer.actors) kids=\(kids)"
            }
            logger.notice("Signed access tokens enabled: audience=\(trust.audience); \(issuers.joined(separator: "; "))")
        } else {
            logger.notice("Signed access tokens disabled: MENDESKY_ACCESS_TOKEN_TRUST / MENDESKY_ACCESS_TOKEN_TRUST_PATH not set")
        }
    }

    private init(
        verification: AccessTokenVerification,
        signed: SignedAccessTokenVerification?,
        legacyJWE: LegacyJWEMode,
        validators: [any WhitelistValidator],
        accepting: [RouteAcceptance],
        serviceName: String,
        logger: Logger
    ) {
        self.verification = verification
        self.signed = signed
        self.legacyJWE = legacyJWE
        self.validators = validators
        self.accepting = accepting
        self.serviceName = serviceName
        self.logger = logger
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

        let authenticated: Authenticated
        let route = context.endpointPath ?? "unknown"
        switch authenticate(token, route: route) {
        case .rejected(let response): return response
        case .authenticated(let result): authenticated = result
        }
        let identity = authenticated.identity

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

        // Verify the caller-asserted operator identity matches the token subject to prevent token theft.
        // `operatorId` is canonical; `userId` is the deprecated fallback. Application callers have no operator.
        if let subject = Self.operatorSubject(of: identity) {
            guard let assertedOperatorId = AccessTokenVerification.operatorId(fromHeaders: input.headers),
                  assertedOperatorId == subject
            else {
                return Response(status: .badRequest)
            }
        }

        // Counted only here: decrypted, admitted and operator-checked. Never carries the token or the userId.
        if authenticated.viaLegacyJWE, case .user(_, let clientId) = identity {
            logger.log(level: legacyJWE == .warn ? .warning : .notice, "legacy-jwe-accepted", metadata: [
                "clientId": .string(clientId), "route": .string(route), "service": .string(serviceName),
            ])
        }

        // Downstream runs outside the verification, so its errors never become 401.
        do {
            return try await Caller.$current.withValue(identity) {
                try await next(input, context)
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

    /// A verified caller, and whether it came from a legacy JWE token (as opposed to a signed `at+jwt`).
    private struct Authenticated {
        let identity: CallerIdentity
        let viaLegacyJWE: Bool
    }

    private enum Authentication {
        case authenticated(Authenticated)
        case rejected(Response)
    }

    /// Verifies the token by its shape: 3 segments = signed `at+jwt`, 5 = legacy JWE, anything else is refused.
    /// Never logs the token (or anything derived from it); the error case or type is enough to diagnose.
    private func authenticate(_ token: String, route: String) -> Authentication {
        switch token.split(separator: ".", omittingEmptySubsequences: false).count {
        case 3:
            guard let signed else {
                logger.notice("Signed access token rejected: access token trust is not configured")
                return .rejected(Self.unauthorized("access token rejected."))
            }
            do {
                return .authenticated(Authenticated(identity: try signed.verify(compactString: token), viaLegacyJWE: false))
            } catch {
                // `AccessTokenError` cases carry no token data (`missingClaim` only a claim name).
                logger.notice("Signed access token verification failed: \(error)")
                return .rejected(Self.unauthorized("access token rejected."))
            }
        case 5:
            // Retired: never decrypt, so a refused JWE costs nothing.
            if legacyJWE == .reject {
                logger.notice("legacy-jwe-rejected", metadata: [
                    "route": .string(route), "service": .string(serviceName),
                ])
                return .rejected(Self.unauthorized("access token rejected."))
            }
            do {
                guard let payload = try verification.decrypt(compactString: token) else {
                    return .rejected(Self.unauthorized("access token decrypt failed."))
                }
                let identity = CallerIdentity.user(userId: payload.userId, clientId: payload.clientId)
                return .authenticated(Authenticated(identity: identity, viaLegacyJWE: true))
            } catch {
                logger.notice("Bearer token verification failed: \(type(of: error))")
                return .rejected(Self.unauthorized("access token rejected."))
            }
        default:
            logger.notice("Bearer token rejected: neither a signed access token nor a JWE")
            return .rejected(Self.unauthorized("access token rejected."))
        }
    }

    /// The subject the `operatorId` header must equal, verbatim; `nil` for callers without an operator.
    private static func operatorSubject(of identity: CallerIdentity) -> String? {
        switch identity {
        case .user(let userId, _): userId
        case .delegatedUser(let claims): claims.userId
        case .application: nil
        }
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
