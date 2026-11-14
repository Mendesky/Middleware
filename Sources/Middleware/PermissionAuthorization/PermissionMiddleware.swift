//
//  PermissionMiddleware.swift
//  Middleware
//
//  Endpoint-level authorization. For requests matching a configured path-rule it:
//    1. takes the trusted userId from `Caller.current` (set by BearerTokenAuthenticationMiddleware
//       when it runs in front of this middleware); only when `Caller.current` is nil does it fall
//       back to self-decrypting the JWE (deprecated; removed together with JWE in a major version).
//       The fallback honours `MENDESKY_LEGACY_JWE` like Bearer does: only a 5-segment token is a legacy
//       JWE; in `reject` mode it is not decrypted (401, `legacy-jwe-rejected` log); otherwise a decrypted
//       JWE is logged as `legacy-jwe-accepted` (warning level in `warn` mode). Logs never carry the
//       token or the userId,
//    2. fetches that user's *current* permissions live via a `PermissionsProvider`
//       (e.g. an IAMContext getPermissions adapter),
//    3. AND-checks them against the rule's required permissions.
//  Allow -> next(); missing permission -> 403; missing/invalid token -> 401;
//  provider failure -> 502 (fail-closed); OPTIONS skipped.
//
//  `.user` and `.delegatedUser` callers are looked up in IAM by userId; `.application` callers have no
//  IAM user and are refused with 401.
//
//  An empty `rules` list makes this middleware a no-op. Because of the JWE fallback it still works when
//  placed before BearerTokenAuthenticationMiddleware, but signed `at+jwt` tokens only pass when Bearer
//  runs first.
//
//  Known limitation: `Context` is fixed to `BasicRequestContext` (matching
//  BearerTokenAuthenticationMiddleware). Consumers using a custom `RequestContext` are not yet
//  supported — unlike `DynamicCORSMiddleware<Context>`, this is not generic over the context.
//

import Foundation
import Hummingbird
import HTTPTypes
import Logging

public struct PermissionMiddleware: MiddlewareProtocol {
    public typealias Input = Request
    public typealias Output = Response
    public typealias Context = BasicRequestContext

    let rules: [PermissionRule]
    let provider: any PermissionsProvider
    let verification: AccessTokenVerification
    let legacyJWE: LegacyJWEMode
    let serviceName: String
    let logger: Logger

    /// - Parameters:
    ///   - legacyJWE: how the JWE fallback treats legacy tokens. This initializer uses the value passed
    ///     (default `.accept`) and ignores `MENDESKY_LEGACY_JWE`; only `init(rules:provider:)` reads it.
    ///   - serviceName: reported in the legacy JWE counter log.
    public init(
        rules: [PermissionRule],
        provider: any PermissionsProvider,
        verification: AccessTokenVerification,
        legacyJWE: LegacyJWEMode = .accept,
        serviceName: String = ProcessInfo.processInfo.processName,
        logger: Logger = Logger(label: "Middleware.PermissionMiddleware")
    ) {
        self.rules = rules
        self.provider = provider
        self.verification = verification
        self.legacyJWE = legacyJWE
        self.serviceName = serviceName
        self.logger = logger
    }

    /// Reads the legacy JWE mode from `MENDESKY_LEGACY_JWE`, then loads the token-verification keys from the
    /// standard `MENDESKY_AUTH_*` environment variables; any invalid setting throws.
    public init(rules: [PermissionRule], provider: any PermissionsProvider) throws {
        try self.init(rules: rules, provider: provider, environment: ProcessInfo.processInfo.environment)
    }

    /// `MENDESKY_LEGACY_JWE` comes from `environment`; the `MENDESKY_AUTH_*` keys from the process environment.
    init(rules: [PermissionRule], provider: any PermissionsProvider, environment: [String: String]) throws {
        let legacyJWE = try LegacyJWEMode.fromEnvironment(environment)
        self.init(rules: rules, provider: provider, verification: try .fromEnvironment(), legacyJWE: legacyJWE)
    }

    public func handle(_ input: Request, context: BasicRequestContext, next: (Request, BasicRequestContext) async throws -> Response) async throws -> Response {
        // CORS preflight carries no credentials and matches no protected handler.
        if input.method == .options {
            return try await next(input, context)
        }

        let applicable = rules.filter { $0.matches(input) }
        guard !applicable.isEmpty else {
            // No rule covers this route: nothing to enforce here.
            return try await next(input, context)
        }

        guard let userId = trustedUserId(from: input, context: context) else {
            return Response(status: .unauthorized)
        }

        let granted: Set<String>
        do {
            granted = Set(try await provider.permissions(forUserId: userId))
        } catch {
            // Fail-closed. 502 (not 503): the failure is the upstream permissions dependency, not this
            // service being unavailable — keeps it distinct from the generic 503s elsewhere in the stack.
            return Response(status: .badGateway)
        }

        // AND across every applicable rule: all must be satisfied.
        guard applicable.allSatisfy({ $0.isSatisfied(by: granted) }) else {
            return Response(status: .forbidden)
        }

        return try await next(input, context)
    }

    private func trustedUserId(from request: Request, context: BasicRequestContext) -> String? {
        switch Caller.current {
        case .user(let userId, _):
            return userId
        case .delegatedUser(let claims):
            return claims.userId
        case .application:
            // An application caller has no IAM user.
            return nil
        case nil:
            return legacyTrustedUserId(from: request, context: context)
        }
    }

    /// Deprecated fallback for when no BearerTokenAuthenticationMiddleware runs in front: decrypt the JWE
    /// ourselves, subject to `MENDESKY_LEGACY_JWE`. Removed together with JWE support in a major version.
    private func legacyTrustedUserId(from request: Request, context: BasicRequestContext) -> String? {
        guard let authorization = request.headers.first(where: { $0.name == .authorization }),
              let token = AccessTokenVerification.bearerToken(fromHeaderValue: authorization.value)
        else { return nil }
        let route = context.endpointPath ?? "unknown"
        // Only a 5-segment token is a legacy JWE; anything else fails the decrypt below as before.
        let isJWE = token.split(separator: ".", omittingEmptySubsequences: false).count == 5
        if isJWE, legacyJWE == .reject {
            logger.notice("legacy-jwe-rejected", metadata: ["route": .string(route), "service": .string(serviceName)])
            return nil
        }
        guard let payload = try? verification.decrypt(compactString: token) else { return nil }
        if isJWE {
            logger.log(level: legacyJWE == .warn ? .warning : .notice, "legacy-jwe-accepted", metadata: [
                "clientId": .string(payload.clientId), "route": .string(route), "service": .string(serviceName),
            ])
        }
        return payload.userId
    }
}
