//
//  PermissionMiddleware.swift
//  Middleware
//
//  Endpoint-level authorization. For requests matching a configured path-rule it:
//    1. takes the trusted userId from `Caller.current`, set by BearerTokenAuthenticationMiddleware, which
//       must run in front of this middleware. When `Caller.current` is nil (no Bearer in front) the request
//       is refused with 401; since 2.0 this middleware never reads the Authorization header itself (the
//       legacy JWE self-decryption fallback is gone),
//    2. fetches that user's *current* permissions live via a `PermissionsProvider`
//       (e.g. an IAMContext getPermissions adapter),
//    3. AND-checks them against the rule's required permissions.
//  Allow -> next(); missing permission -> 403; no authenticated caller -> 401;
//  provider failure -> 502 (fail-closed); OPTIONS skipped.
//
//  `.user` and `.delegatedUser` callers are looked up in IAM by userId; `.application` callers have no
//  IAM user and are refused with 401.
//
//  An empty `rules` list makes this middleware a no-op. Placed before BearerTokenAuthenticationMiddleware
//  it fails closed: every request matching a rule gets 401.
//
//  Known limitation: `Context` is fixed to `BasicRequestContext` (matching
//  BearerTokenAuthenticationMiddleware). Consumers using a custom `RequestContext` are not yet
//  supported — unlike `DynamicCORSMiddleware<Context>`, this is not generic over the context.
//

import Foundation
import Hummingbird
import HTTPTypes

public struct PermissionMiddleware: MiddlewareProtocol {
    public typealias Input = Request
    public typealias Output = Response
    public typealias Context = BasicRequestContext

    let rules: [PermissionRule]
    let provider: any PermissionsProvider

    /// Reads nothing from the environment and never throws any more. It stays `throws` so that existing
    /// `try PermissionMiddleware(rules:provider:)` call sites compile unchanged against 2.0 without a
    /// "no calls to throwing functions occur within 'try' expression" warning (in 1.x it loaded the JWE keys
    /// from `MENDESKY_AUTH_*`).
    public init(rules: [PermissionRule], provider: any PermissionsProvider) throws {
        self.rules = rules
        self.provider = provider
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

        guard let userId = trustedUserId() else {
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

    /// The IAM user to check, from the caller BearerTokenAuthenticationMiddleware authenticated; `nil` (→ 401) when
    /// there is none or it is an application.
    private func trustedUserId() -> String? {
        switch Caller.current {
        case .user(let userId, _):
            return userId
        case .delegatedUser(let claims):
            return claims.userId
        case .application:
            // An application caller has no IAM user.
            return nil
        case nil:
            // No BearerTokenAuthenticationMiddleware in front of this middleware.
            return nil
        }
    }
}
