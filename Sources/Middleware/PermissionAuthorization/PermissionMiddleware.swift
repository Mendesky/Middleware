//
//  PermissionMiddleware.swift
//  Middleware
//
//  Endpoint-level authorization. For requests matching a configured path-rule it:
//    1. self-decrypts the bearer token to obtain a trusted userId,
//    2. fetches that user's *current* permissions live via a `PermissionsProvider`
//       (e.g. an IAMContext getPermissions adapter),
//    3. AND-checks them against the rule's required permissions.
//  Allow -> next(); missing permission -> 403; missing/invalid token -> 401;
//  provider failure -> 502 (fail-closed); OPTIONS skipped.
//
//  An empty `rules` list makes this middleware a no-op. It self-decrypts (does not rely on
//  BearerTokenAuthenticationMiddleware), so it is independent of middleware ordering.
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
    let verification: AccessTokenVerification

    public init(rules: [PermissionRule], provider: any PermissionsProvider, verification: AccessTokenVerification) {
        self.rules = rules
        self.provider = provider
        self.verification = verification
    }

    /// Loads the token-verification keys from the standard `MENDESKY_AUTH_*` environment variables.
    public init(rules: [PermissionRule], provider: any PermissionsProvider) throws {
        self.init(rules: rules, provider: provider, verification: try .fromEnvironment())
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

        // Obtain a trusted userId by decrypting the bearer token ourselves.
        guard let userId = trustedUserId(from: input) else {
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

    private func trustedUserId(from request: Request) -> String? {
        guard let authorization = request.headers.first(where: { $0.name == .authorization }),
              let token = AccessTokenVerification.bearerToken(fromHeaderValue: authorization.value),
              let payload = try? verification.decrypt(compactString: token) else {
            return nil
        }
        return payload.userId
    }
}
