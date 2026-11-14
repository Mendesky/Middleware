import Foundation
import Hummingbird
import HTTPTypes

/// Opens routes to callers other than users. `BearerTokenAuthenticationMiddleware` accepts a `.user` on every route;
/// an `.application` or `.delegatedUser` caller only where a `RouteAcceptance` for that kind matches the request.
public struct RouteAcceptance: Sendable {
    enum Kind: Sendable, Equatable {
        case application
        /// `actors == nil` accepts every actor the issuer allows.
        case delegatedUser(requiresScope: String, actors: Set<String>?)
    }

    let kind: Kind
    private let predicate: @Sendable (Request) -> Bool

    private init(kind: Kind, matches predicate: @escaping @Sendable (Request) -> Bool) {
        self.kind = kind
        self.predicate = predicate
    }

    /// Accepts application tokens on requests whose path matches `path` (and whose method is in `methods`;
    /// `nil` = any method). `PathValidator(_: String)` matches literally; use its regex initializer for patterns.
    public static func application(
        _ path: any WhitelistValidator, methods: Set<HTTPRequest.Method>? = nil
    ) -> RouteAcceptance {
        RouteAcceptance(kind: .application, matches: Self.matcher(path, methods))
    }

    /// Accepts application tokens on requests for which `predicate` returns true.
    public static func application(where predicate: @escaping @Sendable (Request) -> Bool) -> RouteAcceptance {
        RouteAcceptance(kind: .application, matches: predicate)
    }

    /// Accepts delegated user tokens (a user's token held by an actor, e.g. an MCP server) on requests whose path
    /// matches `path` and whose method is in `methods` (`nil` = any method), when the token's scope contains
    /// `requiresScope` exactly (no wildcard) and, if `actors` is given, its actor is one of them.
    /// `actors: nil` accepts every actor the issuer is trusted for.
    public static func delegatedUser(
        _ path: any WhitelistValidator,
        methods: Set<HTTPRequest.Method>? = nil,
        requiresScope: String,
        actors: Set<String>? = nil
    ) -> RouteAcceptance {
        precondition(
            !requiresScope.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && requiresScope != "*",
            "RouteAcceptance.delegatedUser needs a concrete requiresScope (not blank, not \"*\")"
        )
        return RouteAcceptance(
            kind: .delegatedUser(requiresScope: requiresScope, actors: actors), matches: Self.matcher(path, methods))
    }

    private static func matcher(
        _ path: any WhitelistValidator, _ methods: Set<HTTPRequest.Method>?
    ) -> @Sendable (Request) -> Bool {
        { request in
            if let methods, !methods.contains(request.method) { return false }
            return path.isWhitelisted(request)
        }
    }

    func matches(_ request: Request) -> Bool { predicate(request) }
}

/// Whether a route admits a verified caller.
enum RouteAdmission: Equatable {
    case admitted
    /// No acceptance opens this route to the caller's kind (or, for a delegated user, to its actor): `401`.
    case notOptedIn
    /// A delegated user whose route and actor are accepted, but whose scope lacks every required scope: `403`.
    case insufficientScope
}

extension [RouteAcceptance] {
    func admission(of identity: CallerIdentity, for request: Request) -> RouteAdmission {
        switch identity {
        case .user:
            return .admitted
        case .application:
            let opted = contains { $0.kind == .application && $0.matches(request) }
            return opted ? .admitted : .notOptedIn
        case .delegatedUser(let claims):
            let requiredScopes: [String] = compactMap { acceptance in
                guard case .delegatedUser(let requiresScope, let actors) = acceptance.kind,
                      actors?.contains(claims.actor) ?? true,
                      acceptance.matches(request)
                else { return nil }
                return requiresScope
            }
            guard !requiredScopes.isEmpty else { return .notOptedIn }
            let granted = Set(claims.scope)
            return requiredScopes.contains(where: granted.contains) ? .admitted : .insufficientScope
        }
    }
}
