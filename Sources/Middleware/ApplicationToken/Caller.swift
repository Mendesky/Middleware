import Foundation

/// A user's token minted for an actor (e.g. an MCP server) acting on that user's behalf (RFC 8693 `act`).
public struct DelegatedUserClaims: Sendable, Equatable {
    /// The token's `sub`, verbatim.
    public let userId: String
    public let clientId: String
    /// `act.sub`: the client acting for the user.
    public let actor: String
    /// `act.act.sub`, when present: the client the actor was itself called by.
    public let originClient: String?
    public let scope: [String]
    public let issuer: String
    public let expiresAt: Date

    public init(
        userId: String, clientId: String, actor: String, originClient: String?, scope: [String], issuer: String,
        expiresAt: Date
    ) {
        self.userId = userId
        self.clientId = clientId
        self.actor = actor
        self.originClient = originClient
        self.scope = scope
        self.issuer = issuer
        self.expiresAt = expiresAt
    }
}

/// Who is making the current request, as established by the authentication middleware.
public enum CallerIdentity: Sendable, Equatable {
    case user(userId: String, clientId: String)
    case application(ApplicationTokenClaims)
    case delegatedUser(DelegatedUserClaims)
}

public enum Caller {
    /// Unset inside a streaming `ResponseBody` writer, which runs after the handler has returned.
    /// Set by `BearerTokenAuthenticationMiddleware` around the downstream handler; `nil` outside an authenticated request.
    @TaskLocal public static var current: CallerIdentity?
}
