/// Who is making the current request, as established by the authentication middleware.
public enum CallerIdentity: Sendable, Equatable {
    case user(userId: String, clientId: String)
    case application(ApplicationTokenClaims)
}

public enum Caller {
    /// Unset inside a streaming `ResponseBody` writer, which runs after the handler has returned.
    /// Set by `BearerTokenAuthenticationMiddleware` around the downstream handler; `nil` outside an authenticated request.
    @TaskLocal public static var current: CallerIdentity?
}
