import HTTPTypes

/// Request headers in which a caller asserts who it is; `BearerTokenAuthenticationMiddleware` checks them against
/// the verified token (`400` on a mismatch), so a handler that reads them reads the same caller as `Caller.current`.
public enum CallerHeaders {
    /// The user (or, for an application, the application) the request acts as. The deprecated `userId` header is
    /// still read when `operatorId` is absent.
    public static let operatorId = HTTPField.Name("operatorId")!
    /// The application making the request.
    public static let applicationId = HTTPField.Name("applicationId")!
    /// The `applicationId` of Mendesky's own (first-party) clients: optional on `.user` requests, which get it filled in.
    public static let firstPartyApplicationId = "mendesky-first-party"
}
