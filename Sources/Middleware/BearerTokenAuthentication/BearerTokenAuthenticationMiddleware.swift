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

public struct BearerTokenAuthenticationMiddleware: MiddlewareProtocol {
    public typealias Input = Request
    public typealias Output = Response
    public typealias Context = BasicRequestContext

    let logger: Logger
    let verification: AccessTokenVerification
    let applicationTokens: ApplicationTokenVerification?
    let acceptsApplication: @Sendable (Request) -> Bool
    let validators: [any WhitelistValidator]

    private static let defaultLogger = Logger(label: "IdentityContext.BearerTokenAuthenticationMiddleware")

    /// from environment
    /// MENDESKY_AUTH_RECIPIENT_JWK: The base64 json encoded string from JWK for recipient.
    /// MENDESKY_AUTH_RECIPIENT_JWK_PATH: The file path of JWK JSON context  for recipient.
    /// MENDESKY_AUTH_SENDER_JWK: (optional) The base64 json encoded string from JWK for sender.
    /// MENDESKY_AUTH_SENDER_JWK_PATH: (optional) The file path of JWK JSON context  for sender.
    /// MENDESKY_AUTH_PASSWORD: (optional) JWK password for AUTH if needed.
    public init(validators: [any WhitelistValidator] = []) throws {
        // Single source of truth for the MENDESKY_AUTH_* key loading.
        self.verification = try AccessTokenVerification.fromEnvironment()
        self.applicationTokens = nil
        self.acceptsApplication = { _ in false }
        self.validators = validators
        self.logger = Self.defaultLogger
    }

    public init(verification: AccessTokenVerification, validators: [any WhitelistValidator] = []) {
        self.verification = verification
        self.applicationTokens = nil
        self.acceptsApplication = { _ in false }
        self.validators = validators
        self.logger = Self.defaultLogger
    }

    /// Also accepts application tokens (OIDCContext `at+jwt`) on the routes for which `acceptsApplication` returns true.
    /// Application keys come from `MENDESKY_APP_TOKEN_JWKS` / `_JWKS_PATH`; when unset, application tokens are always rejected.
    public init(validators: [any WhitelistValidator] = [], acceptsApplication: @escaping @Sendable (Request) -> Bool) throws {
        self.verification = try AccessTokenVerification.fromEnvironment()
        self.applicationTokens = try ApplicationTokenVerification.fromEnvironment()
        self.acceptsApplication = acceptsApplication
        self.validators = validators
        self.logger = Self.defaultLogger
    }

    public init(
        verification: AccessTokenVerification,
        applicationTokens: ApplicationTokenVerification?,
        validators: [any WhitelistValidator] = [],
        acceptsApplication: @escaping @Sendable (Request) -> Bool,
        logger: Logger = Logger(label: "IdentityContext.BearerTokenAuthenticationMiddleware")
    ) {
        self.verification = verification
        self.applicationTokens = applicationTokens
        self.acceptsApplication = acceptsApplication
        self.validators = validators
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

        let identity: CallerIdentity
        do {
            if token.split(separator: ".", omittingEmptySubsequences: false).count == 3 {
                // Application token: only on opted-in routes, only when keys are configured.
                guard let applicationTokens, acceptsApplication(input) else {
                    return Self.unauthorized("application token rejected.")
                }
                identity = .application(try applicationTokens.verify(compactString: token))
            } else {
                guard let payload = try self.verification.decrypt(compactString: token) else {
                    return Self.unauthorized("access token decrypt failed.")
                }

                // Verify the caller-asserted operator identity matches the token payload to prevent
                // token theft. `operatorId` is canonical; `userId` is the deprecated fallback. Both
                // are compared against `payload.userId` (the token payload field is unchanged).
                guard let assertedOperatorId = AccessTokenVerification.operatorId(fromHeaders: input.headers) else {
                    return Response.init(status: .badRequest)
                }

                guard assertedOperatorId == payload.userId else {
                    return Response(status: .badRequest)
                }
                identity = .user(userId: payload.userId, clientId: payload.clientId)
            }
        } catch {
            // Never log the token (or anything derived from it); the error type is enough to diagnose.
            logger.error("Bearer token verification failed: \(type(of: error))")
            return Self.unauthorized("access token rejected.")
        }

        // Downstream runs outside the do/catch so handler errors propagate unchanged.
        return try await Caller.$current.withValue(identity) {
            try await next(input, context)
        }
    }

    private static func unauthorized(_ message: String) -> Response {
        let body = ResponseBody(contentLength: message.utf8.count) { writer in
            try await writer.write(.init(string: message))
            try await writer.finish(nil)
        }
        return Response(status: .unauthorized, body: body)
    }
}
