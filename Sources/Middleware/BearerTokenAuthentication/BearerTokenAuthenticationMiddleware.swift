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

    let logger: Logger = .init(label: "IdentityContext.BearerTokenAuthenticationMiddleware")
    let verification: AccessTokenVerification
    let validators: [any WhitelistValidator]

    /// from environment
    /// MENDESKY_AUTH_RECIPIENT_JWK: The base64 json encoded string from JWK for recipient.
    /// MENDESKY_AUTH_RECIPIENT_JWK_PATH: The file path of JWK JSON context  for recipient.
    /// MENDESKY_AUTH_SENDER_JWK: (optional) The base64 json encoded string from JWK for sender.
    /// MENDESKY_AUTH_SENDER_JWK_PATH: (optional) The file path of JWK JSON context  for sender.
    /// MENDESKY_AUTH_PASSWORD: (optional) JWK password for AUTH if needed.
    public init(validators: [any WhitelistValidator] = []) throws {
        // Single source of truth for the MENDESKY_AUTH_* key loading.
        self.verification = try AccessTokenVerification.fromEnvironment()
        self.validators = validators
    }

    public init(verification: AccessTokenVerification, validators: [any WhitelistValidator] = []) {
        self.verification = verification
        self.validators = validators
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

        do {
            guard let payload = try self.verification.decrypt(compactString: token) else {
                let responseBodyString = "access token decrypt failed."
                let responseBody = ResponseBody(contentLength: responseBodyString.count) { writer in
                    try await writer.write(.init(string: responseBodyString))
                    try await writer.finish(nil)
                }
                return Response.init(status: .unauthorized, body: responseBody)
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

            return try await next(input, context)

        } catch let error as JWE.JWEError {
            let responseBodyString = "JWEError: \(error)"
            logger.error(.init(stringLiteral: responseBodyString), metadata: ["accesstoken": .string(token)])
            let responseBody = ResponseBody(contentLength: responseBodyString.count) { writer in
                try await writer.write(.init(string: responseBodyString))
                try await writer.finish(nil)
            }
            return Response.init(status: .unauthorized, body: responseBody)
        } catch {
            logger.error("The error happened when verified accessToken: \(error)", metadata: ["accesstoken": .string(token)])
            return Response.init(status: .serviceUnavailable, body: .init(byteBuffer: .init(string: "unknown error: \(error)")))
        }
    }
  }
