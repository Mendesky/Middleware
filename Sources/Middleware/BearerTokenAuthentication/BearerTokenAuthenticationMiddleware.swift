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
    
    /// from environment
    /// MENDESKY_AUTH_RECIPIENT_JWK: The base64 json encoded string from JWK for recipient.
    /// MENDESKY_AUTH_RECIPIENT_JWK_PATH: The file path of JWK JSON context  for recipient.
    /// MENDESKY_AUTH_SENDER_JWK: (optional) The base64 json encoded string from JWK for sender.
    /// MENDESKY_AUTH_SENDER_JWK_PATH: (optional) The file path of JWK JSON context  for sender.
    /// MENDESKY_AUTH_PASSWORD: (optional) JWK password for AUTH if needed.
    public init() throws {
        let env = Environment()
        
        let recipientKeyData = try env.get("MENDESKY_AUTH_RECIPIENT_JWK_PATH").map{ try Data(contentsOf: URL(filePath: $0)) } ?? env.get("MENDESKY_AUTH_RECIPIENT_JWK").flatMap{ Data(base64Encoded: .init($0.utf8)) }
        
        guard let recipientKeyData else {
            throw BearerTokenAuthenticationMiddlewareError.recipientKeyNotFoundInEnvironment
        }
        
        let senderKeyData = try env.get("MENDESKY_AUTH_SENDER_JWK_PATH").map{
            try Data(contentsOf: URL(filePath: $0))
        } ?? env.get("MENDESKY_AUTH_SENDER_JWK").flatMap{ Data(base64Encoded: .init($0.utf8)) }
        
        let password = env.get("MENDESKY_AUTH_PASSWORD").flatMap{ Data(base64Encoded: .init($0.utf8)) }
        self.verification = try AccessTokenVerification(senderKey: senderKeyData, recipientKey: recipientKeyData, password: password)
    }
    
    public init(verification: AccessTokenVerification){
        self.verification = verification
    }
    
    public func handle(_ input: HummingbirdCore.Request, context: BasicRequestContext, next: (HummingbirdCore.Request, BasicRequestContext) async throws -> HummingbirdCore.Response) async throws -> HummingbirdCore.Response {
        guard let authorization = input.headers.first(where: { $0.name == .authorization }) else {
            let responseBodyString = "access token loss in header."
            let responseBody = ResponseBody(contentLength: responseBodyString.count) { writer in
                try await writer.write(.init(string: responseBodyString))
                try await writer.finish(nil)
            }
            return Response.init(status: .unauthorized, body: responseBody)
        }
        
        guard authorization.value.hasPrefix("Bearer "),
            let token = authorization.value.split(separator: " ").last.map({ String($0) }) else {
            return Response.init(status: .badRequest)
        }
        
        do{
            guard let payload = try self.verification.decrypt(compactString: token) else{
                let responseBodyString = "access token decrypt failed."
                let responseBody = ResponseBody(contentLength: responseBodyString.count) { writer in
                    try await writer.write(.init(string: responseBodyString))
                    try await writer.finish(nil)
                }
                return Response.init(status: .unauthorized, body: responseBody)
            }
            guard let fieldKey = HTTPField.Name.init("userId"), let userId = input.headers.first(where: { $0.name == fieldKey}) else {
                return Response.init(status: .badRequest)
            }
            
            guard userId.value == payload.userId else {
                return Response(status: .badRequest)
            }
            
            return try await next(input, context)
            
        }catch let error as JWE.JWEError{
            let responseBodyString = "JWEError: \(error)"
            logger.error(.init(stringLiteral: responseBodyString), metadata: ["accesstoken": .string(token)])
            let responseBody = ResponseBody(contentLength: responseBodyString.count) { writer in
                try await writer.write(.init(string: responseBodyString))
                try await writer.finish(nil)
            }
            return Response.init(status: .unauthorized, body: responseBody)
        }catch{
            logger.error("The error happened when verified accessToken: \(error)", metadata: ["accesstoken": .string(token)])
            return Response.init(status: .serviceUnavailable, body: .init(byteBuffer: .init(string: "unknown error: \(error)")))
        }
    }
  }

