//
//  AccessToken.swift
//  IdentityContext
//
//  Created by Grady Zhuo on 2025/11/20.
//
import Foundation
import Hummingbird
import JSONWebEncryption
import JSONWebKey
import Logging

public struct AccessTokenPayload: Codable {
    package let authorizationId: String
    package let userId: String
    package let clientId: String
    package let scope: [String]
    package let expiresAt: Date
}


public struct AccessTokenVerification: Sendable {
    let logger: Logger = .init(label: "Identity.AccessTokenVerification")
    let recipientKey: JWK
    let senderKey: JWK?
    let password: Data?
    
    public init?(senderKey: JWK? = nil, recipientKey: JWK, password: Data? = nil){
        self.recipientKey = recipientKey
        self.senderKey = senderKey
        self.password = password
    }
    
    public init(senderKey senderKeyData: Data? = nil, recipientKey recipientKeyData: Data, password: Data? = nil) throws {
        
        self.senderKey = try senderKeyData.map{
            try JSONDecoder().decode(JWK.self, from: $0)
        }
        self.recipientKey = try JSONDecoder().decode(JWK.self, from: recipientKeyData)
        self.password = password
    }
    
    public init(senderKeyJSONString: String? = nil, recipientKeyJSONString: String, password: Data? = nil) throws {
        
        let senderKey = senderKeyJSONString.map{
            Data($0.utf8)
        }
        let recipientKey = Data(recipientKeyJSONString.utf8)
        try self.init(senderKey: senderKey, recipientKey: recipientKey, password: password)
    }
    
    public func decrypt(compactString: String) throws -> AccessTokenPayload? {
        let jwe = try JWE(compactString: compactString)
        let payloadData = try jwe.decrypt(senderKey: senderKey, recipientKey: recipientKey, password: password)
        let decoder = JSONDecoder()
        let payload = try decoder.decode(AccessTokenPayload.self, from: payloadData)

        guard Date() < payload.expiresAt else {
            return nil
        }
        return payload
    }
}

extension AccessTokenVerification {
    /// Builds a verification from the standard `MENDESKY_AUTH_*` environment variables — the same
    /// keys `BearerTokenAuthenticationMiddleware` reads. Lets `PermissionMiddleware` self-decrypt
    /// using the same configuration.
    public static func fromEnvironment() throws -> AccessTokenVerification {
        let env = Environment()

        let recipientKeyData = try env.get("MENDESKY_AUTH_RECIPIENT_JWK_PATH").map { try Data(contentsOf: URL(filePath: $0)) }
            ?? env.get("MENDESKY_AUTH_RECIPIENT_JWK").flatMap { Data(base64Encoded: .init($0.utf8)) }

        guard let recipientKeyData else {
            throw BearerTokenAuthenticationMiddlewareError.recipientKeyNotFoundInEnvironment
        }

        let senderKeyData = try env.get("MENDESKY_AUTH_SENDER_JWK_PATH").map { try Data(contentsOf: URL(filePath: $0)) }
            ?? env.get("MENDESKY_AUTH_SENDER_JWK").flatMap { Data(base64Encoded: .init($0.utf8)) }

        let password = env.get("MENDESKY_AUTH_PASSWORD").flatMap { Data(base64Encoded: .init($0.utf8)) }

        return try AccessTokenVerification(senderKey: senderKeyData, recipientKey: recipientKeyData, password: password)
    }
}
