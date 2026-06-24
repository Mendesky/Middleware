//
//  AccessToken.swift
//  IdentityContext
//
//  Created by Grady Zhuo on 2025/11/20.
//
import Foundation
import Hummingbird
import HTTPTypes
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

    /// Extracts the compact token from an `Authorization: Bearer <token>` header value, or `nil`
    /// if it is not well-formed. The auth-scheme is matched case-insensitively (RFC 7235), the value
    /// must be exactly `<scheme> <token>` (one token, no extra segments), and an empty/missing token
    /// yields `nil`. Shared by the auth and permission middleware so parsing lives in one place.
    public static func bearerToken(fromHeaderValue value: String) -> String? {
        let parts = value.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count == 2, parts[0].lowercased() == "bearer" else { return nil }
        return String(parts[1])
    }

    /// Extracts the caller-asserted operator identity from request headers, used by the auth
    /// middleware to confirm the bearer is the same subject the token was issued for.
    ///
    /// `operatorId` is the canonical header; `userId` is the deprecated predecessor and is only
    /// consulted when `operatorId` is absent. When `operatorId` is present it wins outright —
    /// a conflicting `userId` is ignored, not rejected. Returns `nil` when neither header is set.
    public static func operatorId(fromHeaders headers: HTTPFields) -> String? {
        if let key = HTTPField.Name("operatorId"), let value = headers.first(where: { $0.name == key })?.value {
            return value
        }
        if let key = HTTPField.Name("userId"), let value = headers.first(where: { $0.name == key })?.value {
            return value
        }
        return nil
    }
}
