//
//  AccessTokenVerification.swift
//  Middleware
//
//  Created by Grady Zhuo on 2025/11/20.
//
import Foundation
import HTTPTypes

/// Bearer-header parsing helpers used by the Bearer middleware (and public for services that read these headers).
///
/// Until 2.0 this type also decrypted legacy JWE user tokens; that support is gone (signed `at+jwt` tokens are
/// verified by `SignedAccessTokenVerification`), and only these static helpers remain.
public enum AccessTokenVerification {
    /// Extracts the compact token from an `Authorization: Bearer <token>` header value, or `nil`
    /// if it is not well-formed. The auth-scheme is matched case-insensitively (RFC 7235), the value
    /// must be exactly `<scheme> <token>` (one token, no extra segments), and an empty/missing token
    /// yields `nil`.
    public static func bearerToken(fromHeaderValue value: String) -> String? {
        let parts = value.split(separator: " ", omittingEmptySubsequences: true)
        guard parts.count == 2, parts[0].lowercased() == "bearer" else { return nil }
        return String(parts[1])
    }

    /// Extracts the caller-asserted operator identity from request headers, used by the auth
    /// middleware to confirm the bearer is the same subject the token was issued for.
    ///
    /// `operatorId` is the canonical header; `userId` is its deprecated predecessor, which handlers may still read
    /// as the operator. So both are checked: either header repeated (two or more fields) yields `nil`, whether or
    /// not the other is present; when both are present they must be byte-identical (UTF-8, not canonical
    /// equivalence), otherwise `nil`; when only one is present, that is the operator. `nil` also means neither
    /// header is set. A `nil` matches no subject, so the auth middleware answers `400`.
    public static func operatorId(fromHeaders headers: HTTPFields) -> String? {
        let operatorIds = headers[values: CallerHeaders.operatorId]
        let userIds = HTTPField.Name("userId").map { headers[values: $0] } ?? []
        guard operatorIds.count <= 1, userIds.count <= 1 else { return nil }
        switch (operatorIds.first, userIds.first) {
        case (let operatorId?, let userId?): return bytesEqual(operatorId, userId) ? operatorId : nil
        case (let operatorId?, nil): return operatorId
        case (nil, let userId?): return userId
        case (nil, nil): return nil
        }
    }

    /// Identifier equality by UTF-8 bytes. `String ==` treats canonically equivalent text (NFC and NFD forms of the
    /// same characters) as equal; identifiers here must match the issuer's exactly.
    static func bytesEqual(_ a: String, _ b: String) -> Bool {
        Array(a.utf8) == Array(b.utf8)
    }
}
