import Testing
import Foundation
@testable import Middleware
import MiddlewareTesting

private let audience = "mendesky-services"

private func verification(
    now: @escaping @Sendable () -> Date = { Date() }
) throws -> SignedAccessTokenVerification {
    SignedAccessTokenVerification(trust: try icOcTrust(), now: now)
}

private func base64URL(_ string: String) -> String {
    Data(string.utf8).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

private func expectError(
    _ expected: AccessTokenError, _ v: SignedAccessTokenVerification, _ token: String,
    sourceLocation: SourceLocation = #_sourceLocation
) {
    do {
        let identity = try v.verify(compactString: token)
        Issue.record("expected \(expected), but verification returned \(identity)", sourceLocation: sourceLocation)
    } catch {
        #expect(error == expected, sourceLocation: sourceLocation)
    }
}

/// Claims an OIDCContext application token would carry, for hand-built tokens.
private func claimsJSON(exp: Int = 99999999999, extra: String = "") -> String {
    #"{"iss":"https://oidc.test","aud":["\#(audience)"],"sub":"x","sub_type":"application","client_id":"c","scope":"*","exp":\#(exp)\#(extra)}"#
}

@Suite struct SignedAccessTokenVerificationTests {
    // MARK: Caller kinds

    @Test func firstPartyUserToken() throws {
        let id = try verification().verify(
            compactString: ic.token(sub: "Acc_1", clientId: "mendesky-first-party", subType: "user"))
        #expect(id == .user(userId: "Acc_1", clientId: "mendesky-first-party"))
    }

    @Test func applicationToken() throws {
        let id = try verification().verify(
            compactString: oc.token(sub: "3F2A9C1E-7B4D-4C1A-9E2F-0A1B2C3D4E5F", scope: "* notification:send"))
        guard case .application(let c) = id else { Issue.record("not application: \(id)"); return }
        #expect(c.applicationId == "3f2a9c1e-7b4d-4c1a-9e2f-0a1b2c3d4e5f")
        #expect(c.clientId == "client-1")
        #expect(c.scope == ["*", "notification:send"])
        #expect(c.issuer == "https://oidc.test")
    }

    @Test func delegatedUserToken() throws {
        let token = oc.token(
            sub: "acc_1", clientId: "mendesky-mcp-server", scope: "quote:read", expiresIn: 300,
            subType: "user", actors: ["mendesky-mcp-server", "claude-connector"])
        let id = try verification().verify(compactString: token)
        guard case .delegatedUser(let d) = id else { Issue.record("not delegated: \(id)"); return }
        #expect(d.userId == "acc_1")
        #expect(d.clientId == "mendesky-mcp-server")
        #expect(d.actor == "mendesky-mcp-server")
        #expect(d.originClient == "claude-connector")
        #expect(d.scope == ["quote:read"])
        #expect(d.issuer == "https://oidc.test")
    }

    @Test func delegatedWithoutNestedActHasNilOriginClient() throws {
        let token = oc.token(sub: "acc_1", scope: "quote:read", subType: "user", actors: ["mendesky-mcp-server"])
        let id = try verification().verify(compactString: token)
        guard case .delegatedUser(let d) = id else { Issue.record("not delegated: \(id)"); return }
        #expect(d.actor == "mendesky-mcp-server")
        #expect(d.originClient == nil)
    }

    // MARK: Caller-type policy

    @Test func oidcUserTokenWithoutActIsRejected() throws {
        expectError(.callerTypeNotAllowed, try verification(), oc.token(sub: "acc_1", scope: "quote:read", subType: "user"))
    }

    @Test func firstPartyIssuerCannotMintOtherTypes() throws {
        let v = try verification()
        expectError(.callerTypeNotAllowed, v, ic.token(sub: "app-1", subType: "application"))
        expectError(
            .callerTypeNotAllowed, v,
            ic.token(sub: "acc_1", scope: "quote:read", subType: "user", actors: ["mendesky-mcp-server"]))
    }

    @Test func delegatedTokenWithWildcardIsRejected() throws {
        let v = try verification()
        expectError(
            .wildcardScopeInDelegatedToken, v,
            oc.token(sub: "acc_1", scope: "*", subType: "user", actors: ["mendesky-mcp-server"]))
        expectError(
            .wildcardScopeInDelegatedToken, v,
            oc.token(sub: "acc_1", scope: "quote:read *", subType: "user", actors: ["mendesky-mcp-server"]))
        expectError(
            .wildcardScopeInDelegatedToken, v,
            oc.token(sub: "acc_1", scope: "quote:*", subType: "user", actors: ["mendesky-mcp-server"]))
    }

    @Test func nullActIsMissingActSub() throws {
        let v = try verification()
        let header = #"{"alg":"RS256","typ":"at+jwt","kid":"oc-1"}"#
        let payload = #"{"iss":"https://oidc.test","aud":["\#(audience)"],"sub":"acc_1","sub_type":"user","client_id":"c","scope":"quote:read","exp":99999999999,"act":null}"#
        expectError(.missingClaim("act.sub"), v, oc.rawToken(headerJSON: header, payloadJSON: payload))
    }

    @Test func actorNotInIssuerListIsRejected() throws {
        let v = try verification()
        expectError(.actorNotAllowed, v, oc.token(sub: "acc_1", scope: "quote:read", subType: "user", actors: ["evil-mcp"]))
        expectError(
            .actorNotAllowed, v,
            oc.token(sub: "acc_1", scope: "quote:read", subType: "user", actors: ["claude-connector", "mendesky-mcp-server"]))
    }

    @Test func actOnApplicationTokenIsRejected() throws {
        expectError(
            .unexpectedActor, try verification(),
            oc.token(sub: "app-1", subType: "application", actors: ["mendesky-mcp-server"]))
    }

    @Test func subTypeIsRequiredAndKnown() throws {
        let v = try verification()
        expectError(.missingClaim("sub_type"), v, oc.token(sub: "app-1", subType: nil))
        expectError(.missingClaim("sub_type"), v, oc.token(sub: "app-1", subType: " "))
        expectError(.unsupportedSubjectType, v, oc.token(sub: "app-1", subType: "robot"))
    }

    @Test func actWithoutSubIsRejected() throws {
        let v = try verification()
        let header = #"{"alg":"RS256","typ":"at+jwt","kid":"oc-1"}"#
        func payload(act: String) -> String {
            #"{"iss":"https://oidc.test","aud":["\#(audience)"],"sub":"acc_1","sub_type":"user","client_id":"c","scope":"quote:read","exp":99999999999,"act":\#(act)}"#
        }
        expectError(.missingClaim("act.sub"), v, oc.rawToken(headerJSON: header, payloadJSON: payload(act: "{}")))
        expectError(.missingClaim("act.sub"), v, oc.rawToken(headerJSON: header, payloadJSON: payload(act: #""x""#)))
        expectError(.missingClaim("act.sub"), v, oc.rawToken(headerJSON: header, payloadJSON: payload(act: #"{"sub":" "}"#)))
    }

    // MARK: Header

    @Test func rejectsAlgNone() throws {
        let claims = base64URL(claimsJSON())
        expectError(.unsupportedAlgorithm, try verification(), "eyJhbGciOiJub25lIiwidHlwIjoiYXQrand0In0.\(claims).")
    }

    @Test func rejectsDuplicateAlgNoneFirstUnsigned() throws {
        let v = try verification()
        let header = base64URL(#"{"alg":"none","typ":"at+jwt","kid":"oc-1","alg":"RS256"}"#)
        let payload = base64URL(claimsJSON())
        expectError(.malformed, v, "\(header).\(payload).")
        expectError(.malformed, v, "\(header).\(payload).AAAA")
    }

    @Test func rejectsDuplicateAlgRS256FirstUnsigned() throws {
        let v = try verification()
        let header = base64URL(#"{"alg":"RS256","typ":"at+jwt","kid":"oc-1","alg":"none"}"#)
        let payload = base64URL(claimsJSON())
        expectError(.malformed, v, "\(header).\(payload).")
        expectError(.malformed, v, "\(header).\(payload).AAAA")
    }

    @Test func rejectsDuplicateAlgRS256FirstEvenWhenSigned() throws {
        let token = oc.rawToken(
            headerJSON: #"{"alg":"RS256","typ":"at+jwt","kid":"oc-1","alg":"none"}"#, payloadJSON: claimsJSON())
        expectError(.malformed, try verification(), token)
    }

    @Test func rejectsDuplicateAlgNoneFirstEvenWhenSigned() throws {
        let token = oc.rawToken(
            headerJSON: #"{"alg":"none","typ":"at+jwt","kid":"oc-1","alg":"RS256"}"#, payloadJSON: claimsJSON())
        expectError(.malformed, try verification(), token)
    }

    /// The header is exactly `{alg, typ, kid}`: `crit`, `jwk`, `x5u`, `b64`, ... are refused even when correctly signed.
    @Test func rejectsExtraHeaderParameters() throws {
        let v = try verification()
        let base = #""alg":"RS256","typ":"at+jwt","kid":"oc-1""#
        #expect(throws: Never.self) {
            try v.verify(compactString: oc.rawToken(headerJSON: "{\(base)}", payloadJSON: claimsJSON()))
        }
        for extra in [#""crit":["b64"],"b64":false"#, #""jwk":{"kty":"RSA","n":"AQAB","e":"AQAB"}"#, #""x5u":"https://evil.test/k""#] {
            expectError(.malformed, v, oc.rawToken(headerJSON: "{\(base),\(extra)}", payloadJSON: claimsJSON()))
        }
    }

    /// A JSON escape spells a second `alg` without a second literal `"alg"`.
    @Test func rejectsDuplicateAlgSpelledWithAnEscape() throws {
        let v = try verification()
        func signed(_ header: String) -> String { oc.rawToken(headerJSON: header, payloadJSON: claimsJSON()) }
        expectError(.malformed, v, signed(#"{"alg":"none","\u0061lg":"RS256"}"#))
        expectError(.malformed, v, signed(#"{"alg":"RS256","typ":"at+jwt","kid":"oc-1","\u0061lg":"none"}"#))
        // Any other escape is refused as well, even a harmless one.
        expectError(.malformed, v, signed(#"{"alg":"RS256","typ":"at+jw\u0074","kid":"oc-1"}"#))
        expectError(.malformed, v, signed(#"{"alg":"RS256","typ":"at+jwt","kid":"oc-1","x":"\\/"}"#))
    }

    /// Foundation writes `/` as `\/`, so `application/at+jwt` arrives escaped; that escape alone is allowed.
    @Test func acceptsEscapedSlashInType() throws {
        let token = oc.rawToken(
            headerJSON: #"{"alg":"RS256","typ":"application\/at+jwt","kid":"oc-1"}"#, payloadJSON: claimsJSON())
        let id = try verification().verify(compactString: token)
        guard case .application = id else { Issue.record("not application: \(id)"); return }
    }

    @Test func rejectsHS256() throws {
        let token = oc.rawToken(headerJSON: #"{"alg":"HS256","typ":"at+jwt","kid":"oc-1"}"#, payloadJSON: claimsJSON())
        expectError(.unsupportedAlgorithm, try verification(), token)
    }

    @Test func acceptsApplicationAtJwtTypeCaseInsensitively() throws {
        let id = try verification().verify(compactString: oc.token(sub: "app-1", typ: "Application/AT+JWT"))
        guard case .application = id else { Issue.record("not application: \(id)"); return }
    }

    @Test func rejectsIdTokenShape() throws {
        let v = try verification()
        expectError(
            .wrongType, v,
            ic.token(sub: "acc_1", clientId: nil, scope: nil, audience: ["outline-client"], typ: "JWT", subType: nil))
        expectError(
            .wrongAudience, v,
            ic.token(sub: "acc_1", clientId: nil, scope: nil, audience: ["outline-client"], typ: "at+jwt", subType: nil))
    }

    // MARK: Issuer and key selection

    @Test func unverifiedIssuerOnlySelectsTheKey() throws {
        let v = try verification()
        // oc's own kid is not one of identity.test's keys.
        expectError(.unknownKey, v, oc.token(sub: "acc_1", issuer: "https://identity.test", subType: "user"))
        // identity.test's kid selects identity.test's key, which did not sign this token.
        expectError(.badSignature, v, oc.token(sub: "acc_1", kid: "ic-1", issuer: "https://identity.test", subType: "user"))
    }

    @Test func untrustedIssuerIsRejected() throws {
        expectError(.untrustedIssuer, try verification(), oc.token(sub: "app-1", issuer: "https://other"))
    }

    @Test func rejectsMissingOrUnknownKid() throws {
        let v = try verification()
        expectError(.unknownKey, v, oc.token(sub: "app-1", kid: .some(nil)))
        expectError(.unknownKey, v, oc.token(sub: "app-1", kid: "zzz"))
    }

    @Test func rejectsAnotherKeysSignature() throws {
        let impostor = ApplicationTokenTestSigner(kid: "oc-1", issuer: "https://oidc.test")
        expectError(.badSignature, try verification(), impostor.token(sub: "app-1"))
    }

    /// Nothing but `iss` is read before the signature verifies: a forged token that is also expired, for another
    /// audience, and of an unknown subject type fails on its signature, not on any of those claims.
    @Test func signatureIsCheckedBeforeAnyOtherClaim() throws {
        let impostor = ApplicationTokenTestSigner(kid: "oc-1", issuer: "https://oidc.test")
        let forged = impostor.token(sub: "app-1", audience: ["other"], expiresIn: -3600, subType: "robot")
        expectError(.badSignature, try verification(), forged)
    }

    // MARK: Encoding

    /// An RSA-2048 signature is 256 bytes, so its last base64url character carries 4 unused bits; flipping one gives a
    /// string that lenient decoders map to the same bytes.
    @Test func rejectsNonCanonicalTrailingBits() throws {
        let v = try verification()
        let token = oc.token(sub: "app-1")
        #expect(throws: Never.self) { try v.verify(compactString: token) }
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        let lastCharacter = try #require(token.last)
        let last = try #require(alphabet.firstIndex(of: lastCharacter))
        let variant = String(token.dropLast()) + String(alphabet[last ^ 1])
        expectError(.malformed, v, variant)
    }

    @Test func rejectsStandardBase64AndPadding() throws {
        let v = try verification()
        // Find a token whose signature spells both `-` and `_`, so its standard-base64 form differs in both.
        let token = try #require((0..<50).lazy.map { _ in oc.token(sub: "app-1") }.first {
            let signature = $0.split(separator: ".")[2]
            return signature.contains("-") && signature.contains("_")
        })
        expectError(.malformed, v, token.replacingOccurrences(of: "-", with: "+"))
        expectError(.malformed, v, token.replacingOccurrences(of: "_", with: "/"))
        // 256 bytes encode to 342 characters; standard base64 pads that with `==`.
        expectError(.malformed, v, token + "==")
    }

    /// `JSONSerialization` auto-detects UTF-16/UTF-32, which would hide a duplicate `"alg"` from the UTF-8 text check.
    @Test func rejectsHeaderNotInUTF8() throws {
        let v = try verification()
        let header = #"{"alg":"RS256","typ":"at+jwt","kid":"oc-1","alg":"none"}"#
        let payload = Data(claimsJSON().utf8)
        for encoding: String.Encoding in [.utf16LittleEndian, .utf16BigEndian, .utf32LittleEndian, .utf16] {
            let headerData = try #require(header.data(using: encoding))
            expectError(.malformed, v, oc.rawToken(headerData: headerData, payloadData: payload))
        }
    }

    @Test func rejectsBOMOrWhitespaceBeforeHeader() throws {
        let v = try verification()
        let header = Data(#"{"alg":"RS256","typ":"at+jwt","kid":"oc-1"}"#.utf8)
        let payload = Data(claimsJSON().utf8)
        let plain = oc.rawToken(headerData: header, payloadData: payload)
        #expect(throws: Never.self) { try v.verify(compactString: plain) }
        expectError(.malformed, v, oc.rawToken(headerData: Data([0xEF, 0xBB, 0xBF]) + header, payloadData: payload))
        expectError(.malformed, v, oc.rawToken(headerData: Data(" ".utf8) + header, payloadData: payload))
    }

    @Test func rejectsPayloadNotInUTF8() throws {
        let v = try verification()
        let header = Data(#"{"alg":"RS256","typ":"at+jwt","kid":"oc-1"}"#.utf8)
        let utf16Payload = try #require(claimsJSON().data(using: .utf16LittleEndian))
        // Validly signed by a trusted key: only the encoding is wrong.
        expectError(.malformed, v, oc.rawToken(headerData: header, payloadData: utf16Payload))
        let bomPayload = Data([0xEF, 0xBB, 0xBF]) + Data(claimsJSON().utf8)
        expectError(.malformed, v, oc.rawToken(headerData: header, payloadData: bomPayload))
    }

    @Test func rejectsImpossibleSegmentLength() throws {
        let token = oc.token(sub: "app-1")
        let parts = token.split(separator: ".")
        // Five characters cannot be a base64url encoding (length % 4 == 1).
        expectError(.malformed, try verification(), "\(parts[0]).\(parts[1]).AAAAA")
    }

    // MARK: Claims

    @Test func expiredAtTheBoundary() throws {
        let token = oc.token(sub: "app-1")
        guard case .application(let c) = try verification().verify(compactString: token) else {
            Issue.record("not application"); return
        }
        expectError(.expired, try verification(now: { c.expiresAt }), token)
        #expect(throws: Never.self) {
            try verification(now: { c.expiresAt.addingTimeInterval(-1) }).verify(compactString: token)
        }
    }

    @Test func audienceRules() throws {
        let v = try verification()
        expectError(.wrongAudience, v, oc.token(sub: "app-1", audience: ["other"]))
        expectError(.wrongAudience, v, oc.token(sub: "app-1", audience: nil))
        #expect(throws: Never.self) { try v.verify(compactString: oc.token(sub: "app-1", audienceAsString: true)) }
    }

    @Test func requiredClaims() throws {
        let v = try verification()
        expectError(.missingClaim("sub"), v, oc.token(sub: " "))
        expectError(.missingClaim("client_id"), v, oc.token(sub: "app-1", clientId: nil))
        expectError(.missingClaim("scope"), v, oc.token(sub: "app-1", scope: nil))
        let id = try v.verify(compactString: oc.token(sub: "app-1", scope: ""))
        guard case .application(let c) = id else { Issue.record("not application: \(id)"); return }
        #expect(c.scope == [])
    }

    @Test func rejectsMissingExp() throws {
        let token = oc.rawToken(
            headerJSON: #"{"alg":"RS256","typ":"at+jwt","kid":"oc-1"}"#,
            payloadJSON: #"{"iss":"https://oidc.test","aud":"\#(audience)","sub":"x","sub_type":"application","client_id":"c","scope":"*"}"#)
        expectError(.missingClaim("exp"), try verification(), token)
    }

    @Test func fiveSegmentIsMalformed() throws {
        let v = try verification()
        expectError(.malformed, v, "a.b.c.d.e")
        expectError(.malformed, v, "a.b")
    }
}
