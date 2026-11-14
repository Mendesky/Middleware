import Testing
import Foundation
@testable import Middleware
import MiddlewareTesting

private let ic = ApplicationTokenTestSigner(kid: "ic-1", issuer: "https://identity.test")
private let oc = ApplicationTokenTestSigner(kid: "oc-1", issuer: "https://oidc.test")
private let audience = "mendesky-services"

private func verification(
    now: @escaping @Sendable () -> Date = { Date() }
) throws -> SignedAccessTokenVerification {
    let trust = try AccessTokenTrust(audience: audience, issuers: [
        ic.trustedIssuer(callerTypes: [.user]),
        oc.trustedIssuer(callerTypes: [.application, .delegatedUser], actors: ["mendesky-mcp-server"]),
    ])
    return SignedAccessTokenVerification(trust: trust, now: now)
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

private func expectRejected(
    _ v: SignedAccessTokenVerification, _ token: String, sourceLocation: SourceLocation = #_sourceLocation
) {
    do {
        let identity = try v.verify(compactString: token)
        Issue.record("token was accepted as \(identity)", sourceLocation: sourceLocation)
    } catch {}
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
        expectRejected(v, "\(header).\(payload).")
        expectRejected(v, "\(header).\(payload).AAAA")
    }

    @Test func rejectsDuplicateAlgRS256FirstUnsigned() throws {
        let v = try verification()
        let header = base64URL(#"{"alg":"RS256","typ":"at+jwt","kid":"oc-1","alg":"none"}"#)
        let payload = base64URL(claimsJSON())
        expectRejected(v, "\(header).\(payload).")
        expectRejected(v, "\(header).\(payload).AAAA")
    }

    @Test func rejectsDuplicateAlgRS256FirstEvenWhenSigned() throws {
        let token = oc.rawToken(
            headerJSON: #"{"alg":"RS256","typ":"at+jwt","kid":"oc-1","alg":"none"}"#, payloadJSON: claimsJSON())
        expectRejected(try verification(), token)
    }

    @Test func rejectsDuplicateAlgNoneFirstEvenWhenSigned() throws {
        let token = oc.rawToken(
            headerJSON: #"{"alg":"none","typ":"at+jwt","kid":"oc-1","alg":"RS256"}"#, payloadJSON: claimsJSON())
        expectRejected(try verification(), token)
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
