import Testing
import Foundation
@testable import Middleware

@Suite struct PermissionRuleTests {
    @Test func andSemanticsRequiresEveryPermission() {
        let rule = PermissionRule(PathValidator("/x"), requires: ["a", "b"])
        #expect(rule.isSatisfied(by: ["a", "b", "c"]))   // superset -> ok
        #expect(rule.isSatisfied(by: ["a", "b"]))        // exact -> ok
        #expect(!rule.isSatisfied(by: ["a"]))            // missing "b"
        #expect(!rule.isSatisfied(by: []))
    }

    @Test func emptyRequirementIsAlwaysSatisfied() {
        let rule = PermissionRule(PathValidator("/x"), requires: [])
        #expect(rule.isSatisfied(by: []))
        #expect(rule.isSatisfied(by: ["whatever"]))
    }

    @Test func matchingIsExactStringNotPrefix() {
        let rule = PermissionRule(PathValidator("/x"), requires: ["audit:read"])
        #expect(rule.isSatisfied(by: ["audit:read"]))
        #expect(!rule.isSatisfied(by: ["audit:readwrite"]))  // not a prefix match
        #expect(!rule.isSatisfied(by: ["audit"]))
    }
}

@Suite struct BearerTokenParsingTests {
    @Test func parsesWellFormedHeader() {
        #expect(AccessTokenVerification.bearerToken(fromHeaderValue: "Bearer abc.def.ghi") == "abc.def.ghi")
    }

    @Test func schemeIsCaseInsensitive() {
        #expect(AccessTokenVerification.bearerToken(fromHeaderValue: "bearer abc") == "abc")
        #expect(AccessTokenVerification.bearerToken(fromHeaderValue: "BEARER abc") == "abc")
    }

    @Test func rejectsMissingOrEmptyToken() {
        #expect(AccessTokenVerification.bearerToken(fromHeaderValue: "Bearer ") == nil)   // trailing space, empty token
        #expect(AccessTokenVerification.bearerToken(fromHeaderValue: "Bearer") == nil)    // no token
        #expect(AccessTokenVerification.bearerToken(fromHeaderValue: "") == nil)
    }

    @Test func rejectsWrongSchemeOrExtraSegments() {
        #expect(AccessTokenVerification.bearerToken(fromHeaderValue: "Basic abc") == nil)
        #expect(AccessTokenVerification.bearerToken(fromHeaderValue: "Bearer a b") == nil)  // more than one token
    }
}
