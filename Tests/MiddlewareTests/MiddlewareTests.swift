import Testing
import Foundation
import HTTPTypes
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

@Suite struct OperatorIdHeaderTests {
    private func headers(_ pairs: [(String, String)]) -> HTTPFields {
        var fields = HTTPFields()
        for (name, value) in pairs {
            fields.append(HTTPField(name: HTTPField.Name(name)!, value: value))
        }
        return fields
    }

    @Test func prefersOperatorIdWhenPresent() {
        let h = headers([("operatorId", "op-1"), ("userId", "user-1")])
        #expect(AccessTokenVerification.operatorId(fromHeaders: h) == "op-1")
    }

    @Test func fallsBackToUserIdWhenOperatorIdMissing() {
        let h = headers([("userId", "user-1")])
        #expect(AccessTokenVerification.operatorId(fromHeaders: h) == "user-1")
    }

    @Test func operatorIdWinsEvenWhenUserIdDiffers() {
        // operatorId is authoritative; a conflicting (deprecated) userId is ignored.
        let h = headers([("operatorId", "op-1"), ("userId", "other")])
        #expect(AccessTokenVerification.operatorId(fromHeaders: h) == "op-1")
    }

    @Test func returnsNilWhenNeitherPresent() {
        #expect(AccessTokenVerification.operatorId(fromHeaders: headers([])) == nil)
    }
}
