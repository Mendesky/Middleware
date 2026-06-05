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
