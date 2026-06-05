//
//  PermissionRule.swift
//  Middleware
//
//  Declares the permissions a set of routes requires. Reuses the existing `PathValidator`
//  (a `Request -> Bool` path predicate) for path matching and adds an optional HTTP-method
//  filter, since RBAC usually differs by verb.
//

import Hummingbird
import HTTPTypes

public struct PermissionRule: Sendable {
    let pathMatcher: any WhitelistValidator
    /// `nil` means the rule applies to any method.
    let methods: Set<HTTPRequest.Method>?
    let requiredPermissions: [String]

    /// - Parameters:
    ///   - pathMatcher: a path predicate. Note `PathValidator(_: String)` matches the path
    ///     *literally* (`Regex(verbatim:)`); for patterns use the regex initializer, e.g.
    ///     `PathValidator(try Regex("/quotations/.+"))` or the `@RegexComponentBuilder` form.
    ///   - methods: HTTP methods this rule covers; `nil` = any method.
    ///   - requiredPermissions: permissions the token must hold (exact match, AND semantics).
    public init(_ pathMatcher: any WhitelistValidator,
                methods: Set<HTTPRequest.Method>? = nil,
                requires requiredPermissions: [String]) {
        self.pathMatcher = pathMatcher
        self.methods = methods
        self.requiredPermissions = requiredPermissions
    }

    /// Whether this rule applies to the given request (method filter, then path predicate).
    func matches(_ request: Request) -> Bool {
        if let methods, !methods.contains(request.method) { return false }
        return pathMatcher.isWhitelisted(request)
    }

    /// AND semantics: every required permission must be present in `granted` (exact match).
    func isSatisfied(by granted: Set<String>) -> Bool {
        requiredPermissions.allSatisfy(granted.contains)
    }
}
