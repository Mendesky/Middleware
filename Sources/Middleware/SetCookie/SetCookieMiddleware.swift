//
//  SetCookieMiddleware.swift
//  IdentityContext
//
//  Created by Grady Zhuo on 2025/11/23.
//
import Foundation
import Logging
import Hummingbird
import NIOConcurrencyHelpers
import HTTPTypes


fileprivate struct SetCookies {
    package class Management: @unchecked Sendable {
        var _cookies: NIOLockedValueBox<[Cookie]> = .init([])
        var _cookiesToRemove: NIOLockedValueBox<[String]> = .init([])
        var _headers: NIOLockedValueBox<[HTTPField]> = .init([])
        public var cookies: [Cookie] { _cookies.withLockedValue { $0 }}
        public var cookiesToRemove: [String] { _cookiesToRemove.withLockedValue { $0 }}
        public var headers: [HTTPField] { _headers.withLockedValue { $0 }}

        public func add(cookie: Cookie) {
            _cookies.withLockedValue { $0.append(cookie) }
        }
 
        public func remove(cookie name: String ) {
            _cookiesToRemove.withLockedValue { $0.append(name) }
        }
        
        public func add(header: HTTPField) {
            _headers.withLockedValue { $0.append(header) }
        }
        
    }
    
    @TaskLocal fileprivate static var _management: Management?
    
    // work-around until cookies are supported though openapi-generator
    // https://github.com/apple/swift-openapi-generator/issues/38
    /// Collects cookies and send them via the
    package static var management: Management {
        precondition(Self._management != nil, "SetCookies.management called outside request handling task, make sure SetCookieMiddleware is used!")
        return Self._management!
    }
}

/// Provides Response.setCookies and attaches all added cookies to the response header
public struct SetCookieMiddleware: MiddlewareProtocol {
    let presetKeys: [(cookie: String, header: String)]
    public init(presetKeys: [(cookie: String, header: String)]) {
        self.presetKeys = presetKeys
    }

    public func handle(_ input: Request, context: BasicRequestContext, next: (Request, BasicRequestContext) async throws -> Response) async throws -> Response {
        
        return try await SetCookies.$_management.withValue(.init()){
            for presetKey in presetKeys {
                if let cookie = input.cookies[presetKey.cookie] {
                    SetCookies.management.add(header: .init(name: .init(presetKey.header)!, value: cookie.value))
                }
            }
            
            var response = try await next(input, context)
            for cookie in SetCookies.management.cookies {
                response.headers.append(.init(name: .setCookie, value: cookie.description))
            }
            
            for cookieName in SetCookies.management.cookiesToRemove {
                response.setCookie(.init(name: cookieName, value: "", expires: .now, maxAge: 0, httpOnly: true, sameSite: .strict))
            }
            return response
        }
    }

}
