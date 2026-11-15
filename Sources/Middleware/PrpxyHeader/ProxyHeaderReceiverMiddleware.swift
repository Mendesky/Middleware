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

public struct SetHeaders {
    public class Management: @unchecked Sendable {
        var _headers: NIOLockedValueBox<[HTTPField]> = .init([])
        public var headers: [HTTPField] { _headers.withLockedValue { $0 }}
        
        public func add(header: HTTPField) {
            _headers.withLockedValue { $0.append(header) }
        }
        
    }
    
    @TaskLocal fileprivate static var _management: Management?
    
    // work-around until cookies are supported though openapi-generator
    // https://github.com/apple/swift-openapi-generator/issues/38
    /// Collects cookies and send them via the
    public static var management: Management {
        precondition(Self._management != nil, "SetCookies.management called outside request handling task, make sure SetCookieMiddleware is used!")
        return Self._management!
    }
}

/// 加在自己的 Router Middlewares
public struct ProxyHeaderReceiverMiddleware: MiddlewareProtocol {
    let presetKeys: [HTTPField.Name]

    /// Captures the inbound headers named in `presetKeys`, and always `applicationId` (`CallerHeaders.applicationId`;
    /// listing it too does not capture it twice). `.application` and `.delegatedUser` callers send `applicationId`
    /// themselves; for a `.user` request the `mendesky-first-party` value that `BearerTokenAuthenticationMiddleware`
    /// fills in is captured only when this middleware runs after it (a downstream fills it in again when it is missing).
    public init(presetKeys: [HTTPField.Name]) {
        self.presetKeys = presetKeys.contains(CallerHeaders.applicationId) ? presetKeys : presetKeys + [CallerHeaders.applicationId]
    }

    public func handle(_ input: Request, context: BasicRequestContext, next: (Request, BasicRequestContext) async throws -> Response) async throws -> Response {
        
        return try await SetHeaders.$_management.withValue(.init()){
            
            for key in presetKeys {
                if let headerField = input.headers.first(where: { $0.name == key }){
                    SetHeaders.management.add(header: headerField)
                }
            }
            return try await next(input, context)
            
        }
    }

}
