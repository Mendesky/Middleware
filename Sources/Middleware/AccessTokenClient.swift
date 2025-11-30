//
//  AccessTokenClient.swift
//  Middleware
//
//  Created by Grady Zhuo on 2025/12/1.
//

import Foundation
import OpenAPIRuntime
import Hummingbird

public struct AccessTokenMiddleware: ClientMiddleware {
    
    public init(){}
    
    public func intercept(_ request: HTTPRequest, body: HTTPBody?, baseURL: URL, operationID: String, next: (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)) async throws -> (HTTPResponse, HTTPBody?) {
        
        guard let authorizationHeader = request.headerFields.first(where: { $0.name == .authorization }) else {
            return try await next(request, body, baseURL)
        }
        
        var newRequest = request
        newRequest.headerFields.append(authorizationHeader)
        return try await next(newRequest, body, baseURL)
    }
}
