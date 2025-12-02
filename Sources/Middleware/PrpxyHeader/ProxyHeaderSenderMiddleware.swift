//
//  AccessTokenClient.swift
//  Middleware
//
//  Created by Grady Zhuo on 2025/12/1.
//

import Foundation
import OpenAPIRuntime
import Hummingbird

/// 加在 client 的 Middlewares
public struct ProxyHeaderSenderMiddleware: ClientMiddleware {
    
    public init(){}
    
    public func intercept(_ request: HTTPRequest, body: HTTPBody?, baseURL: URL, operationID: String, next: (HTTPRequest, HTTPBody?, URL) async throws -> (HTTPResponse, HTTPBody?)) async throws -> (HTTPResponse, HTTPBody?) {
        
        var newRequest = request
        for header in SetHeaders.management.headers{
            if !newRequest.headerFields.contains(header.name) {
                newRequest.headerFields.append(header)
            }
        }
        return try await next(newRequest, body, baseURL)
    }
}
