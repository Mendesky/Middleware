//
//  DynamicCORSMiddleware.swift
//  Middleware
//
//  Created by Grady Zhuo on 2025/11/27.
//

import Hummingbird
import HTTPTypes

struct DynamicCORSMiddleware<Context: RequestContext>: RouterMiddleware {
    let allowedOrigins: Set<String>
    let allowedMethods: Set<HTTPRequest.Method>
    let allowedHeaders: Set<String>
    let allowCredentials: Bool
    let maxAge: Int?

    init(
        allowedOrigins: Set<String>,
        allowedMethods: Set<HTTPRequest.Method> = [.get, .post, .put, .delete, .options],
        allowedHeaders: Set<String> = ["content-type", "authorization"],
        allowCredentials: Bool = true,
        maxAge: Int? = 3600
    ) {
        self.allowedOrigins = allowedOrigins
        self.allowedMethods = allowedMethods
        self.allowedHeaders = allowedHeaders
        self.allowCredentials = allowCredentials
        self.maxAge = maxAge
    }

    func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        // 取得請求的 Origin
        let requestOrigin = request.headers[.origin]
        
        // 檢查是否在允許清單中
        let allowedOrigin: String? = if let origin = requestOrigin,
                                        allowedOrigins.contains(origin) {
            origin
        } else {
            nil
        }

        // 處理 preflight OPTIONS 請求
        if request.method == .options {
            var response = Response(status: .noContent)
            if let origin = allowedOrigin {
                response.headers[.accessControlAllowOrigin] = origin
                response.headers[.accessControlAllowMethods] = allowedMethods
                    .map(\.rawValue)
                    .joined(separator: ", ")
                response.headers[.accessControlAllowHeaders] = allowedHeaders.joined(separator: ", ")
                if allowCredentials {
                    response.headers[.accessControlAllowCredentials] = "true"
                }
                if let maxAge {
                    response.headers[.accessControlMaxAge] = String(maxAge)
                }
            }
            return response
        }

        // 處理一般請求
        var response = try await next(request, context)
        
        if let origin = allowedOrigin {
            response.headers[.accessControlAllowOrigin] = origin
            if allowCredentials {
                response.headers[.accessControlAllowCredentials] = "true"
            }
        }

        return response
    }
}
