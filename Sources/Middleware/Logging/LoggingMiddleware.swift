//
//  LoggingMiddleware.swift
//  IdentityContext
//
//  Created by Grady Zhuo on 2025/11/20.
//
import Foundation
import Logging
import Hummingbird

public struct LoggingMiddleware: MiddlewareProtocol {
    public typealias Input = Request
    public typealias Output = Response
    public typealias Context = BasicRequestContext
    
    let logger: Logger = .init(label: "IdentityContext.LoggingMiddleware")
    
    public init(){ }
    
    public func handle(_ input: HummingbirdCore.Request, context: BasicRequestContext, next: (HummingbirdCore.Request, BasicRequestContext) async throws -> HummingbirdCore.Response) async throws -> HummingbirdCore.Response {
        logger.debug(">>>: \(input.method.rawValue) \(String(describing: input.uri.path))")
        do {
            let response = try await next(input, context)
            logger.debug("<<<: \(response.status.code)")
            return response
        } catch {
            logger.error("The error happened: \(error.localizedDescription)")
            throw error
        }
    }
  }


