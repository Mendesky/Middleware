import Hummingbird

public protocol WhitelistValidator: Sendable {
    func isWhitelisted(_ request: Request) -> Bool
}
