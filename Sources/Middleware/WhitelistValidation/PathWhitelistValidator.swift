import Hummingbird

public struct PathWhitelistValidator: WhitelistValidator {
    private let exactPaths: Set<String>
    private let patterns: [@Sendable (String) -> Bool]

    public init(
        exactPaths: Set<String> = [],
        patterns: [@Sendable (String) -> Bool] = []
    ) {
        self.exactPaths = exactPaths
        self.patterns = patterns
    }

    public func isWhitelisted(_ request: Request) -> Bool {
        let path = request.uri.path
        if exactPaths.contains(path) { return true }
        return patterns.contains { $0(path) }
    }
}
