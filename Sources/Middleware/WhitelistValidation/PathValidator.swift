import Hummingbird
import RegexBuilder

public struct PathValidator: WhitelistValidator {
    private struct Matcher: @unchecked Sendable {
        let check: (String) -> Bool
        func callAsFunction(_ s: String) -> Bool { check(s) }
    }

    private let matcher: Matcher

    public init(_ path: String) {
        let regex = Regex<Substring>(verbatim: path)
        matcher = Matcher { (try? regex.wholeMatch(in: $0)) != nil }
    }

    public init<Output>(_ regex: Regex<Output>) {
        matcher = Matcher { (try? regex.wholeMatch(in: $0)) != nil }
    }

    public func isWhitelisted(_ request: Request) -> Bool {
        matcher(request.uri.path)
    }
}
