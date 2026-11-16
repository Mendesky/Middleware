import Hummingbird
import RegexBuilder

/// Matches the request path against a literal, a `Regex` or a `RegexComponentBuilder` pattern.
///
/// The path is normalized the way Hummingbird's router splits it before matching: empty segments are
/// dropped and the rest rejoined as `/` + segments joined by `/` (empty becomes `/`). So `/a/b/`,
/// `//a/b` and `/a//b` are matched exactly like `/a/b`, the same path the router routes them to.
/// Nothing else is normalized: `.`/`..` segments and percent-encoding are left as they are, because
/// the router leaves them as they are too.
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

    public init<Output>(@RegexComponentBuilder _ build: () -> some RegexComponent<Output>) {
        let component = build()
        matcher = Matcher { (try? component.regex.wholeMatch(in: $0)) != nil }
    }

    public func isWhitelisted(_ request: Request) -> Bool {
        matcher(Self.normalized(request.uri.path))
    }

    /// Mirrors `Trie.ResolveContext.pathComponents` in Hummingbird (`split(separator: "/", omittingEmptySubsequences: true)`).
    static func normalized(_ path: String) -> String {
        "/" + path.split(separator: "/", omittingEmptySubsequences: true).joined(separator: "/")
    }
}
