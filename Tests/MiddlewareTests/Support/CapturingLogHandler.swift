import Foundation
import Logging

/// Collects every log line as `"<level> <message> <metadata> <handler metadata>"`, so tests can assert on what was
/// (and was not) logged, including the level.
struct CapturingLogHandler: LogHandler {
    final class Store: @unchecked Sendable {
        private let lock = NSLock()
        private var lines: [String] = []
        func add(_ s: String) { lock.lock(); lines.append(s); lock.unlock() }
        var all: String { lock.lock(); defer { lock.unlock() }; return lines.joined(separator: "\n") }
    }

    let store: Store
    var metadata: Logger.Metadata = [:]
    var logLevel: Logger.Level = .trace

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(
        level: Logger.Level, message: Logger.Message, metadata: Logger.Metadata?, source: String, file: String,
        function: String, line: UInt
    ) {
        store.add("\(level) \(message) \(metadata ?? [:]) \(self.metadata)")
    }

    /// A logger that writes into a fresh store, and that store.
    static func logger() -> (Logger, Store) {
        let store = Store()
        return (Logger(label: "capture") { _ in CapturingLogHandler(store: store) }, store)
    }
}
