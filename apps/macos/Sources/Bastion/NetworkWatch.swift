import Foundation
import Network

/// Watches the default network path and calls `onChange` (on the main actor) when it changes
/// after the first report: interface switch, VPN up or down, or the link coming back.
@MainActor
final class NetworkWatch {
    var onChange: () -> Void = {}
    private(set) var changes = 0
    private let monitor = NWPathMonitor()
    private var last: String?

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            let key = Self.key(path)
            Task { @MainActor in self?.handle(key) }
        }
        monitor.start(queue: DispatchQueue(label: "bastion.network-watch", qos: .utility))
    }

    /// Feeds a path key; also used by the UI driver to simulate a change.
    func handle(_ key: String) {
        defer { last = key }
        guard let last, last != key else { return }
        changes += 1
        onChange()
    }

    nonisolated private static func key(_ path: NWPath) -> String {
        let ifaces = path.availableInterfaces.map(\.name).joined(separator: ",")
        return "\(path.status)|\(ifaces)"
    }

    deinit { monitor.cancel() }
}
