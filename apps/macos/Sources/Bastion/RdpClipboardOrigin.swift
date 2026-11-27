/// App-wide record of the last RDP server write to the pasteboard (SEC-6). Every RDP session watches the same
/// pasteboard, so text one session's server copied must never be offered to another session's server. A write is
/// identified by the pasteboard change count right after it; any later copy changes the count, so the tag clears
/// itself. Session ids are never reused, so a closed session's text stays foreign. Main thread only.
enum RdpClipboardOrigin {
    nonisolated(unsafe) private static var nextId = 0
    nonisolated(unsafe) private static var owner: Int?
    nonisolated(unsafe) private static var changeCount = 0

    /// A fresh id for one RDP session's clipboard sharing.
    static func newSessionId() -> Int {
        nextId += 1
        return nextId
    }

    /// Record that session `id`'s server just wrote the pasteboard, now at `changeCount`.
    static func markRemoteWrite(by id: Int, changeCount count: Int) {
        owner = id
        changeCount = count
    }

    /// False when the pasteboard at `changeCount` still holds another session's server text.
    static func mayOffer(to id: Int, changeCount count: Int) -> Bool {
        guard let owner else { return true }
        return owner == id || changeCount != count
    }

    static func resetForTests() {
        owner = nil
        changeCount = 0
    }
}
