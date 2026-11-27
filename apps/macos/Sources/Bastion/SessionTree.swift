import AppKit

/// Open sessions as rows in the library tree (UI-05, `docs/design/SESSION-TREE.md`): one row per
/// tab under the connection it was opened from, the rest under Other sessions. UI-only: rows are
/// built from the tab list and never saved to the library file.
struct SessionRow: Equatable {
    enum State: Equatable {
        case connected, connecting, ended, notStarted

        var label: String {
            switch self {
            case .connected: "connected"
            case .connecting: "connecting"
            case .ended: "failed"
            case .notStarted: "not started"
            }
        }

        /// Core theme token for the dot (`theme.rs`).
        var token: String {
            switch self {
            case .connected: "status.connected"
            case .connecting: "status.connecting"
            case .ended: "status.failed"
            case .notStarted: "text.secondary"
            }
        }
    }

    let tabId: UUID
    let title: String
    let state: State
    /// Library connection the tab came from; nil for a local shell, quick connect, or one whose
    /// connection is gone (then it shows under Other sessions).
    let connectionId: String?

    static let rowPrefix = "session:"
    var rowId: String { Self.rowPrefix + tabId.uuidString }

    func matches(_ filter: String) -> Bool { filter.isEmpty || title.localizedCaseInsensitiveContains(filter) }
}

/// Session rows by connection, plus the Other sessions list. Equatable, so the tree compares the
/// whole set in one step and terminal output (which changes no row) never reaches it.
struct SessionRows: Equatable {
    var byConnection: [String: [SessionRow]] = [:]
    var other: [SessionRow] = []

    var isEmpty: Bool { byConnection.isEmpty && other.isEmpty }
    func rows(for connectionId: String) -> [SessionRow] { byConnection[connectionId] ?? [] }
}

extension SessionsModel {
    /// The tree's rows, in tab-strip order. Tabs of a locked protected document are left out, so
    /// no title leaks; `exists` says whether the library still has the connection.
    func sessionRows(exists: (String) -> Bool) -> SessionRows {
        var rows = SessionRows()
        var known: [String: Bool] = [:]
        for tab in tabs where !isDocumentLocked(tab) {
            let linked = tab.connectionId.flatMap { id -> String? in
                if known[id] == nil { known[id] = exists(id) }
                return known[id]! ? id : nil
            }
            // The name only: the row's dot shows the link state, no "(Reconnecting…)" text (owner 2026-11-17).
            // The name only: the row's dot shows the link state, no "(Reconnecting…)" text (owner 2026-11-17).
            let row = SessionRow(tabId: tab.id, title: tab.shownName, state: Self.rowState(tab), connectionId: linked)
            if let linked { rows.byConnection[linked, default: []].append(row) } else { rows.other.append(row) }
        }
        return rows
    }

    private static func rowState(_ tab: TerminalTab) -> SessionRow.State {
        if tab.ended { return .ended }
        if tab.isWaiting { return .notStarted }
        if tab.panes.contains(where: { $0.linkStatus != nil }) { return .connecting }
        return .connected
    }

    /// A session row was clicked or activated: select its tab and bring its window forward.
    /// Never opens a new session.
    func focus(tabId: UUID) {
        guard let tab = tabs.first(where: { $0.id == tabId }) else { return }
        if let window = windowed[tab.id] {
            windowSelected[window] = tab.id
            focusTabWindow?(window)
        } else {
            reveal(tab)
            NSApp.mainWindow?.makeKeyAndOrderFront(nil)
        }
    }

    /// ⌘W or Close Tab on a session row: the tab's usual close (with its question).
    func close(tabId: UUID) {
        guard let tab = tabs.first(where: { $0.id == tabId }) else { return }
        requestClose(tab)
    }
}
