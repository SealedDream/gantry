import SwiftUI
import BastionCore

/// One row of the core's recent-sessions list (`Library.recentSessionsJson`, spec §2).
struct RecentSession: Decodable, Identifiable, Equatable {
    let connection: String
    let name: String
    let host: String
    let port: UInt16?
    let user: String?
    let `protocol`: String
    let lastConnectedAt: Int64?
    let lastError: String?
    var id: String { connection }

    var address: String { sessionAddress(user: user, host: host, port: port) }

    static func decode(_ json: String) throws -> [RecentSession] {
        try JSONDecoder().decode([RecentSession].self, from: Data(json.utf8))
    }
}

/// Start page shown when no tab is open (spec §2): the usual empty state on top, Recent sessions
/// below. Double-click or Enter opens one; right-click offers Remove from Recents.
struct StartPage: View {
    static let recentLimit: UInt32 = 20
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    @Environment(AppRouter.self) private var router
    @State private var recents: [RecentSession] = []
    @State private var loadError: String?

    var body: some View {
        VStack(spacing: 0) {
            EmptyState(symbol: "terminal", title: "No active sessions", message: "Open a saved connection or use Quick Connect.") {
                HStack(spacing: DS.Space.xs) {
                    StartQuickConnectButton()
                    Button("New Local Shell") { sessions.openLocal() }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            recentList.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .task(id: sessions.historyRevision) { reload() }
        // Only when set: an equal write still invalidates every view that reads it (the inspector's
        // demand), and the page disappears on every first tab.
        .onDisappear { if sessions.startPick != nil { sessions.startPick = nil } }
        .onChange(of: commands.model.library != nil) { reload() }
        // The UI driver's `recent open|remove <name>` acts on a row by name.
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.recentAction)) { note in
            guard let parts = note.object as? [String], parts.count == 2,
                  let r = recents.first(where: { $0.name == parts[1] }) else { return }
            switch parts[0] {
            case "open": open(r.id)
            case "pick": sessions.startPick = r.id
            default: remove(r.id)
            }
        }
    }

    private var recentList: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            Text("Recent Sessions").font(DS.Font.bodyStrong).padding(.horizontal, DS.Space.m).padding(.top, DS.Space.s)
            if let loadError {
                Text(loadError).foregroundStyle(.secondary).padding(.horizontal, DS.Space.m)
                Spacer()
            } else if recents.isEmpty {
                Text("Sessions you open appear here.").foregroundStyle(.secondary).padding(.horizontal, DS.Space.m)
                Spacer()
            } else {
                // Single-click picks a row and the inspector shows for it; the empty state above
                // re-centres in the narrower area (owner feedback 8).
                List(recents, selection: Binding(get: { sessions.startPick }, set: { sessions.startPick = $0 })) { r in
                    RecentRow(recent: r).tag(r.id)
                }
                .accessibilityIdentifier("recent-sessions")
                .contextMenu(forSelectionType: String.self) { ids in
                    Button("Remove from Recents") { ids.forEach(remove) }
                } primaryAction: { ids in
                    // Double-click and Enter.
                    ids.forEach(open)
                }
            }
        }
    }

    private func reload() {
        guard let lib = commands.model.library else { return }
        do {
            recents = try RecentSession.decode(lib.recentSessionsJson(dataDir: LibraryModel.stateDir, limit: Self.recentLimit))
            loadError = nil
        } catch {
            loadError = "Recent sessions could not be read: \(error.userMessage)"
        }
        DriverEvents.recentNames = recents.map(\.name)
    }

    private func open(_ id: String) {
        guard let c = commands.model.connection(id: id) else { return }
        commands.requestConnect(c, Commands.mode(for: c))
    }

    private func remove(_ id: String) {
        do {
            try forgetConnectionHistory(dataDir: LibraryModel.stateDir, connectionId: id)
            sessions.historyRevision += 1
        } catch {
            loadError = "Could not remove it from Recents: \(error.userMessage)"
        }
    }
}

private struct RecentRow: View {
    let recent: RecentSession

    private var when: String {
        guard let at = recent.lastConnectedAt else { return "Never" }
        return Date(timeIntervalSince1970: TimeInterval(at)).formatted(.relative(presentation: .named))
    }

    var body: some View {
        HStack(spacing: DS.Space.xs) {
            Image(systemName: protocolSymbol(recent.protocol)).frame(width: 18)
            VStack(alignment: .leading, spacing: 0) {
                Text(recent.name)
                Text(recent.address).font(DS.Font.caption.monospaced()).foregroundStyle(.secondary)
            }
            Spacer()
            if let err = recent.lastError {
                Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange).help(err)
            }
            Text(when).font(DS.Font.caption).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}

/// The start page's Quick Connect, Return's default only while nothing covers the page: under a window
/// panel or the New Connection form, Return opened Quick Connect behind it instead of pressing their
/// own default button. Its own view, so a panel opening re-renders this button only.
private struct StartQuickConnectButton: View {
    @Environment(Commands.self) private var commands
    @Environment(AppRouter.self) private var router

    var body: some View {
        let covered = commands.panel != nil || commands.addConnection != nil
        Button("Quick Connect…") { router.open("quick-connect") }
            .keyboardShortcut(covered ? nil : .defaultAction)
            .dsPrimaryButton()
    }
}
