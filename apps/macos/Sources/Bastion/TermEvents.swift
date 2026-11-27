import AppKit
import SwiftUI
import UserNotifications
import BastionCore

/// TERM-MARKS (core `shellmarks`, as on Native Windows #1262): what a terminal reports besides its
/// screen. The core parses, cleans and rate-limits; this polls once a second while a terminal is
/// open and shows it: the unread dot on a background tab, a notice when a long command (10 s or
/// more, OSC 133 marks) ends in a background tab, program notifications (OSC 9 / 777, setting
/// `terminal.program-notifications`), and "Save as Connection" for an `ssh` line typed in an
/// unsaved local tab (the core tracks typed lines only for local programs).
@MainActor
final class TermEventsRuntime {
    static let shared = TermEventsRuntime()
    static let pollInterval: TimeInterval = 1

    /// Set by `SessionsModel` when it is made.
    weak var sessions: SessionsModel?
    /// `terminal.program-notifications`, kept current by the terminal views (which read settings).
    var programNotifications = true
    private var timer: Timer?

    /// Called for every new pane: make sure the poll runs.
    func start() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { _ in
            MainActor.assumeIsolated { TermEventsRuntime.shared.poll() }
        }
    }

    func poll() {
        guard let sessions, !sessions.tabs.isEmpty else { timer?.invalidate(); timer = nil; return }
        for tab in sessions.tabs {
            for pane in tab.panes where !pane.ended {
                handle(pane.terminal.takeEvents(), tab: tab, pane: pane, sessions: sessions)
            }
        }
    }

    private func handle(_ ev: TerminalEventsView, tab: TerminalTab, pane: TerminalPane, sessions: SessionsModel) {
        // A tab torn off into its own window is on screen: never "background".
        let background = sessions.selected != tab.id && sessions.windowed[tab.id] == nil
        if ev.activity && background && !tab.unread { tab.unread = true }
        if ev.finished && background {
            let text = Self.finishedTitle(exitCode: ev.finishedExitCode, durationMs: ev.finishedDurationMs)
            tab.notice = text
            DesktopNotice.post(title: text, body: tab.shownName)
        }
        if let body = ev.notificationBody, let title = ev.notificationTitle, programNotifications {
            let note = TabTitle.programNotice(source: tab.name, title: title, body: body)
            DesktopNotice.post(title: note.title, body: note.body)
        }
        if let host = ev.typedSshHost, tab.connectionId == nil {
            pane.sshOffer = TypedSshTarget(host: host, user: ev.typedSshUser, port: ev.typedSshPort)
        }
    }

    /// "Command finished (2 min)" or "Command failed, exit 2 (40 s)".
    static func finishedTitle(exitCode: Int32?, durationMs: UInt64) -> String {
        let secs = durationMs / 1000
        let took = secs >= 120 ? "\(secs / 60) min" : "\(secs) s"
        if let code = exitCode, code != 0 { return "Command failed, exit \(code) (\(took))" }
        return "Command finished (\(took))"
    }
}

/// `ssh [user@]host[:port]` typed in a local shell. Never holds a password.
struct TypedSshTarget: Equatable {
    let host: String
    let user: String?
    let port: UInt16?

    var text: String {
        (user.map { $0 + "@" } ?? "") + host + (port.flatMap { $0 == 22 ? nil : ":\($0)" } ?? "")
    }
}

/// A desktop notification (Notification Centre); without an app bundle (`swift run`) the Dock
/// bounces instead. Shared by triggers and program notifications.
@MainActor
enum DesktopNotice {
    private static var askedPermission = false

    static func post(title: String, body: String) {
        guard Bundle.main.bundleIdentifier != nil else { NSApp.requestUserAttention(.informationalRequest); return }
        let center = UNUserNotificationCenter.current()
        if !askedPermission {
            askedPermission = true
            center.requestAuthorization(options: [.alert, .sound]) { _, error in
                if let error { NSLog("Gantry notifications refused: %@", error.localizedDescription) }
            }
        }
        let content = UNMutableNotificationContent()
        content.title = title
        content.body = body
        center.add(UNNotificationRequest(identifier: UUID().uuidString, content: content, trigger: nil)) { error in
            if let error { NSLog("Gantry notification: %@", error.localizedDescription) }
        }
        if !NSApp.isActive { NSApp.requestUserAttention(.informationalRequest) }
    }
}

/// "ssh user@host:port · Save as Connection" above a local pane: one click saves host, user and port
/// to the library root (no password). Dismiss or Save removes it; a newer ssh line replaces it.
struct TypedSshBar: View {
    let pane: TerminalPane
    @Environment(LibraryModel.self) private var model

    var body: some View {
        if let target = pane.sshOffer {
            HStack(spacing: DS.Space.s) {
                Image(systemName: "network").foregroundStyle(.secondary)
                Text("ssh " + target.text).font(DS.Font.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                Spacer()
                Button("Dismiss") { pane.sshOffer = nil }
                Button("Save as Connection") { Self.save(target, pane: pane, model: model) }.dsPrimaryButton()
            }
            .controlSize(.small)
            .padding(.horizontal, DS.Space.s).padding(.vertical, DS.Space.xs)
            .background(.bar)
            .overlay(alignment: .bottom) { Divider() }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Save ssh \(target.text) as a connection")
        }
    }

    static func save(_ t: TypedSshTarget, pane: TerminalPane, model: LibraryModel) {
        pane.sshOffer = nil
        model.mutate { _ = try $0.addConnection(parent: nil, name: t.host, protocol: "ssh", host: t.host, port: t.port, username: t.user) }
    }
}

/// The red accent of a connection tagged `production` or `prod` (core rule), when it has no host
/// colour of its own.
enum ProductionAccent {
    static let paint = HostColors.Paint(accent: .systemRed, text: .white, tint: NSColor.systemRed.withAlphaComponent(0.12))

    /// Every production-tagged connection in the tree (one walk per tree change, not per paint).
    static func ids(in tree: FolderView?) -> Set<String> {
        var out = Set<String>()
        func walk(_ f: FolderView) {
            for c in f.connections where !c.tags.isEmpty && tagsIsProduction(tags: c.tags) { out.insert(c.id) }
            f.folders.forEach(walk)
        }
        if let tree { walk(tree) }
        return out
    }
}
