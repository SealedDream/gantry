import AppKit
import SwiftUI

/// The start window (owner-approved design, 2026-11-23): one window, two halves. Left: the
/// product, Recent documents and three quiet actions on the native sidebar material. Right: what
/// the selected row needs (unlock, open, locate), the create form, or the first-run welcome.
struct StartWindow: View {
    @Bindable var gate: DocumentGate
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    static let productName = "Gantry Terminal"
    static let leftWidth: CGFloat = 300
    static let rightMin: CGFloat = 360
    static let rightContent: CGFloat = 340
    /// ≤ 200 ms between unlock and create; a plain fade with Reduce Motion.
    private var swap: Animation { reduceMotion ? DS.Motion.reducedFade : .easeOut(duration: 0.18) }

    var body: some View {
        HStack(spacing: 0) {
            StartSidebar(gate: gate)
                .frame(width: Self.leftWidth)
                .frame(maxHeight: .infinity)
                .background(StartSidebarMaterial().ignoresSafeArea())
            Divider().ignoresSafeArea()
            right
                .frame(minWidth: Self.rightMin, maxWidth: .infinity, maxHeight: .infinity)
                .background(.background)
        }
        .animation(swap, value: pane)
        .accessibilityIdentifier("start-window")
    }

    /// A pane centred in the right half, scrolling when the window is short.
    private func scrolled<V: View>(_ v: V) -> some View {
        VStack(alignment: .leading, spacing: DS.Space.l) { v; StartFooter() }
            .frame(maxWidth: Self.rightContent)
            .padding(DS.Space.xl)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .scrollOnOverflow()
    }

    /// Which right-half view shows; drives the transition.
    enum Pane: Hashable { case create, unlock(String), open(String), missing(String), welcome }

    private var pane: Pane {
        if gate.creating { return .create }
        if let d = gate.unlockingDocument { return .unlock(d.info.path ?? d.id) }
        if let p = gate.selectedPath, let r = gate.row(p) { return r.present ? .open(p) : .missing(p) }
        return .welcome
    }

    @ViewBuilder private var right: some View {
        Group {
            switch pane {
            // The create form scrolls its own fields and pins Cancel / Create under them.
            case .create: StartCreatePane(gate: gate)
            case .unlock: scrolled(StartUnlockPane(gate: gate))
            case .open(let p): scrolled(StartOpenPane(gate: gate, recent: gate.row(p)!))
            case .missing(let p): scrolled(StartMissingPane(gate: gate, recent: gate.row(p)!))
            case .welcome: scrolled(StartWelcomePane(gate: gate))
            }
        }
        .transition(.opacity)
        .id(pane)
    }
}

extension DocumentGate {
    /// A Recents row, or the missing notice's document (dropped from Recents already).
    func row(_ path: String) -> Recent? {
        recents.first { $0.path == path } ?? (missing?.path == path ? missing : nil)
    }

    /// The left list: Recents, with the missing document (if any) first.
    var startRows: [Recent] {
        guard let m = missing, !recents.contains(where: { $0.path == m.path }) else { return recents }
        return [m] + recents
    }
}

/// The window's left half on the system sidebar material (vibrancy follows the desktop).
private struct StartSidebarMaterial: NSViewRepresentable {
    func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.material = .sidebar
        v.blendingMode = .behindWindow
        v.state = .followsWindowActiveState
        return v
    }
    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {}
}

private struct StartSidebar: View {
    @Bindable var gate: DocumentGate

    private var version: String {
        Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "dev"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, DS.Space.m)
                .padding(.top, DS.Space.xl)
                .padding(.bottom, DS.Space.m)
            Text("Recent documents")
                .font(DS.Font.subheadline.weight(.semibold)).foregroundStyle(.secondary)
                .padding(.horizontal, DS.Space.m)
                .padding(.bottom, DS.Space.xxs)
            recents
            Divider().padding(.horizontal, DS.Space.m)
            actions.padding(DS.Space.xs)
        }
    }

    private var header: some View {
        HStack(spacing: DS.Space.s) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable().frame(width: 40, height: 40)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(StartWindow.productName).font(DS.Font.headline)
                Text("Version \(version)").font(DS.Font.caption).foregroundStyle(.secondary).monospacedDigit()
            }
        }
        .accessibilityElement(children: .combine)
    }

    @ViewBuilder private var recents: some View {
        if gate.startRows.isEmpty {
            Text("No documents yet.")
                .font(DS.Font.callout).foregroundStyle(.tertiary)
                .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.xs)
            Spacer(minLength: 0)
        } else {
            // A native List: arrow keys move through it, the selection uses the system accent.
            List(selection: Binding(get: { gate.creating ? nil : gate.selectedPath }, set: { gate.select($0) })) {
                ForEach(gate.startRows, id: \.path) { r in
                    StartRecentRow(gate: gate, recent: r).tag(r.path)
                }
            }
            .listStyle(.sidebar)
            .scrollContentBackground(.hidden)
            .accessibilityIdentifier("start-recents")
        }
    }

    private var actions: some View {
        VStack(alignment: .leading, spacing: 0) {
            StartAction(title: "New document", symbol: "doc.badge.plus", shortcut: "⌥⌘N", id: "start-new") { gate.showCreate() }
            StartAction(title: "Open document…", symbol: "folder", shortcut: "⌘O", id: "start-open") { gate.openAnother() }
            StartAction(title: "Personal library", symbol: "person.crop.square", shortcut: "no password", id: "start-personal") { gate.openPersonal() }
        }
    }
}

private struct StartRecentRow: View {
    let gate: DocumentGate
    let recent: DocumentGate.Recent

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: DS.Space.xs) {
            Image(systemName: recent.present ? (recent.protected ? "lock.fill" : "lock.open") : "exclamationmark.triangle.fill")
                .font(DS.Font.caption)
                .foregroundStyle(recent.present ? AnyShapeStyle(.secondary) : AnyShapeStyle(Color.orange))
                .frame(width: 14)
                .accessibilityLabel(recent.present ? (recent.protected ? "Encrypted" : "No password") : "Missing")
            VStack(alignment: .leading, spacing: 1) {
                Text(recent.displayName).font(DS.Font.body).lineLimit(1)
                Text(detail).font(DS.Font.caption).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle)
            }
            Spacer(minLength: 0)
            if !recent.present {
                Button("Locate") { gate.locate(recent) }
                    .controlSize(.small)
                    .accessibilityIdentifier("start-locate")
                    .startFit(.button, "Locate \(recent.displayName)")
            }
        }
        .frame(minHeight: 36)
        .startFit(.row, "row \(recent.displayName)")
        .help(recent.path)
        .contextMenu {
            if !recent.present { Button("Locate…") { gate.locate(recent) } }
            Button("Remove from Recents") { gate.removeRecent(recent) }
        }
    }

    private var detail: String {
        let folder = StartText.shortPath((recent.path as NSString).deletingLastPathComponent)
        guard recent.present else { return "Not found · \(folder)" }
        return [folder, StartText.connections(recent.connectionCount), StartText.lastOpened(recent.lastOpenedAt)].compactMap { $0 }.joined(separator: " · ")
    }
}

private struct StartAction: View {
    let title: String
    let symbol: String
    let shortcut: String
    let id: String
    let action: () -> Void
    @State private var hover = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: DS.Space.xs) {
                Image(systemName: symbol).frame(width: 18).foregroundStyle(.secondary).accessibilityHidden(true)
                Text(title)
                Spacer(minLength: DS.Space.xs)
                Text(shortcut).font(DS.Font.caption).foregroundStyle(.tertiary)
            }
            .padding(.horizontal, DS.Space.xs)
            .frame(minHeight: 28)
            .contentShape(Rectangle())
            .background(RoundedRectangle(cornerRadius: 5).fill(hover ? Color.primary.opacity(0.06) : .clear))
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .startFit(.row, title, pinned: true)
        .accessibilityIdentifier(id)
    }
}

struct StartFooter: View {
    var body: some View {
        Text("Works offline · No telemetry")
            .font(DS.Font.caption).foregroundStyle(.tertiary)
            .accessibilityIdentifier("start-footer")
    }
}

enum StartText {
    /// `~/Documents/Lab` rather than `/Users/me/Documents/Lab`.
    static func shortPath(_ p: String) -> String { (p as NSString).abbreviatingWithTildeInPath }

    /// "12 connections"; nil when the count was never recorded.
    static func connections(_ n: UInt32?) -> String? {
        guard let n else { return nil }
        return n == 1 ? "1 connection" : "\(n) connections"
    }

    /// "last opened 2 h ago"; nil when never recorded.
    static func lastOpened(_ at: UInt64?) -> String? {
        guard let at, at > 0 else { return nil }
        let secs = at > 100_000_000_000 ? Double(at) / 1000 : Double(at)
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return "opened " + f.localizedString(for: Date(timeIntervalSince1970: secs), relativeTo: Date())
    }
}

extension View {
    /// Centred when it fits the height, scrollable when it does not.
    func scrollOnOverflow() -> some View {
        GeometryReader { g in
            ScrollView(.vertical) {
                self.frame(minHeight: g.size.height)
            }
            .scrollBounceBehavior(.basedOnSize)
        }
    }
}
