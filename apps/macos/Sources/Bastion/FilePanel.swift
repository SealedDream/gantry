import AppKit
import SwiftUI
import BastionCore

/// Where the file panel sits beside the session area.
enum FileDock: String, CaseIterable {
    case left, right, bottom

    var label: String {
        switch self {
        case .left: "Dock Left"
        case .right: "Dock Right"
        case .bottom: "Dock Bottom"
        }
    }

    var edge: Edge.Set {
        switch self {
        case .left: .leading
        case .right: .trailing
        case .bottom: .bottom
        }
    }

    var alignment: Alignment {
        switch self {
        case .left: .leading
        case .right: .trailing
        case .bottom: .bottom
        }
    }

    var isVertical: Bool { self == .bottom }

    /// Coordinate space of the session area the panel docks in.
    static let area = "file-panel-area"

    /// The dock a header dropped at `point` in an area of `size` asks for: the outer thirds pick a
    /// side, the lower part of the middle picks the bottom, anything else keeps `current`.
    static func target(for point: CGPoint, in size: CGSize, current: FileDock) -> FileDock {
        guard size.width > 0, size.height > 0 else { return current }
        if point.x < size.width / 3 { return .left }
        if point.x > size.width * 2 / 3 { return .right }
        if point.y > size.height * 0.6 { return .bottom }
        return current
    }
}

/// Dock edge, size and pop-out state of the SFTP file panel, remembered per workspace in
/// `file-panel.json` next to the library (`{"<workspace id>|default": {"dock": "right", "size": 320}}`),
/// so test runs with `BASTION_LIBRARY` never touch the user's layout.
@MainActor @Observable
final class FilePanelLayout {
    static let shared = FilePanelLayout(file: LibraryModel.dataDir.appendingPathComponent("file-panel.json"))
    static let minSize: CGFloat = 220
    static let defaultSize: CGFloat = 320
    /// The panel never takes more than this share of the session area.
    static let maxShare: CGFloat = 0.7

    struct Saved: Codable, Equatable {
        var dock: String
        var size: Double
    }

    private(set) var dock: FileDock = .right
    private(set) var size: CGFloat = defaultSize
    var poppedOut = false
    private(set) var scope = "default"
    private var saved: [String: Saved] = [:]
    private let file: URL

    init(file: URL) {
        self.file = file
        if let data = try? Data(contentsOf: file) {
            do { saved = try JSONDecoder().decode([String: Saved].self, from: data) } catch {
                NSLog("Gantry: file-panel.json is unreadable and will be replaced: \(error)")
            }
        }
        apply()
    }

    /// Switches to another workspace's remembered layout.
    func use(workspace id: String?) {
        let next = id ?? "default"
        guard next != scope else { return }
        scope = next
        apply()
    }

    func move(to dock: FileDock) {
        self.dock = dock
        save()
    }

    /// Clamped to `minSize`…`maxShare` of `available` (the session area along the dock's axis).
    func resize(to value: CGFloat, available: CGFloat) {
        size = Self.clamp(value, available: available)
        save()
    }

    static func clamp(_ value: CGFloat, available: CGFloat) -> CGFloat {
        let upper = max(minSize, available * maxShare)
        return min(max(value, minSize), upper)
    }

    private func apply() {
        let s = saved[scope]
        dock = s.flatMap { FileDock(rawValue: $0.dock) } ?? .right
        size = s.map { max(CGFloat($0.size), Self.minSize) } ?? Self.defaultSize
    }

    private func save() {
        saved[scope] = Saved(dock: dock.rawValue, size: Double(size))
        do {
            try JSONEncoder().encode(saved).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch {
            NSLog("Gantry: file panel layout not saved: \(error)")
        }
    }
}

/// Lays the selected tab's file panel along its dock edge. `content` keeps one place in the view
/// tree whatever the dock, so terminals are never remounted when the panel moves or closes.
struct FilePanelHost<Content: View>: View {
    let tab: TerminalTab?
    @ViewBuilder let content: Content
    @Environment(WorkspaceModel.self) private var workspaces
    @State private var layout = FilePanelLayout.shared
    @State private var area: CGSize = .zero

    private var browser: FilesBrowser? { layout.poppedOut ? nil : tab?.filePanel }

    var body: some View {
        content
            .padding(layout.dock.edge, browser == nil ? 0 : layout.size + 1)
            .overlay(alignment: layout.dock.alignment) {
                if let browser, let tab {
                    DockedFilePanel(tab: tab, browser: browser, layout: layout, area: area)
                        .frame(width: layout.dock.isVertical ? nil : layout.size,
                               height: layout.dock.isVertical ? layout.size : nil)
                }
            }
            .coordinateSpace(.named(FileDock.area))
            .background(SizeReporter { if area != $0 { area = $0 } })
            .onChange(of: workspaces.currentId, initial: true) { _, id in layout.use(workspace: id) }
    }

}

/// Header (title, dock menu, close), the browser, and a resize edge facing the terminal.
/// Dragging the header to another edge of the session area docks it there.
private struct DockedFilePanel: View {
    let tab: TerminalTab
    let browser: FilesBrowser
    let layout: FilePanelLayout
    let area: CGSize
    @State private var dragStart: CGFloat?
    @State private var dropTarget: FileDock?

    var body: some View {
        let stack = layout.dock.isVertical ? AnyLayout(VStackLayout(spacing: 0)) : AnyLayout(HStackLayout(spacing: 0))
        stack {
            if layout.dock != .left { resizeEdge }
            VStack(spacing: 0) {
                header
                Divider()
                FilesView(browser: browser, tab: tab)
            }
            if layout.dock == .left { resizeEdge }
        }
        .background(.background)
        .overlay {
            if let dropTarget, dropTarget != layout.dock { Color.accentColor.opacity(0.08).allowsHitTesting(false) }
        }
        .uiProbe("file-panel")
    }

    private var header: some View {
        HStack(spacing: DS.Space.xs) {
            Image(systemName: "folder").foregroundStyle(.secondary)
            Text("Files — \(tab.title)").font(DS.Font.caption.weight(.semibold)).lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 0)
            Menu {
                ForEach(FileDock.allCases, id: \.self) { d in
                    Button(d.label) { layout.move(to: d) }.disabled(d == layout.dock)
                }
                Divider()
                Button("Pop Out") { FilePanelWindow.shared.popOut(tab) }
            } label: {
                Image(systemName: "rectangle.split.3x1")
            }
            .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
            .help("Move or pop out")
            .accessibilityLabel("File panel position")
            Button { tab.closeFilePanel() } label: { Image(systemName: "xmark").iconHitTarget() }
                .buttonStyle(.borderless)
                .help("Close file panel")
                .accessibilityLabel("Close file panel")
        }
        .padding(.horizontal, DS.Space.s).frame(height: 26)
        .contentShape(Rectangle())
        .gesture(DragGesture(minimumDistance: 8, coordinateSpace: .named(FileDock.area))
            .onChanged { dropTarget = FileDock.target(for: $0.location, in: area, current: layout.dock) }
            .onEnded {
                layout.move(to: FileDock.target(for: $0.location, in: area, current: layout.dock))
                dropTarget = nil
            })
        .help("Drag to another edge to move")
    }

    /// Thin divider with a wider invisible grip; drags change the panel's size.
    private var resizeEdge: some View {
        let vertical = layout.dock.isVertical
        return Divider()
            .overlay {
                Color.clear
                    .frame(width: vertical ? nil : 6, height: vertical ? 6 : nil)
                    .contentShape(Rectangle())
                    .onHover { inside in
                        if inside { (vertical ? NSCursor.resizeUpDown : NSCursor.resizeLeftRight).push() } else { NSCursor.pop() }
                    }
                    .gesture(DragGesture(minimumDistance: 1, coordinateSpace: .named(FileDock.area))
                        .onChanged { g in
                            let start = dragStart ?? layout.size
                            dragStart = start
                            let delta: CGFloat = switch layout.dock {
                            case .left: g.translation.width
                            case .right: -g.translation.width
                            case .bottom: -g.translation.height
                            }
                            layout.resize(to: start + delta, available: vertical ? area.height : area.width)
                        }
                        .onEnded { _ in dragStart = nil })
            }
    }
}

/// The popped-out file panel: one window for the tab it was popped from. Closing the window docks
/// the panel again; closing the panel (or its tab) closes the window.
@MainActor
final class FilePanelWindow: NSObject, NSWindowDelegate {
    static let shared = FilePanelWindow()
    private var window: NSWindow?
    private weak var tab: TerminalTab?

    var isOpen: Bool { window != nil }

    func popOut(_ tab: TerminalTab) {
        guard let browser = tab.filePanel else { return }
        close()
        self.tab = tab
        let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 420),
                         styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false)
        w.title = "Files — \(tab.title)"
        w.isReleasedWhenClosed = false
        w.contentView = NSHostingView(rootView: FilesView(browser: browser, tab: tab))
        w.delegate = self
        w.setFrameAutosaveName("BastionFilePanel")
        w.makeKeyAndOrderFront(nil)
        window = w
        FilePanelLayout.shared.poppedOut = true
    }

    /// Closes the window when it shows `tab`'s panel (or that tab is gone).
    func closeIfShowing(_ tab: TerminalTab) {
        if self.tab == nil || self.tab === tab { close() }
    }

    func close() {
        window?.delegate = nil
        window?.close()
        window = nil
        tab = nil
        FilePanelLayout.shared.poppedOut = false
    }

    func windowWillClose(_ notification: Notification) {
        window = nil
        tab = nil
        FilePanelLayout.shared.poppedOut = false
    }
}

extension TerminalTab {
    /// SSH terminal tabs opened from a saved connection can carry a file panel.
    var canShowFilePanel: Bool { terminal != nil && connectionId != nil && mode == .terminal }

    func closeFilePanel() {
        filePanel = nil
        FilePanelWindow.shared.closeIfShowing(self)
    }
}
