import AppKit
import SwiftUI
import UniformTypeIdentifiers

// Tabs torn off the strip into their own window (owner UX spec §4, Safari/Edge): drag a tab
// out of every Bastion window, or right-click › Move Tab to New Window. The session keeps
// running; only its view moves. "Move to Main Window" (or closing the window, which asks
// first like ⌘W) brings it back.

/// What one tab shows: its pane tree, file browser, desktop, web page, system view or task.
/// Used by the main window's session area and by a torn-off tab's window.
struct TabContentView: View {
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    let tab: TerminalTab
    let isActive: Bool

    var body: some View {
        let _ = RenderCount.hit("TabContent")
        let locked = sessions.isDocumentLocked(tab)
        content
            .opacity(locked ? 0 : 1)
            .allowsHitTesting(!locked)
            .accessibilityHidden(locked)
            .overlay { if locked { DocumentLockedCover() } }
    }

    @ViewBuilder private var content: some View {
        Group {
            if let root = tab.root {
                PaneTreeView(tab: tab, node: root, isActive: isActive)
                    .overlay {
                        // Per-host colour: a thin border round the whole terminal.
                        if let p = HostColors.shared.paint(for: tab.connectionId) {
                            Rectangle().strokeBorder(Color(nsColor: p.accent), lineWidth: 2).allowsHitTesting(false)
                        }
                    }
            } else if case .files(let b) = tab.content {
                FilesView(browser: b).background(.background)
            } else if case .rdp(let session) = tab.content {
                RdpView(session: session, isActive: isActive,
                        fit: DesktopFit.of(commands.model.library, connectionId: tab.connectionId),
                        onClosed: { tab.desktopCloseReason = $0 ?? "closed" })
                    .overlay { DesktopEndedOverlay(tab: tab) }
            } else if case .web(let url) = tab.content {
                WebTabView(url: url, socksPort: tab.gatewayRoute?.localPort() ?? tab.webTunnel?.port,
                           storeId: tab.webTunnel.flatMap { UUID(uuidString: $0.id) }, connectionId: tab.connectionId,
                           onFirstResult: { f in if let id = tab.connectionId { sessions.recordOutcome(id, user: nil, failure: f) } })
            } else if case .system(let system) = tab.content {
                SystemViewTab(system: system, isActive: isActive) {
                    if let id = tab.connectionId, let c = commands.model.connection(id: id) { commands.requestConnect(c, .terminal) }
                }
            } else if case .task(let run) = tab.content {
                TaskOutputView(run: run).background(.background)
            } else if case .plugin(let m) = tab.content {
                PluginTabView(model: m).background(.background)
            } else if tab.isWaiting {
                RestoredTabView(tab: tab, isActive: isActive)
            } else if case .vnc(let viewer) = tab.content {
                VncView(viewer: viewer, isActive: isActive,
                        fit: DesktopFit.of(commands.model.library, connectionId: tab.connectionId),
                        onClosed: { tab.desktopCloseReason = $0 ?? "closed" })
                    .overlay { DesktopEndedOverlay(tab: tab) }
            }
        }
    }
}

/// Shown over a session whose document is locked: nothing of the session shows through, and
/// keyboard focus leaves the session view so typing cannot reach it.
struct DocumentLockedCover: View {
    var body: some View {
        VStack(spacing: DS.Space.s) {
            Image(systemName: "lock.fill").font(DS.Font.title2).foregroundStyle(.secondary)
            Text("Document locked").font(DS.Font.headline)
            Text("Unlock the document in the main window to use this session.").font(DS.Font.callout).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(.background)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("document-locked-cover")
        .background(WindowHook { DocumentLockedCover.dropSessionFocus(in: $0) })
    }
}

extension DocumentLockedCover {
    /// A session view (terminal, desktop, web) holding the keyboard loses it; a text field such as
    /// the main window's Unlock password (edited through the field editor, an `NSText`) keeps it.
    static func dropSessionFocus(in window: NSWindow) {
        guard let v = window.firstResponder as? NSView, !(v is NSText) else { return }
        window.makeFirstResponder(nil)
    }
}

extension SessionsModel {
    /// Tear a tab off into a new window of its own, its top-left at `point` (screen coordinates)
    /// when it came from a drag. The session keeps running; nothing reconnects.
    func moveToWindow(_ tab: TerminalTab, at point: NSPoint? = nil) {
        guard tabs.contains(where: { $0.id == tab.id }), let open = openTabWindow else { return }
        // Already alone in its window: a new one would look the same.
        if let w = windowed[tab.id], tabs(inWindow: w).count == 1 { return }
        let window = UUID()
        TabWindows.pendingOrigin[window] = point
        TabWindows.pendingFocus.insert(window)
        move(tab, toWindow: window)
        open(window)
    }

    /// Move a tab into a window (nil: the main window) and select it there. A window left with
    /// no tabs closes itself (`TabWindowView`).
    func move(_ tab: TerminalTab, toWindow window: UUID?) {
        if tab.pinned, window != nil { setPinned(tab, false) }
        let from = windowed[tab.id]
        windowed[tab.id] = window
        if let from, from != window, windowSelected[from] == tab.id {
            windowSelected[from] = tabs.last { windowed[$0.id] == from }?.id
        }
        if let window {
            windowSelected[window] = tab.id
            if selected == tab.id { selected = mainTabs.last?.id }
        } else {
            selected = tab.id
        }
    }

    /// Tabs in a torn-off window, in strip order.
    func tabs(inWindow window: UUID) -> [TerminalTab] { tabs.filter { windowed[$0.id] == window } }

    /// The tab with this id was dropped on `target` (any window): it joins the target's window,
    /// at the target's place (core `StripOp::Move`).
    func dropTab(_ id: String, onto target: TerminalTab) {
        guard id != target.id.uuidString, let dragged = tabs.first(where: { $0.id.uuidString == id }),
              let to = tabs.firstIndex(where: { $0.id == target.id }) else { return }
        if windowed[dragged.id] != windowed[target.id] { move(dragged, toWindow: windowed[target.id]) }
        groupOp(["op": "move", "tab": id, "to": to])
    }

    /// Edge "Move group to new window": every tab of the group, in strip order, into one new window.
    func moveGroupToWindow(_ group: String) {
        let members = tabs.filter { $0.group == group }
        guard !members.isEmpty, let open = openTabWindow else { return }
        let window = UUID()
        for tab in members { move(tab, toWindow: window) }
        open(window)
    }

    /// A tab dropped past the last tab: to the end of the strip, out of its group.
    func dropTabAtEnd(_ id: String) {
        guard let dragged = tabs.first(where: { $0.id.uuidString == id }) else { return }
        if windowed[dragged.id] != nil { move(dragged, toWindow: nil) }
        groupOp(["op": "move", "tab": id, "to": tabs.count])
        if tabs.first(where: { $0.id.uuidString == id })?.group != nil { groupOp(["op": "removeFromGroup", "tab": id]) }
    }

    /// B12: a restored tab goes back into the window it was torn off into (`pendingWindows`, in
    /// plan order per connection). The window opens at its saved frame, kept on a visible screen;
    /// its saved front tab is in front again. Nothing reconnects or signs in because of this.
    func placeRestored(_ tab: TerminalTab) {
        guard let id = tab.connectionId, var queue = pendingWindows[id], !queue.isEmpty else { return }
        let target = queue.removeFirst()
        pendingWindows[id] = queue.isEmpty ? nil : queue
        guard let window = target, let open = openTabWindow else { return }
        move(tab, toWindow: window)
        let key = SessionRestore.waitingKey(connection: id, mode: tab.mode.rawValue)
        if pendingWindowFronts[window] == key {
            pendingWindowFronts[window] = nil
            restoredFronts[window] = tab.id
        } else if let front = restoredFronts[window] {
            windowSelected[window] = front
        }
        guard TabWindows.windows[window] == nil, let frame = pendingWindowFrames.removeValue(forKey: window) else { return }
        TabWindows.pendingFrame[window] = frame
        open(window)
    }

    /// A torn-off window closed: its tabs go back to the main window's strip.
    func windowClosed(_ window: UUID) {
        for tab in tabs(inWindow: window) { move(tab, toWindow: nil) }
        windowSelected[window] = nil
        TabWindows.windows[window] = nil
    }
}

/// The windows holding torn-off tabs, by window id.
@MainActor
enum TabWindows {
    static let sceneId = "tab-window"
    static var windows: [UUID: NSWindow] = [:]
    /// Where a dragged-out tab's window should open (its top-left), until the window exists.
    static var pendingOrigin: [UUID: NSPoint] = [:]
    /// B12: set once the app has agreed to quit. Windows closed by the quit itself are not a user
    /// closing them: their tabs stay put, so the saved set keeps them in their windows.
    static var isTerminating = false
    /// B12: a restored window's saved frame, until the window exists.
    static var pendingFrame: [UUID: NSRect] = [:]
    /// How much of a restored window must show on some screen (both ways, points) to keep its
    /// saved place: enough to grab the title bar. Less, and it opens centred on the main screen.
    nonisolated static let minimumShown: CGFloat = 80

    /// B12 (owner 2026-11-14): a saved frame where it was, unless no screen shows enough of it
    /// (a monitor that is gone); then centred on the first screen, shrunk to fit. `screens` are
    /// visible frames, the main screen first.
    nonisolated static func onScreen(_ frame: NSRect, screens: [NSRect]) -> NSRect {
        guard let main = screens.first else { return frame }
        let shown = screens.contains { s in
            let i = s.intersection(frame)
            return !i.isNull && i.width >= minimumShown && i.height >= minimumShown
        }
        if shown { return frame }
        let size = NSSize(width: min(frame.width, main.width), height: min(frame.height, main.height))
        return NSRect(x: main.midX - size.width / 2, y: main.midY - size.height / 2, width: size.width, height: size.height)
    }

    static var visibleScreens: [NSRect] {
        let main = NSScreen.main.map { [$0.visibleFrame] } ?? []
        return main + NSScreen.screens.map(\.visibleFrame).filter { !main.contains($0) }
    }

    /// Make the window key and frontmost (W16). An inactive app (a background launch, or picking the
    /// tab from the Dock menu) does not reorder on `makeKeyAndOrderFront` alone, so the window is
    /// also ordered front among the app's windows; the app is not activated (no focus stealing).
    static func focus(_ window: UUID) {
        guard let w = windows[window] else { return }
        raise(w)
        // Picking the tab also changes the main window's selection; SwiftUI's update of the main
        // window runs after this and can order it back on top, so raise again once it has run.
        DispatchQueue.main.async { MainActor.assumeIsolated { if w.isVisible { raise(w) } } }
    }

    private static func raise(_ w: NSWindow) {
        w.makeKeyAndOrderFront(nil)
        if !NSApp.isActive { w.orderFrontRegardless() }
    }

    /// Windows the user just tore off: they take focus once attached (restored ones do not).
    static var pendingFocus: Set<UUID> = []

    private static var closeObservers: [UUID: NSObjectProtocol] = [:]
    private static var frameObservers: [UUID: [NSObjectProtocol]] = [:]

    /// Remember the window and run `closed` when it closes (the red button, ⌘W, Move to Main
    /// Window). SwiftUI's onDisappear does not run for a WindowGroup window closed by the user.
    fileprivate static func attach(_ window: NSWindow, to id: UUID, moved: @escaping @MainActor @Sendable () -> Void,
                                   closed: @escaping @MainActor @Sendable () -> Void) {
        guard windows[id] !== window else { return }
        windows[id] = window
        if let origin = pendingOrigin.removeValue(forKey: id) { window.setFrameTopLeftPoint(origin) }
        if let frame = pendingFrame.removeValue(forKey: id) { window.setFrame(onScreen(frame, screens: visibleScreens), display: true) }
        frameObservers[id]?.forEach(NotificationCenter.default.removeObserver)
        frameObservers[id] = [NSWindow.didMoveNotification, NSWindow.didEndLiveResizeNotification].map { name in
            NotificationCenter.default.addObserver(forName: name, object: window, queue: .main) { _ in
                MainActor.assumeIsolated { moved() }
            }
        }
        moved()
        if pendingFocus.remove(id) != nil { focus(id) }
        closeObservers[id].map(NotificationCenter.default.removeObserver)
        closeObservers[id] = NotificationCenter.default.addObserver(forName: NSWindow.willCloseNotification, object: window, queue: .main) { _ in
            MainActor.assumeIsolated {
                closeObservers.removeValue(forKey: id).map(NotificationCenter.default.removeObserver)
                frameObservers.removeValue(forKey: id)?.forEach(NotificationCenter.default.removeObserver)
                closed()
            }
        }
    }
}

/// One torn-off window (`WindowGroup` scene `tab-window`, keyed by window id): its own tab bar
/// over its own tabs. A window left with no tabs (moved back, merged away, closed, or a stale
/// restored window) closes itself.
struct TabWindowView: View {
    @Environment(SessionsModel.self) private var sessions
    @Environment(\.dismiss) private var dismiss
    let id: UUID?

    var body: some View {
        let tabs = id.map(sessions.tabs(inWindow:)) ?? []
        if let id, !tabs.isEmpty {
            let selected = sessions.windowSelected[id].flatMap { s in tabs.first { $0.id == s } } ?? tabs[0]
            VStack(spacing: 0) {
                TabWindowStrip(window: id, tabs: tabs, selected: selected.id)
                    .modifier(ChromeSurface(tone: \.tabStrip))
                Divider()
                ZStack {
                    ForEach(tabs) { tab in
                        TabContentView(tab: tab, isActive: tab.id == selected.id)
                            .opacity(tab.id == selected.id ? 1 : 0)
                            .allowsHitTesting(tab.id == selected.id)
                    }
                }
            }
            .navigationTitle(selected.title)
            // UI-06: this window's tones come from its own selected tab, apart from the main window's.
            .modifier(ChromeTonesProvider(window: (id, selected)))
            .toolbar {
                Button { moveAllBack(id) } label: {
                    Label("Move to Main Window", systemImage: "rectangle.stack.badge.plus")
                }
                .help("Put this window's tabs back in the main window's tab strip")
            }
            .background(WindowHook { [sessions] in
                TabWindows.attach($0, to: id, moved: { sessions.windowFramesVersion += 1 }) {
                    // Closed with the red button: the tabs go back to the strip, then the usual
                    // close question for each. Cancel leaves it as a tab in the main window.
                    let open = sessions.tabs(inWindow: id)
                    guard !open.isEmpty, !TabWindows.isTerminating else { return }
                    sessions.windowClosed(id)
                    for tab in open { sessions.requestClose(tab) }
                }
            })
        } else {
            Color.clear.frame(width: 1, height: 1).onAppear { dismiss() }
        }
    }

    private func moveAllBack(_ window: UUID) {
        sessions.windowClosed(window)
        dismiss()
    }
}

/// A torn-off window's tab bar: the main strip's buttons, drag and drop (reorder, merge into
/// another window, tear off again) and close.
private struct TabWindowStrip: View {
    @Environment(SessionsModel.self) private var sessions
    let window: UUID
    let tabs: [TerminalTab]
    let selected: UUID

    var body: some View {
        GeometryReader { geo in
            let width = max(DS.Size.tabMin, geo.size.width / CGFloat(max(tabs.count, 1)) - 2)
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 2) {
                    ForEach(tabs) { tab in
                        TabButton(tab: tab, isSelected: tab.id == selected,
                                  select: { sessions.windowSelected[window] = tab.id },
                                  close: { sessions.requestClose(tab) }, width: width)
                            .tabDragAndDrop(tab, sessions: sessions)
                    }
                }
                .padding(.horizontal, 6)
            }
        }
        .frame(height: 32)
    }
}

/// Hands the hosting NSWindow to `found` once the view is in one.
private struct WindowHook: NSViewRepresentable {
    let found: (NSWindow) -> Void

    func makeNSView(context: Context) -> HookView { HookView(found: found) }
    func updateNSView(_ view: HookView, context: Context) { view.found = found }

    final class HookView: NSView {
        var found: (NSWindow) -> Void
        init(found: @escaping (NSWindow) -> Void) { self.found = found; super.init(frame: .zero) }
        required init?(coder: NSCoder) { nil }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let window { found(window) }
        }
    }
}

/// Dragging a tab: a private, in-process pasteboard type (so Finder or another app never takes
/// it as text), dropped on another tab to reorder, or released outside every Bastion window to
/// tear it off. SwiftUI says nothing when a drag ends on no drop target, so the end is watched
/// from the mouse button.
@MainActor
enum TabDrag {
    static let typeId = "com.sealeddream.bastion.tab"
    static let type = UTType(importedAs: typeId)
    private static var watch: Timer?
    private static var dropped = false
    private static let pollInterval: TimeInterval = 0.05

    static func provider(for tab: TerminalTab, sessions: SessionsModel) -> NSItemProvider {
        began(tab, sessions: sessions)
        let provider = NSItemProvider()
        let payload = Data(tab.id.uuidString.utf8)
        provider.registerDataRepresentation(forTypeIdentifier: typeId, visibility: .ownProcess) { done in
            done(payload, nil)
            return nil
        }
        return provider
    }

    /// A drop on a tab in any window: reorder or merge (`dropTab`); the drag is not a tear-off.
    static func drop(_ providers: [NSItemProvider], onto tab: TerminalTab, sessions: SessionsModel) -> Bool {
        guard let provider = providers.first(where: { $0.hasItemConformingToTypeIdentifier(typeId) }) else { return false }
        dropped = true
        provider.loadDataRepresentation(forTypeIdentifier: typeId) { data, _ in
            guard let data, let id = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async { sessions.dropTab(id, onto: tab) }
        }
        return true
    }

    /// A drop on a group chip: the tab joins that group (core `AddToGroup`).
    static func dropInto(group: String, _ providers: [NSItemProvider], sessions: SessionsModel) -> Bool {
        load(providers) { id in
            if let tab = sessions.tabs.first(where: { $0.id.uuidString == id }), sessions.windowed[tab.id] != nil { sessions.move(tab, toWindow: nil) }
            sessions.groupOp(["op": "addToGroup", "tab": id, "group": group])
        }
    }

    /// A drop past the last tab (on +): the tab leaves its group for the end of the strip.
    static func dropAtEnd(_ providers: [NSItemProvider], sessions: SessionsModel) -> Bool {
        load(providers) { sessions.dropTabAtEnd($0) }
    }

    private static func load(_ providers: [NSItemProvider], _ then: @escaping @MainActor (String) -> Void) -> Bool {
        guard let provider = providers.first(where: { $0.hasItemConformingToTypeIdentifier(typeId) }) else { return false }
        dropped = true
        provider.loadDataRepresentation(forTypeIdentifier: typeId) { data, _ in
            guard let data, let id = String(data: data, encoding: .utf8) else { return }
            DispatchQueue.main.async { MainActor.assumeIsolated { then(id) } }
        }
        return true
    }

    private static func began(_ tab: TerminalTab, sessions: SessionsModel) {
        dropped = false
        watch?.invalidate()
        watch = Timer.scheduledTimer(withTimeInterval: pollInterval, repeats: true) { _ in
            MainActor.assumeIsolated {
                guard NSEvent.pressedMouseButtons & 1 == 0 else { return }
                watch?.invalidate()
                watch = nil
                if !dropped { ended(tab, at: NSEvent.mouseLocation, sessions: sessions) }
            }
        }
    }

    /// The drag ended on no drop target at `point` (screen coordinates).
    static func ended(_ tab: TerminalTab, at point: NSPoint, sessions: SessionsModel) {
        let frames = NSApp.windows.filter { $0.isVisible && !$0.isMiniaturized }.map(\.frame)
        guard tearsOff(at: point, windowFrames: frames) else { return }
        sessions.moveToWindow(tab, at: point)
    }

    /// Released outside every Bastion window: Safari and Edge open the tab in a new window there.
    nonisolated static func tearsOff(at point: NSPoint, windowFrames: [NSRect]) -> Bool {
        !windowFrames.contains { $0.contains(point) }
    }
}
