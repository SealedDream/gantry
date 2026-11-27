import AppKit
import SwiftUI

/// Full-screen auto-dock of the library panel (Royal TS style). While the window is in full screen
/// and the library column is hidden, resting the pointer on the far left edge slides the library in
/// *over* the sessions; it slides away once the pointer leaves it. The split view's column is never
/// shown, so the session area (and every PTY) keeps its size.
@MainActor @Observable
final class AutoDock {
    static let shared = AutoDock()

    /// Pointer must rest on the edge this long before the panel comes in.
    static let revealDelay: Duration = .milliseconds(150)
    /// Pointer must stay outside the panel this long before it goes.
    static let hideDelay: Duration = .milliseconds(400)
    /// How close to the window's left edge counts as "at the edge", in points.
    static let edgeWidth: CGFloat = 2

    /// The docked panel shows now.
    private(set) var docked = false
    /// Things that keep the panel in while they last: the outline's rename and drag, menu tracking.
    var renaming = false { didSet { holdChanged() } }
    var dragging = false { didSet { holdChanged() } }
    private(set) var menuTracking = false

    @ObservationIgnored private var pending: Task<Void, Never>?
    @ObservationIgnored private var pointerInPanel = false
    @ObservationIgnored private var tokens: [NSObjectProtocol] = []

    var isHeld: Bool { renaming || dragging || menuTracking }

    private init() {
        let center = NotificationCenter.default
        for (name, on) in [(NSMenu.didBeginTrackingNotification, true), (NSMenu.didEndTrackingNotification, false)] {
            tokens.append(center.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.setMenuTracking(on) }
            })
        }
    }

    /// The pointer moved to `x` (window points from the left). `enabled`: full screen, the setting
    /// is on and the library column is hidden.
    func pointerMoved(x: CGFloat, panelWidth: CGFloat, enabled: Bool) {
        guard enabled else { return dismiss() }
        if docked {
            pointerInPanel = x <= panelWidth
            pointerInPanel ? cancelPending() : scheduleHide()
        } else if x <= Self.edgeWidth {
            scheduleReveal()
        } else {
            cancelPending()
        }
    }

    /// ⌃⌘S while docking applies: slide the panel in or out at once.
    func toggle() {
        cancelPending()
        docked.toggle()
        pointerInPanel = docked
    }

    /// Left full screen, setting off, or the real column shows: no overlay.
    func dismiss() {
        cancelPending()
        docked = false
        pointerInPanel = false
    }

    private func setMenuTracking(_ on: Bool) {
        menuTracking = on
        holdChanged()
    }

    private func holdChanged() {
        if isHeld { cancelPending() } else if docked && !pointerInPanel { scheduleHide() }
    }

    private func scheduleReveal() {
        guard pending == nil else { return }
        pending = Task { [weak self] in
            try? await Task.sleep(for: Self.revealDelay)
            guard !Task.isCancelled, let self else { return }
            self.pending = nil
            self.docked = true
            self.pointerInPanel = true
        }
    }

    private func scheduleHide() {
        guard pending == nil, !isHeld else { return }
        pending = Task { [weak self] in
            try? await Task.sleep(for: Self.hideDelay)
            guard !Task.isCancelled, let self else { return }
            self.pending = nil
            if !self.isHeld && !self.pointerInPanel { self.docked = false }
        }
    }

    private func cancelPending() {
        pending?.cancel()
        pending = nil
    }
}

/// Reports pointer movement in its window (a local event monitor: nothing runs while the pointer is still).
struct PointerMonitor: NSViewRepresentable {
    let onMove: (CGFloat) -> Void

    func makeNSView(context: Context) -> MonitorView { MonitorView(onMove: onMove) }
    func updateNSView(_ view: MonitorView, context: Context) { view.onMove = onMove }

    final class MonitorView: NSView {
        var onMove: (CGFloat) -> Void
        private var monitor: Any?

        init(onMove: @escaping (CGFloat) -> Void) {
            self.onMove = onMove
            super.init(frame: .zero)
        }

        required init?(coder: NSCoder) { nil }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
            guard let window else { return }
            window.acceptsMouseMovedEvents = true
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.mouseMoved, .leftMouseDragged]) { [weak self] event in
                if let self, event.window === self.window { self.onMove(event.locationInWindow.x) }
                return event
            }
        }
    }
}
