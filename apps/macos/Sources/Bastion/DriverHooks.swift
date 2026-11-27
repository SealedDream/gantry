import AppKit

/// The few driver touch points that ordinary code refers to. They are compiled into every build but
/// inert outside a test build: only the UI driver (`#if BASTION_TEST_HOOKS`) posts these
/// notifications, `RenderCount` and `registerForDriver` do nothing unless `TestHooks.isScripted`.
enum DriverEvents {
    /// UI-06: the tones the main window last applied (`ChromeTonesProvider`); nil = stock colours.
    @MainActor static var chromeTones: ChromeTones?
    /// UI-06: tones per torn-off window id.
    @MainActor static var windowChromeTones: [UUID: ChromeTones?] = [:]
    /// Posted by `top-button` with the button title when no titled AppKit button matches.
    static let pressButton = Notification.Name("bastion.ui.press-button")
    /// Posted by `title-bar-button` with Reconnect, Pin or Unpin.
    static let pressTitleBarButton = Notification.Name("bastion.ui.press-title-bar-button")
    /// Posted by `recent open|remove <name>` with [action, name] for the start page's Recent Sessions.
    static let recentAction = Notification.Name("bastion.ui.recent-action")
    /// Names in the start page's Recent Sessions, newest first (`recents` logs them).
    @MainActor static var recentNames: [String] = []
    /// The Compact header's controls by name ("library-switcher", "new", "active-tab",
    /// "tab-viewport"), for `header-menu` and `header-layout`; read their frames when asked.
    @MainActor static var headerViews: [String: WeakView] = [:]
    @MainActor static func headerFrame(_ name: String) -> NSRect? {
        guard let view = headerViews[name]?.view, view.window != nil else { return nil }
        return view.convert(view.bounds, to: nil)
    }
}

final class WeakView {
    weak var view: NSView?
    init(_ view: NSView) { self.view = view }
}

/// Body evaluations per view while UI suites run, so a timed step can say which views re-rendered.
@MainActor enum RenderCount {
    static var counts: [String: Int] = [:]
    static func hit(_ view: String) { if UIProbe.isActive { counts[view, default: 0] += 1 } }
    /// Time spent making and filling dashboard row views, in whole microseconds under "row-build-us".
    static func build(ms: Double) { if UIProbe.isActive { counts["row-build-us", default: 0] += Int(ms * 1000) } }
    static func delta(since before: [String: Int]) -> String {
        let d = counts.compactMap { k, v in v - (before[k] ?? 0) > 0 ? "\(k)+\(v - (before[k] ?? 0))" : nil }.sorted()
        return d.isEmpty ? "none" : d.joined(separator: ",")
    }
}

extension ConnectionTest {
    /// The test of the property dialog that is open in a driver run.
    static weak var driverTarget: ConnectionTest?

    func registerForDriver() {
        if TestHooks.isScripted { Self.driverTarget = self }
    }
}

extension NSView {
    func firstSubview<T: NSView>(of type: T.Type) -> T? {
        for v in subviews {
            if let hit = v as? T { return hit }
            if let hit = v.firstSubview(of: type) { return hit }
        }
        return nil
    }

    func allSubviews<T: NSView>(of type: T.Type) -> [T] {
        subviews.flatMap { v -> [T] in
            let own: [T] = (v as? T).map { [$0] } ?? []
            return own + v.allSubviews(of: type)
        }
    }
}
