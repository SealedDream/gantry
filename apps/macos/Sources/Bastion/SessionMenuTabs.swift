import AppKit

/// Owner round 2, item 12: the Session menu lists the open tabs (up to nine) by name, on ⌘1…⌘9.
/// The items are AppKit's, added at the end of the menu and renamed in place, as `FullScreenMenu`
/// adds its item. Publishing the names to the SwiftUI menu instead rebuilt the whole menu bar on
/// every tab open, close and title change, and each rebuild left memory behind (#1277 soak,
/// about 0.08 MB a cycle).
@MainActor
enum SessionMenuTabs {
    private static var titles: [String] = []
    private static var keys: [String: (String, NSEvent.ModifierFlags)] = [:]
    private static var open: (String) -> Void = { _ in }
    /// The separator and the item per tab, while they are in the menu.
    private static var separator: NSMenuItem?
    private static var items: [NSMenuItem] = []
    private static var observers: [NSObjectProtocol] = []
    private static var pending = false

    /// The tab names (first nine), their key equivalents by `tab:n`, and the router call.
    static func update(titles: [String], keys: MenuKeys, open: @escaping (String) -> Void) {
        self.titles = titles
        self.keys = keys.chords.mapValues(Chords.menuKey)
        self.open = open
        if observers.isEmpty {
            // SwiftUI rebuilds its menus now and then (new key equivalents, workspaces) and drops
            // items it did not make: put them back when a menu opens or is refilled.
            observers = [NSMenu.didBeginTrackingNotification, NSMenu.didAddItemNotification].map { name in
                NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { _ in
                    MainActor.assumeIsolated { scheduleApply() }
                }
            }
        }
        apply()
    }

    /// One `apply` after a burst of item additions (also while a menu tracks).
    private static func scheduleApply() {
        guard !pending else { return }
        pending = true
        RunLoop.main.perform(inModes: [.eventTracking, .default]) {
            MainActor.assumeIsolated { pending = false; apply() }
        }
    }

    static func apply() {
        guard let menu = NSApp.mainMenu?.items.first(where: { $0.title == "Session" })?.submenu else { return }
        // Ours are kept at the end of the menu; SwiftUI may have rebuilt it without them.
        let ours = [separator].compactMap { $0 } + items
        if ours.contains(where: { $0.menu !== menu }) || menu.items.suffix(ours.count) != ours[...] {
            ours.forEach { $0.menu?.removeItem($0) }
            separator = nil
            items = []
        }
        if titles.isEmpty {
            ours.forEach { $0.menu?.removeItem($0) }
            separator = nil
            items = []
            return
        }
        if separator == nil {
            let s = NSMenuItem.separator()
            menu.addItem(s)
            separator = s
        }
        while items.count > titles.count { menu.removeItem(items.removeLast()) }
        while items.count < titles.count {
            let item = NSMenuItem(title: "", action: #selector(Target.show(_:)), keyEquivalent: "")
            item.target = Target.shared
            menu.addItem(item)
            items.append(item)
        }
        for (i, item) in items.enumerated() {
            if item.title != titles[i] { item.title = titles[i] }
            item.tag = i + 1
            let key = keys["tab:\(i + 1)"] ?? ("", [])
            if item.keyEquivalent != key.0 { item.keyEquivalent = key.0 }
            if item.keyEquivalentModifierMask != key.1 { item.keyEquivalentModifierMask = key.1 }
        }
    }

    /// The items' action target.
    @MainActor private final class Target: NSObject {
        static let shared = Target()
        @objc func show(_ sender: NSMenuItem) {
            SessionMenuTabs.open("tab:\(sender.tag)")
        }
    }
}
