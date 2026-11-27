import AppKit

/// MAC-FULLSCREEN (owner 2026-11-14: "I tried full screening and it didn't work"). SwiftUI builds
/// the View menu from `AppMenus` (`CommandGroup(replacing: .sidebar)`), and AppKit's automatic
/// "Enter Full Screen" item never lands in it, so View › Enter Full Screen was missing and ⌃⌘F
/// had no menu item to fire, also not to leave full screen. This puts AppKit's own item back:
/// action `toggleFullScreen:` to the first responder, so NSWindow validates it and flips its title
/// between Enter and Exit Full Screen. SwiftUI may rebuild the menu, so it is re-checked when a
/// window becomes key and after every shortcut update.
@MainActor
enum FullScreenMenu {
    static let title = "Enter Full Screen"
    private static var observer: NSObjectProtocol?

    static func install() {
        ensure()
        guard observer == nil else { return }
        observer = NotificationCenter.default.addObserver(forName: NSWindow.didBecomeKeyNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { ensure() }
        }
    }

    /// Adds the item at the end of the View menu unless a toggleFullScreen: item is there already.
    static func ensure() {
        guard let view = NSApp.mainMenu?.items.first(where: { $0.title == "View" })?.submenu else { return }
        guard !view.items.contains(where: { $0.action == #selector(NSWindow.toggleFullScreen(_:)) }) else { return }
        let item = NSMenuItem(title: title, action: #selector(NSWindow.toggleFullScreen(_:)), keyEquivalent: "f")
        item.keyEquivalentModifierMask = [.control, .command]
        if view.items.last?.isSeparatorItem == false { view.addItem(.separator()) }
        view.addItem(item)
    }
}
