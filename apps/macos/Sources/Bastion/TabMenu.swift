import AppKit
import SwiftUI

/// A tab's right-click menu, in AppKit. The strip sits in the toolbar, where SwiftUI's
/// `.contextMenu` never opens: right-click showed NSToolbar's "Icon and Text / Icon Only" menu
/// instead (owner round 4, item 5). Built on each click from the tab's current state.
@MainActor
enum TabMenu {
    static func build(tab: TerminalTab, sessions: SessionsModel, close: @escaping () -> Void) -> NSMenu {
        let menu = NSMenu()
        menu.addItem(ClosureMenuItem(title: "Rename Tab…") { sessions.renamingTab = tab.id })
        menu.addItem(ClosureMenuItem(title: tab.pinned ? "Unpin Tab" : "Pin Tab") { sessions.setPinned(tab, !tab.pinned) })
        menu.addItem(.separator())
        // SSH terminal tabs: a one-off login as another user (Commands "connect-as").
        if let id = tab.connectionId, tab.terminal != nil {
            menu.addItem(ClosureMenuItem(title: "Reconnect as…") { sessions.connectAsRequest = ConnectAsRequest(connectionId: id, replacing: tab.id) })
            menu.addItem(ClosureMenuItem(title: "Connect as… in New Tab") { sessions.connectAsRequest = ConnectAsRequest(connectionId: id, replacing: nil) })
            menu.addItem(.separator())
        }
        if !tab.pinned {
            groupItems(tab: tab, sessions: sessions).forEach(menu.addItem)
            menu.addItem(.separator())
        }
        menu.addItem(ClosureMenuItem(title: "Move Tab to New Window") { sessions.moveToWindow(tab) })
        if sessions.windowed[tab.id] != nil {
            menu.addItem(ClosureMenuItem(title: "Move Tab to Main Window") { sessions.move(tab, toWindow: nil) })
        }
        menu.addItem(.separator())
        menu.addItem(ClosureMenuItem(title: "Close Tab", handler: close))
        return menu
    }

    /// "Add to New Group" opens the new group's editor, so the user names it at once (Chrome).
    private static func groupItems(tab: TerminalTab, sessions: SessionsModel) -> [NSMenuItem] {
        var items: [NSMenuItem] = [ClosureMenuItem(title: "Add to New Group") {
            sessions.groupOp(["op": "newGroup", "tabs": [tab.id.uuidString]])
            let id = sessions.tabs.first { $0.id == tab.id }?.group
            DispatchQueue.main.async { sessions.editingGroup = id }
        }]
        let others = sessions.groups.filter { $0.id != tab.group }
        if !others.isEmpty {
            let entry = NSMenuItem(title: "Add to Group", action: nil, keyEquivalent: "")
            let sub = NSMenu(title: "Add to Group")
            for g in others {
                sub.addItem(ClosureMenuItem(title: g.name.isEmpty ? "Unnamed group" : g.name) {
                    sessions.groupOp(["op": "addToGroup", "tab": tab.id.uuidString, "group": g.id])
                })
            }
            entry.submenu = sub
            items.append(entry)
        }
        if tab.group != nil {
            items.append(ClosureMenuItem(title: "Remove from Group") { sessions.groupOp(["op": "removeFromGroup", "tab": tab.id.uuidString]) })
        }
        return items
    }
}

/// Marks a tab's frame for its menu. The strip's hosting view (`StripHost`) finds the anchor under
/// a right-click and opens its menu: inside the toolbar neither SwiftUI's `.contextMenu` nor a
/// subview catcher gets the event (SwiftUI hit-tests its own container, then the click goes up the
/// responder chain to the toolbar).
struct TabMenuAnchor: NSViewRepresentable {
    /// The menu to open, or nil when `action` runs instead (a group chip opens its editor).
    var menu: (() -> NSMenu)?
    var action: (() -> Void)?

    init(menu: @escaping () -> NSMenu) { self.menu = menu }
    init(action: @escaping () -> Void) { self.action = action }

    func makeNSView(context: Context) -> AnchorView { AnchorView(menu: menu, action: action) }
    func updateNSView(_ view: AnchorView, context: Context) { view.makeMenu = menu; view.action = action }

    final class AnchorView: NSView {
        var makeMenu: (() -> NSMenu)?
        var action: (() -> Void)?
        init(menu: (() -> NSMenu)?, action: (() -> Void)?) { makeMenu = menu; self.action = action; super.init(frame: .zero) }
        required init?(coder: NSCoder) { nil }
        /// Never a click target itself.
        override func hitTest(_ point: NSPoint) -> NSView? { nil }

        /// The anchor under a window point, searching `root`'s subviews.
        static func under(_ windowPoint: NSPoint, in root: NSView) -> AnchorView? {
            for sub in root.subviews {
                if let a = sub as? AnchorView, !a.isHiddenOrHasHiddenAncestor, a.convert(a.bounds, to: nil).contains(windowPoint) { return a }
                if let a = under(windowPoint, in: sub) { return a }
            }
            return nil
        }
    }
}
