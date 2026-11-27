#if BASTION_TEST_HOOKS
import AppKit

/// UI driver steps for MAC-FULLSCREEN: enter and leave full screen the ways a user does (the green
/// window button, View › Enter Full Screen, ⌃⌘F) and report the window's real state. Unlike
/// `fullscreen on|off`, these never add `.fullScreenPrimary` themselves, so a window that cannot go
/// full screen fails here. A connection's own Full Screen runs through `menu "<row> > Full Screen"`.
extension Driver {
    /// Handles one of these steps; false when `cmd` is not one.
    func fullScreenStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "fs-state": write(fullScreenState())
        case "fs-via": fullScreenVia(arg)
        case "fs-expect": await fullScreenExpect(arg)
        case "fs-frame": fullScreenFrame(arg)
        case "fs-toolbar":
            // Full screen keeps the toolbar shown (no auto-hide): the session header sits below it.
            let opts = NSApp.currentSystemPresentationOptions
            let hides = opts.contains(.autoHideToolbar)
            let full = window?.styleMask.contains(.fullScreen) == true
            write("\(full && hides ? "FAIL " : "")FS-TOOLBAR full=\(full) autoHideToolbar=\(hides) options=\(opts.rawValue)")
        default: return false
        }
        return true
    }

    /// `FS-STATE full=on|off primary=yes|no zoom-button=enabled|disabled|none frame=WxH screen=WxH menu=<title>(on|off)|none`
    func fullScreenState() -> String {
        guard let w = window else { return "FAIL FS-STATE: no window" }
        let full = w.styleMask.contains(.fullScreen)
        let primary = w.collectionBehavior.contains(.fullScreenPrimary) ? "yes" : "no"
        let zoom = w.standardWindowButton(.zoomButton).map { $0.isEnabled ? "enabled" : "disabled" } ?? "none"
        let screen = w.screen?.frame.size ?? .zero
        let menu = Self.fullScreenMenuItem().map { "\($0.title.replacingOccurrences(of: " ", with: "_"))(\(w.validateMenuItem($0) ? "on" : "off"))" } ?? "none"
        return String(format: "FS-STATE full=%@ primary=%@ zoom-button=%@ frame=%.0fx%.0f screen=%.0fx%.0f menu=%@",
                      full ? "on" : "off", primary, zoom, w.frame.width, w.frame.height, screen.width, screen.height, menu)
    }

    /// The main menu's toggleFullScreen: item (AppKit adds it to the View menu).
    static func fullScreenMenuItem() -> NSMenuItem? {
        func find(_ menu: NSMenu) -> NSMenuItem? {
            for item in menu.items {
                if item.action == #selector(NSWindow.toggleFullScreen(_:)) { return item }
                if let sub = item.submenu, let hit = find(sub) { return hit }
            }
            return nil
        }
        return NSApp.mainMenu.flatMap(find)
    }

    /// `fs-via green|menu|key`: one user path; `fs-expect` then checks the result.
    func fullScreenVia(_ arg: String) {
        guard let w = window else { return write("FAIL FS-VIA \(arg): no window") }
        switch arg {
        case "green":
            guard let b = w.standardWindowButton(.zoomButton) else { return write("FAIL FS-VIA green: no zoom button") }
            // In full screen the button sits in the title bar AppKit reveals on hover (reported as
            // disabled while hidden); its click is the same action, so send that.
            if w.styleMask.contains(.fullScreen) { w.toggleFullScreen(b) } else {
                guard b.isEnabled else { return write("FAIL FS-VIA green: zoom button disabled") }
                b.performClick(nil)
            }
        case "menu":
            guard let item = Self.fullScreenMenuItem() else { return write("FAIL FS-VIA menu: no Enter Full Screen item") }
            guard w.validateMenuItem(item) else { return write("FAIL FS-VIA menu: item disabled") }
            // The item targets the first responder; send it to this window as a click would.
            NSApp.sendAction(#selector(NSWindow.toggleFullScreen(_:)), to: w, from: item)
        case "key":
            appKey("ctrl+cmd+f")
        default:
            return write("FAIL FS-VIA \(arg): unknown path")
        }
        write("FS-VIA \(arg)")
    }

    /// `fs-frame WxH`: after leaving full screen the window is back at its size (within 2 pt).
    func fullScreenFrame(_ arg: String) {
        guard let w = window else { return write("FAIL FS-FRAME: no window") }
        let want = arg.split(separator: "x").compactMap { Double($0) }
        guard want.count == 2 else { return write("FAIL FS-FRAME \(arg): want WxH") }
        let ok = abs(w.frame.width - want[0]) <= 2 && abs(w.frame.height - want[1]) <= 2
        write(String(format: "%@FS-FRAME want %@ got %.0fx%.0f", ok ? "" : "FAIL ", arg, w.frame.width, w.frame.height))
    }

    /// `fs-expect on|off`: waits up to 6 s for the transition, then logs the state.
    func fullScreenExpect(_ arg: String) async {
        guard let w = window else { return write("FAIL FS-EXPECT: no window") }
        let want = arg == "on"
        for _ in 0..<60 where w.styleMask.contains(.fullScreen) != want { await settle(0.1) }
        await settle(1.0)
        let ok = w.styleMask.contains(.fullScreen) == want
        write("\(ok ? "" : "FAIL ")FS-EXPECT \(arg) -> \(fullScreenState())")
    }
}
#endif
