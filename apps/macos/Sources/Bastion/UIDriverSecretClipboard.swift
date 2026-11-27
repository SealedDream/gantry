#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for the "Clear copied passwords after" setting (A3-S1), printed as text so a
/// run with the screen locked still checks them. They use a private pasteboard, never the user's.
extension Driver {
    static let secretClipboardSetting = "security.clipboard-clear-seconds"
    /// Seconds before and after the lifetime at which the copy is checked (packet: 25 s and 35 s for 30 s).
    static let secretClipboardMargin = 5.0

    /// Handles one of these steps; false when `cmd` is not one.
    func secretClipboardStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "secret-lifetime": secretLifetime(expected: arg)
        case "secret-pasteboard-setting": await secretPasteboardSetting()
        case "window-size": await windowSize(arg)
        default: return false
        }
        return true
    }

    /// `secret-lifetime <seconds>`: the lifetime a copy made now would get, the value a model
    /// opened from disk reads (what a restart sees), and whether the Settings row is offered.
    private func secretLifetime(expected: String) {
        let id = Self.secretClipboardSetting
        let seconds = SecretPasteboard.configuredLifetime.components.seconds
        let fresh = SettingsModel()
        let offered = fresh.definitions(in: "security").contains { $0.id == id }
        let ok = String(seconds) == expected && fresh.value(id) == expected && offered
        write("\(ok ? "" : "FAIL ")SECRET-LIFETIME seconds=\(seconds) from-disk=\(fresh.value(id)) offered=\(offered) expected=\(expected)")
    }

    /// `secret-pasteboard-setting`: a copy with the lifetime from the setting is still there
    /// shortly before it ends and gone shortly after; a later copy by the user is left alone.
    private func secretPasteboardSetting() async {
        let seconds = Double(SecretPasteboard.configuredLifetime.components.seconds)
        let margin = Self.secretClipboardMargin
        let secret = "a3-s1-secret"
        let pb = NSPasteboard(name: NSPasteboard.Name("bastion-ui-a3-s1-\(UUID().uuidString)"))
        SecretPasteboard.copy(secret, to: pb)
        let marked = pb.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")) == true
            && pb.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.TransientType")) == true
        await settle(seconds - margin)
        let held = pb.string(forType: .string) == secret
        await settle(2 * margin)
        let cleared = pb.string(forType: .string) == nil
        SecretPasteboard.copy(secret, to: pb)
        pb.clearContents(); pb.setString("user-copy", forType: .string)
        await settle(seconds + margin)
        let kept = pb.string(forType: .string) == "user-copy"
        pb.releaseGlobally()
        let ok = marked && held && cleared && kept
        write("\(ok ? "" : "FAIL ")SECRET-PASTEBOARD-SETTING seconds=\(Int(seconds)) marked=\(marked) held-before=\(held) cleared-after=\(cleared) later-copy-kept=\(kept)")
    }

    /// `window-size <window>|<width>x<height>`: resize a window other than the main one (Settings)
    /// and report the size it took, which its own minimum may raise.
    private func windowSize(_ arg: String) async {
        let p = arg.split(separator: "|", maxSplits: 1).map(String.init)
        let d = (p.last ?? "").split(separator: "x").compactMap { Double($0) }
        guard p.count == 2, d.count == 2, let w = findWindow(p[0]) else { return write("FAIL window-size \(arg)") }
        w.setFrame(NSRect(x: w.frame.minX, y: w.frame.maxY - d[1], width: d[0], height: d[1]), display: true)
        await settle(0.5)
        write("WINDOW-SIZE \(p[0]) \(Int(w.frame.width))x\(Int(w.frame.height))")
    }
}
#endif
