import AppKit
import SwiftUI
import BastionRdp

/// Shows an RDP desktop in the shared remote-desktop canvas. Keys go out as set-1 scancodes.
struct RdpView: View {
    let session: RdpSession
    let isActive: Bool
    var fit: DesktopFit = .fit
    var onClosed: (String?) -> Void = { _ in }

    var body: some View {
        RemoteDesktopView(desktop: RdpDesktop(session: session), isActive: isActive, fit: fit, onClosed: onClosed)
    }
}

final class RdpDesktop: RemoteDesktop {
    private let session: RdpSession
    /// The desktop as last drawn; `frame_update` only sends what changed since.
    private var picture = Data()
    private var width = 0
    private var height = 0

    /// The pasteboard clipboard sharing reads and writes; the UI test driver swaps in a private one.
    /// Only read and set on the main thread (the desktop poll timer and the driver).
    nonisolated(unsafe) static var pasteboard: NSPasteboard = .general
    /// Pasteboard change count already handled; -1 offers the current text once connected.
    private var seenChangeCount = -1
    /// Text this adapter put on the pasteboard from the server, not offered back.
    private var fromServer: String?
    /// This session's id in the app-wide server-write tag (SEC-6).
    private let clipboardId = RdpClipboardOrigin.newSessionId()

    init(session: RdpSession) { self.session = session }

    var previewKey: ObjectIdentifier { ObjectIdentifier(session) }

    /// The server's desktop follows the tab (Display Control); servers without it keep their
    /// size and the canvas letterboxes the picture as before.
    func viewResized(width: Int, height: Int) {
        session.resize(width: UInt32(width), height: UInt32(height))
    }

    /// Text copied on the server goes onto the Mac's pasteboard; text copied on the Mac is
    /// offered to the server. Items marked concealed (password managers) are never offered, nor is
    /// text another session's server put there (`RdpClipboardOrigin`, SEC-6).
    func syncClipboard() {
        guard session.sharesClipboard() else { return }
        let pasteboard = Self.pasteboard
        if let text = session.takeRemoteClipboard() {
            pasteboard.clearContents()
            pasteboard.setString(text, forType: .string)
            fromServer = text
            seenChangeCount = pasteboard.changeCount
            RdpClipboardOrigin.markRemoteWrite(by: clipboardId, changeCount: pasteboard.changeCount)
        }
        guard pasteboard.changeCount != seenChangeCount else { return }
        seenChangeCount = pasteboard.changeCount
        // Another session's server text is never offered to this server (SEC-6).
        guard RdpClipboardOrigin.mayOffer(to: clipboardId, changeCount: seenChangeCount) else { return }
        let concealed = pasteboard.types?.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")) == true
        guard !concealed, let text = pasteboard.string(forType: .string), text != fromServer else { return }
        session.setLocalClipboard(text: text)
    }

    var closeReason: String? { session.state() == .closed ? session.closeReason() ?? "closed" : nil }

    func frame(after serial: UInt64) -> DesktopFrame? {
        guard let update = session.frameUpdate(afterSerial: serial) else { return nil }
        width = Int(update.width)
        height = Int(update.height)
        if update.full || picture.count != width * height * 4 {
            picture = update.rects.first?.bgra ?? Data(count: width * height * 4)
        } else {
            patch(update.rects)
        }
        return DesktopFrame(width: width, height: height, serial: update.serial, bgra: picture)
    }

    private func patch(_ rects: [RdpDirtyRect]) {
        let stride = width * 4
        picture.withUnsafeMutableBytes { dst in
            for rect in rects {
                let row = Int(rect.width) * 4
                rect.bgra.withUnsafeBytes { src in
                    for y in 0..<Int(rect.height) {
                        let at = (Int(rect.y) + y) * stride + Int(rect.x) * 4
                        dst.baseAddress!.advanced(by: at).copyMemory(from: src.baseAddress!.advanced(by: y * row), byteCount: row)
                    }
                }
            }
        }
    }

    func pointer(x: UInt16, y: UInt16) { session.mouseMove(x: x, y: y) }

    func button(_ button: DesktopButton, down: Bool) {
        let b: RdpPointerButton = switch button {
        case .left: .left
        case .right: .right
        case .middle: .middle
        }
        session.mouseButton(button: b, down: down)
    }

    /// Modifier keys (Mac key codes) the server currently has down.
    private var heldModifiers: Set<UInt16> = []
    /// Keys whose press went out as Unicode text; their release is not sent again.
    private var typedKeys: Set<UInt16> = []

    /// Printable characters go out as Unicode events, so the Mac input source (US, UK, …) decides
    /// the character and the server's layout or a stuck Shift cannot change it. Everything else
    /// (function, navigation, editing keys and ⌃/⌘ chords) goes out as set-1 scancodes, with the
    /// server's modifiers first brought in line with the keys actually held on this Mac.
    func key(_ event: NSEvent?, keyCode: UInt16, down: Bool) {
        guard let event else { return modifierChanged(keyCode: keyCode, down: down) }
        guard down else {
            if typedKeys.remove(keyCode) == nil { sendScancode(keyCode, down: false) }
            return
        }
        let kind = RdpKeyText.classify(characters: event.characters, flags: event.modifierFlags, keyCode: keyCode)
        syncModifiers(event.modifierFlags, pressMissing: kind == .scancode)
        switch kind {
        case .text(let text):
            liftTypingModifiers()
            session.typeText(text: text)
            typedKeys.insert(keyCode)
        case .deadKey:
            typedKeys.insert(keyCode)
        case .scancode:
            sendScancode(keyCode, down: true)
        }
    }

    func releaseAllKeys() {
        heldModifiers.removeAll()
        typedKeys.removeAll()
        session.releaseAllKeys()
    }

    private func modifierChanged(keyCode: UInt16, down: Bool) {
        // Caps Lock is applied on this Mac (the typed characters already carry it).
        guard keyCode != RdpKeyText.capsLock, RdpScancodes.map[keyCode] != nil else { return }
        // Option is the Mac's AltGr: it shapes typed characters here. A lone Alt press and release
        // on Windows opens the menu bar, so Alt goes down only with a non-text key (`syncModifiers`).
        if down && RdpScancodes.modifierFlag[keyCode] == .option { return }
        if down {
            heldModifiers.insert(keyCode)
        } else if heldModifiers.remove(keyCode) == nil, RdpScancodes.modifierFlag[keyCode] == .option {
            return
        }
        sendScancode(keyCode, down: down)
    }

    /// Releases modifiers the server holds that are no longer down here (an up event lost to a
    /// menu shortcut or a focus change), and presses ones held here that the server lacks.
    private func syncModifiers(_ flags: NSEvent.ModifierFlags, pressMissing: Bool) {
        for code in heldModifiers where !flags.contains(RdpScancodes.modifierFlag[code] ?? []) {
            heldModifiers.remove(code)
            sendScancode(code, down: false)
        }
        guard pressMissing else { return }
        for (flag, code) in RdpKeyText.leftModifier where flags.contains(flag) {
            guard !heldModifiers.contains(where: { RdpScancodes.modifierFlag[$0] == flag }) else { continue }
            heldModifiers.insert(code)
            sendScancode(code, down: true)
        }
    }

    /// Shift and Option already shaped the character on this Mac; on the server they would turn
    /// a Unicode "." into nothing useful (Alt) or trigger shortcuts, so they are released first.
    /// `syncModifiers` presses them again before the next non-text key.
    private func liftTypingModifiers() {
        for code in heldModifiers {
            let flag = RdpScancodes.modifierFlag[code]
            guard flag == .shift || flag == .option else { continue }
            heldModifiers.remove(code)
            sendScancode(code, down: false)
        }
    }

    private func sendScancode(_ keyCode: UInt16, down: Bool) {
        guard let code = RdpScancodes.map[keyCode] else { return }
        session.key(scancode: code.scancode, extended: code.extended, down: down)
    }
}
