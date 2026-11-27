import AppKit
import SwiftUI

/// Builds and lays out the first sheet once, offscreen, while the app is idle after launch. The
/// first SwiftUI sheet pays for form controls, fonts and type metadata (nm-21 perf-budgets:
/// new-connection 242 ms cold, 0.2 ms after); doing it ahead keeps that off the user's click.
@MainActor
enum SheetPrewarm {
    /// Delay after the launch gate opens, so the warm-up never competes with the first frames.
    static let delay: Duration = .milliseconds(800)
    private(set) static var isDone = false

    static func run(model: LibraryModel, credentials: CredentialsModel, sessions: SessionsModel) async {
        guard !isDone else { return }
        isDone = true
        try? await Task.sleep(for: delay)
        let host = NSHostingView(rootView: AddConnectionView(proto: "ssh").environment(model).environment(credentials).environment(sessions))
        host.frame = NSRect(x: 0, y: 0, width: 520, height: 480)
        host.layoutSubtreeIfNeeded()
        _ = host.fittingSize
        await presentOffscreen(host)
    }

    /// Owner 2026-11-07 (nm-22): the form alone left most of the first sheet's cost in AppKit
    /// (window creation, titlebar, layout). Show the warmed form once in an invisible, offscreen
    /// window that can't take focus: nothing is seen and the main window stays key.
    private static func presentOffscreen(_ host: NSView) async {
        // Owner feedback 2026-11-07 (#705 follow-up): a sheet presentation made the window server
        // animate the transparent parent and sheet from their offscreen frame across the display.
        // No sheet now: the form is shown in one transparent, titled window (window creation,
        // titlebar and layout are what the first sheet paid for) that never leaves its offscreen
        // frame, then ordered out.
        let window = PrewarmWindow(contentRect: NSRect(x: -20_000, y: -20_000, width: host.frame.width, height: host.frame.height),
                                   styleMask: [.titled], backing: .buffered, defer: false)
        window.contentView = host
        // Setting the content resizes the window around it: put it back off every screen.
        window.setFrameOrigin(NSPoint(x: -20_000, y: -20_000))
        window.ignoresMouseEvents = true
        window.collectionBehavior = [.transient, .ignoresCycle]
        window.orderBack(nil)
        window.displayIfNeeded()
        warmTextEditing(in: window)
        try? await Task.sleep(for: .milliseconds(50))
        window.orderOut(nil)
    }

    /// The first inline edit of the process (the tree's rename, New Folder) set up the text system
    /// and field editor: 407 ms on the first New Folder, 3.7 ms after (2026-11-15). The same steps
    /// here, in the hidden window that can't become key, so focus never moves.
    private static func warmTextEditing(in window: NSWindow) {
        let field = NSTextField(string: "New Folder")
        field.isEditable = true
        field.frame = NSRect(x: 0, y: 0, width: 160, height: 22)
        window.contentView?.addSubview(field)
        window.makeFirstResponder(field)
        field.currentEditor()?.selectAll(nil)
        window.makeFirstResponder(nil)
        field.removeFromSuperview()
    }
}

/// A window that is never seen: transparent, unanimated, no shadow, and its frame is never
/// pulled back onto a screen (the default for titled windows).
final class PrewarmWindow: NSWindow {
    override init(contentRect: NSRect, styleMask: NSWindow.StyleMask, backing: NSWindow.BackingStoreType, defer flag: Bool) {
        super.init(contentRect: contentRect, styleMask: styleMask, backing: backing, defer: flag)
        alphaValue = 0
        hasShadow = false
        animationBehavior = .none
        isReleasedWhenClosed = false
        isExcludedFromWindowsMenu = true
    }

    override func constrainFrameRect(_ frameRect: NSRect, to screen: NSScreen?) -> NSRect { frameRect }
    override var canBecomeKey: Bool { false }
    override var canBecomeMain: Bool { false }
}

/// Draws a line in the terminal font offscreen once after launch. The first terminal draw of the
/// process loaded the font's CoreText tables (`TBaseFont::SupportsConnectedLanguage`, ~16 ms of
/// the nm-24 first-shell stall); this takes the same `NSAttributedString.draw` path ahead of it.
@MainActor
enum TerminalFontPrewarm {
    private(set) static var isDone = false
    static let sample = "mo@host ~ % ls -la │ ▶ 0123456789"

    static func run(family: String, size: CGFloat) {
        guard !isDone else { return }
        isDone = true
        let (regular, bold) = TerminalFonts.fonts(family: family, size: size)
        guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: 640, pixelsHigh: 48, bitsPerSample: 8,
                                         samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                         bytesPerRow: 0, bitsPerPixel: 0),
              let context = NSGraphicsContext(bitmapImageRep: rep) else { return }
        NSGraphicsContext.saveGraphicsState()
        NSGraphicsContext.current = context
        for (i, font) in [regular, bold].enumerated() {
            NSAttributedString(string: sample, attributes: [.font: font, .foregroundColor: NSColor.white, .ligature: 0])
                .draw(at: NSPoint(x: 0, y: CGFloat(i) * 20))
        }
        NSGraphicsContext.restoreGraphicsState()
    }
}
