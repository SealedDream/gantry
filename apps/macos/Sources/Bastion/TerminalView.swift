import AppKit
import SwiftUI
import BastionCore

/// Draws a core `Terminal` grid and turns keyboard, paste, scroll and resize into terminal
/// input. Emulation happens in the Rust core (alacritty_terminal); this view only renders the
/// snapshot it gets and redraws when the snapshot's generation moves.
final class TerminalNSView: NSView {
    let terminal: Terminal
    private var screen: TermScreen?
    private var lastGeneration: UInt64 = .max
    private var wake: TerminalWake?
    private var font: NSFont
    private var boldFont: NSFont
    private var cellSize: CGSize
    /// Family, size and ligatures in use (`terminal.font-*`, a connection's own, ⌘+/⌘− zoom).
    private(set) var fontChoice: TerminalFontView
    /// `terminal.cursor-style`: block, bar or underline.
    var cursorStyle = "block" { didSet { if cursorStyle != oldValue { needsDisplay = true } } }
    /// `terminal.bell`: visual, sound, both or off.
    var bellStyle = "visual"
    /// `terminal.copy-on-select`.
    var copyOnSelect = false
    /// Bells rung so far (UI driver).
    private(set) var bellCount = 0
    private var gridSize: (cols: UInt16, rows: UInt16) = (0, 0)
    var onTitle: ((String?) -> Void)?
    var onExit: (() -> Void)?
    /// Connection state of a supervised SSH terminal ("Reconnecting (2)", nil while connected).
    var onLinkStatus: ((String?) -> Void)?
    /// Theme id and revisions last applied, so SwiftUI updates do not re-apply it.
    var appliedTheme: String?
    /// `terminal.scrollback` last applied.
    var appliedScrollback: UInt32?
    /// Bytes the user typed or pasted here, after they went to this terminal (broadcast input).
    var onInput: (([UInt8]) -> Void)?
    /// A program's OSC 52 copy request (already filtered by the clipboard policy).
    var onClipboard: ((ClipboardRequestView) -> Void)?
    private var linkStatus: String?
    var onFocus: (() -> Void)?
    /// Set for the focused pane of the visible tab; only that view takes first responder.
    var wantsFocus = false {
        didSet { if wantsFocus && !oldValue { DispatchQueue.main.async { [weak self] in self?.takeFocus() } } }
    }

    init(terminal: Terminal, font choice: TerminalFontView) {
        self.terminal = terminal
        fontChoice = choice
        (font, boldFont, cellSize) = Self.metrics(choice)
        super.init(frame: .zero)
        wantsLayer = true
        setAccessibilityRole(.textArea)
        setAccessibilityLabel("Terminal")
    }

    @available(*, unavailable) required init?(coder: NSCoder) { fatalError("not used") }

    /// `draw(_:)` fills every pixel with the theme's background (always opaque), so Core Animation
    /// need not clear the surface on the main thread before each draw (MAC-STALLS profile: about
    /// 23 ms of clearing on main over one profiled run).
    override var isOpaque: Bool { true }

    private static func metrics(_ choice: TerminalFontView) -> (NSFont, NSFont, CGSize) {
        let (regular, bold) = TerminalFonts.fonts(family: choice.family, size: CGFloat(choice.size))
        return (regular, bold, TerminalFonts.cellSize(regular))
    }

    /// Window coordinates of a cell's centre (UI driver); a negative row counts from the bottom.
    func windowPoint(row: Int, col: Int) -> NSPoint {
        let row = row < 0 ? Int(gridSize.rows) + row : row
        return convert(NSPoint(x: gridInset.width + (CGFloat(col) + 0.5) * cellSize.width, y: gridInset.height + (CGFloat(row) + 0.5) * cellSize.height), to: nil)
    }

    /// A cell's rectangle in view coordinates, padding included (UI driver).
    func cellRect(row: Int, col: Int) -> NSRect {
        NSRect(x: gridInset.width + CGFloat(col) * cellSize.width, y: gridInset.height + CGFloat(row) * cellSize.height,
               width: cellSize.width, height: cellSize.height)
    }

    var gridDescription: String { "\(gridSize.cols)x\(gridSize.rows)" }

    var fontSize: CGFloat { font.pointSize }
    var fontFamily: String { font.familyName ?? fontChoice.family }

    /// A new font: new metrics, then the grid is recomputed for the same frame.
    func setFont(_ choice: TerminalFontView) {
        guard choice != fontChoice else { return }
        let resize = choice.family != fontChoice.family || choice.size != fontChoice.size
        fontChoice = choice
        if resize {
            (font, boldFont, cellSize) = Self.metrics(choice)
            gridSize = (0, 0)
            setFrameSize(frame.size)
        }
        needsDisplay = true
    }

    override var acceptsFirstResponder: Bool { true }
    override var isFlipped: Bool { true }

    /// False while another tab covers this one: every tab stays mounted and only the selected one
    /// shows (opacity 0). Hidden, the view updates its layer instead of drawing, so AppKit keeps no
    /// backing store: each tab kept a window-sized Retina one, about 25 MB of IOSurface per tab
    /// (MAC-MEMORY). Not `isHidden`: hiding the focused view moved first responder through the
    /// window and rebuilt the toolbar's items on every tab switch (22 → 77 ms). The core screen is
    /// still followed (title, bell, exit); shown again, it draws once.
    var isShown = true {
        didSet { if isShown != oldValue { needsDisplay = true } }
    }

    override var wantsUpdateLayer: Bool { !isShown }

    /// Hidden only (`wantsUpdateLayer`): drop the drawn contents.
    override func updateLayer() { layer?.contents = nil }

    override func viewWillMove(toWindow newWindow: NSWindow?) {
        if newWindow == nil { releaseDrawnSurface() }
        super.viewWillMove(toWindow: newWindow)
    }

    /// Leaving the window (a closed tab, or one moving to another window), while the window can
    /// still commit the change. AppKit draws this view into its own content sublayer, not into
    /// `layer`, as a terminal-sized half-float surface (8 bytes a pixel, about 29 MB on Retina),
    /// rendered asynchronously. Left to the view's teardown, that surface sometimes stayed charged
    /// to the app for dozens of tab cycles after the view was gone (MAC-MEM-30MB). The next draw
    /// fills the sublayer again.
    private func releaseDrawnSurface() {
        layer?.sublayers?.forEach { $0.contents = nil }
    }

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        wake?.stop()
        wake = nil
        guard window != nil else {
            // Out of the window: drop the screen snapshot (about 1 MB per window-sized grid) and
            // the layer's own contents, so a view something still holds for a while after its tab
            // closed does not keep them (MAC-MEMORY-GROWTH). The drawn surface went in
            // `viewWillMove(toWindow:)`. Both come back when it returns.
            screen = nil
            lastGeneration = .max
            layer?.contents = nil
            return
        }
        // Event-driven: redraw when the core says the screen changed, not on a frame timer.
        wake = TerminalWake(terminal: terminal) { [weak self] in self?.refresh() }
        // Focus is taken here, inside the layout pass. Deferring it past the frame (#1485, for the
        // first shell's stall) let the connect sheet's end hand focus back to the library: keys typed
        // right after connecting were lost (final regression 2026-11-26, m12 and reconnect suites).
        if wantsFocus { takeFocus() }
        refresh()
    }

    deinit { wake?.stop() }

    /// UI driver: called after each refresh with the snapshot about to be drawn.
    static var didRefresh: ((TermScreen) -> Void)?

    override func removeFromSuperview() {
        wake?.stop()
        wake = nil
        super.removeFromSuperview()
    }

    private func takeFocus() {
        guard wantsFocus, let window, window.firstResponder !== self else { return }
        window.makeFirstResponder(self)
    }

    private func refresh() {
        let gen = terminal.generation()
        guard gen != lastGeneration else { return }
        let wasAlive = screen?.alive ?? true
        let s = terminal.fastScreen()
        lastGeneration = s.generation
        if s.title != screen?.title { onTitle?(s.title) }
        if let req = terminal.takeClipboardRequest() { onClipboard?(req) }
        if terminal.takeBell() { ringBell() }
        let status = terminal.linkStatus()
        if status != linkStatus { linkStatus = status; onLinkStatus?(status) }
        screen = s
        needsDisplay = true
        Self.didRefresh?(s)
        if wasAlive && !s.alive { onExit?() }
    }

    override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        guard newSize.width > 0, newSize.height > 0 else { return }
        let inset = gridInset
        let cols = UInt16(max(2, min(1000, Int((newSize.width - 2 * inset.width) / cellSize.width))))
        let rows = UInt16(max(1, min(1000, Int((newSize.height - 2 * inset.height) / cellSize.height))))
        guard cols != gridSize.cols || rows != gridSize.rows else { return }
        gridSize = (cols, rows)
        try? terminal.resize(cols: cols, rows: rows)
    }

    /// `terminal.bell`: a short flash over the view, the system alert sound, or nothing.
    private func ringBell() {
        bellCount += 1
        switch bellStyle {
        case "sound": QuietLaunch.beep()
        case "visual", "both":
            if bellStyle == "both" { QuietLaunch.beep() }
            guard let layer else { return }
            let flash = CALayer()
            flash.frame = layer.bounds
            flash.backgroundColor = NSColor.white.withAlphaComponent(0.18).cgColor
            layer.addSublayer(flash)
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.bellFlash) { flash.removeFromSuperlayer() }
        default: break
        }
    }

    private static let bellFlash: TimeInterval = 0.12

    /// Inner padding around the grid (UI-03): 8 pt left and right, 4 pt top and bottom at the default
    /// 13 pt font, scaled with the text size. Painted in the theme background; clicks there hit the edge cell.
    private static let paddingAtDefault = NSSize(width: 8, height: 4)
    private static let defaultFontSize: CGFloat = 13
    var gridInset: NSSize {
        let scale = font.pointSize / Self.defaultFontSize
        return NSSize(width: (Self.paddingAtDefault.width * scale).rounded(), height: (Self.paddingAtDefault.height * scale).rounded())
    }

    // MARK: Drawing

    override func draw(_ dirtyRect: NSRect) {
        guard let s = screen else {
            NSColor(rgb: 0x1c1c1e).setFill()
            bounds.fill()
            return
        }
        NSColor(rgb: s.background).setFill()
        bounds.fill()
        selectionBackground = Self.selection(over: s.background)
        let inset = gridInset
        NSGraphicsContext.current?.cgContext.translateBy(x: inset.width, y: inset.height)
        let dirty = dirtyRect.offsetBy(dx: -inset.width, dy: -inset.height)
        let cols = Int(s.cols)
        for row in 0..<Int(s.rows) {
            let y = CGFloat(row) * cellSize.height
            guard y < dirty.maxY, y + cellSize.height > dirty.minY else { continue }
            drawRow(s, row: row, cols: cols, y: y)
        }
        if s.cursorVisible && s.alive { drawCursor(s) }
        if !markedText.isEmpty { drawMarkedText(s) }
    }

    /// IME composition shown over the cursor cell, underlined, until the input method commits it.
    private func drawMarkedText(_ s: TermScreen) {
        let text = NSAttributedString(string: markedText, attributes: [
            .font: font, .foregroundColor: NSColor(rgb: s.background), .underlineStyle: NSUnderlineStyle.single.rawValue,
        ])
        let origin = NSPoint(x: CGFloat(s.cursorCol) * cellSize.width, y: CGFloat(s.cursorRow) * cellSize.height)
        NSColor(rgb: s.cells[Int(s.cursorRow) * Int(s.cols) + Int(s.cursorCol)].fg).setFill()
        NSRect(origin: origin, size: NSSize(width: ceil(text.size().width), height: cellSize.height)).fill()
        text.draw(at: origin)
    }

    /// The app accent at 40 % over the theme background, so selected text keeps its own colour and stays readable.
    private var selectionBackground: UInt32 = 0x264f78
    private static let selectionOpacity: CGFloat = 0.4
    static func selection(over background: UInt32) -> UInt32 {
        guard let accent = NSColor.controlAccentColor.usingColorSpace(.sRGB) else { return 0x264f78 }
        let a = selectionOpacity
        func mix(_ c: CGFloat, _ shift: UInt32) -> UInt32 {
            let b = CGFloat((background >> shift) & 0xff) / 255
            return UInt32(((c * a + b * (1 - a)) * 255).rounded()) << shift
        }
        return mix(accent.redComponent, 16) | mix(accent.greenComponent, 8) | mix(accent.blueComponent, 0)
    }
    static let matchBackground: UInt32 = 0x8a6d1d

    /// Search hits win over the selection, which wins over the program's own colour.
    private func background(_ c: TermCell) -> UInt32 {
        c.matched ? Self.matchBackground : (c.selected ? selectionBackground : c.bg)
    }

    /// Backgrounds per run, then text: ASCII runs of one style in a single draw, everything else
    /// (wide or combining characters) positioned on its own cell so columns stay aligned.
    private func drawRow(_ s: TermScreen, row: Int, cols: Int, y: CGFloat) {
        let base = row * cols
        var col = 0
        while col < cols {
            let bg = background(s.cells[base + col])
            var end = col + 1
            while end < cols, background(s.cells[base + end]) == bg { end += 1 }
            if bg != s.background {
                NSColor(rgb: bg).setFill()
                NSRect(x: CGFloat(col) * cellSize.width, y: y, width: CGFloat(end - col) * cellSize.width, height: cellSize.height).fill()
            }
            col = end
        }
        col = 0
        while col < cols {
            let cell = s.cells[base + col]
            if cell.text.isEmpty || cell.text == " " { col += 1; continue }
            var end = col + 1
            if cell.text.utf8.count == 1 {
                while end < cols, sameStyleAscii(s.cells[base + end], cell) { end += 1 }
                let text = (col..<end).map { s.cells[base + $0].text }.joined()
                NSAttributedString(string: text, attributes: attributes(cell)).draw(at: NSPoint(x: CGFloat(col) * cellSize.width, y: y))
            } else {
                // A wide character's second cell is an empty spacer.
                let span = col + 1 < cols && s.cells[base + col + 1].text.isEmpty ? 2 : 1
                drawGlyph(cell, at: NSRect(x: CGFloat(col) * cellSize.width, y: y, width: CGFloat(span) * cellSize.width, height: cellSize.height),
                          cells: span, nextIsBlank: col + span < cols && s.cells[base + col + span].text == " ")
            }
            col = end
        }
    }

    /// One non-ASCII cell: shapes for box drawing, blocks and Powerline; icons scaled into their
    /// cells; other text (CJK, emoji, accented letters) through the font with fallback.
    private func drawGlyph(_ cell: TermCell, at rect: NSRect, cells: Int, nextIsBlank: Bool) {
        let color = NSColor(rgb: cell.fg)
        switch TerminalFonts.glyphClass(cell.text) {
        case .boxDrawing, .block, .powerline:
            let one = NSRect(origin: rect.origin, size: cellSize)
            if CellGlyphs.draw(cell.text, in: one, color: color) { return }
        case .icon:
            return drawIcon(cell, in: rect, cells: cells, nextIsBlank: nextIsBlank)
        case .text:
            break
        }
        NSAttributedString(string: cell.text, attributes: attributes(cell)).draw(at: rect.origin)
    }

    /// Nerd Font icons: drawn at their natural size when that fits (one cell, or two when the
    /// next cell is blank, as Starship leaves it), else scaled down to fit and centred.
    private func drawIcon(_ cell: TermCell, in rect: NSRect, cells: Int, nextIsBlank: Bool) {
        var attrs = attributes(cell)
        let natural = NSAttributedString(string: cell.text, attributes: attrs).size()
        let room = CGFloat(nextIsBlank && cells == 1 ? 2 : cells) * cellSize.width
        if natural.width > room, let f = attrs[.font] as? NSFont {
            attrs[.font] = NSFont(descriptor: f.fontDescriptor, size: f.pointSize * room / natural.width) ?? f
        }
        let text = NSAttributedString(string: cell.text, attributes: attrs)
        let size = text.size()
        let x = rect.minX + max(0, (min(room, max(rect.width, size.width)) - size.width) / 2)
        text.draw(at: NSPoint(x: x, y: rect.minY + (cellSize.height - size.height) / 2))
    }

    private func sameStyleAscii(_ a: TermCell, _ b: TermCell) -> Bool {
        a.text.utf8.count == 1 && a.fg == b.fg && a.bold == b.bold && a.underline == b.underline && a.italic == b.italic
    }

    private func attributes(_ c: TermCell) -> [NSAttributedString.Key: Any] {
        var a: [NSAttributedString.Key: Any] = [.font: c.bold ? boldFont : font, .foregroundColor: NSColor(rgb: c.fg),
                                                .ligature: fontChoice.ligatures ? 1 : 0]
        if c.underline { a[.underlineStyle] = NSUnderlineStyle.single.rawValue }
        if c.italic { a[.obliqueness] = 0.15 }
        return a
    }

    private func drawCursor(_ s: TermScreen) {
        let rect = NSRect(x: CGFloat(s.cursorCol) * cellSize.width, y: CGFloat(s.cursorRow) * cellSize.height,
                          width: cellSize.width, height: cellSize.height)
        let cell = s.cells[Int(s.cursorRow) * Int(s.cols) + Int(s.cursorCol)]
        NSColor(rgb: cell.fg).withAlphaComponent(0.85).set()
        let focused = window?.firstResponder === self
        switch cursorStyle {
        case "bar" where focused: return NSRect(x: rect.minX, y: rect.minY, width: max(1, (cellSize.width / 6).rounded()), height: rect.height).fill()
        case "underline" where focused: return NSRect(x: rect.minX, y: rect.maxY - max(1, (cellSize.height / 10).rounded()), width: rect.width, height: max(1, (cellSize.height / 10).rounded())).fill()
        default: break
        }
        if focused {
            rect.fill()
            NSAttributedString(string: cell.text, attributes: [.font: font, .foregroundColor: NSColor(rgb: cell.bg)]).draw(at: rect.origin)
        } else {
            NSBezierPath(rect: rect.insetBy(dx: 0.5, dy: 0.5)).stroke()
        }
    }

    // MARK: Input

    /// Text the input method is composing (Japanese, Chinese, dead keys), drawn at the cursor.
    private var markedText = ""
    /// The key being interpreted, for `doCommand(by:)` to fall back to its terminal encoding.
    private var interpretingEvent: NSEvent?

    override func keyDown(with event: NSEvent) {
        let appCursor = screen?.appCursor ?? false
        // Scrollback keys stay in the app (Shift-Page Up as in xterm and Native Windows, ⌘Home/End as in Terminal).
        if let lines = ScrollKeys.lines(keyCode: event.keyCode, flags: event.modifierFlags, pageRows: Int(gridSize.rows)) {
            terminal.scroll(lines: lines)
            return
        }
        if event.modifierFlags.contains(.command) { return super.keyDown(with: event) }
        // Arrows, Return, Ctrl-letter and friends go straight to the program unless an input method
        // is composing; text goes through the input method so IMEs and dead keys work.
        if !hasMarkedText(), let bytes = KeyEncoder.controlBytes(for: event, appCursor: appCursor) {
            return send(bytes)
        }
        interpretingEvent = event
        interpretKeyEvents([event])
        interpretingEvent = nil
    }

    private func send(_ bytes: [UInt8]) {
        try? terminal.write(bytes: Data(bytes))
        onInput?(bytes)
    }

    @objc func paste(_ sender: Any?) {
        guard let text = NSPasteboard.general.string(forType: .string) else { return }
        guard Self.needsPasteConfirmation(text, bracketed: terminal.bracketedPaste()) else {
            try? terminal.paste(text: text)
            onInput?(Array(text.utf8))
            return
        }
        // Without bracketed paste every newline runs as Return, so a multi-line paste executes lines.
        let lines = text.split(whereSeparator: \.isNewline).count
        let alert = NSAlert()
        alert.messageText = "Paste \(lines) lines?"
        alert.informativeText = "This program did not enable bracketed paste, so each line will run as a command."
        alert.addButton(withTitle: "Paste")
        alert.addButton(withTitle: "Cancel")
        guard let window else { return }
        alert.beginSheetModal(for: window) { [terminal] response in
            if response == .alertFirstButtonReturn { try? terminal.paste(text: text); self.onInput?(Array(text.utf8)) }
        }
    }

    /// Multi-line text needs confirmation unless the program bracketed the paste.
    static func needsPasteConfirmation(_ text: String, bracketed: Bool) -> Bool {
        !bracketed && text.trimmingCharacters(in: .newlines).contains(where: \.isNewline)
    }

    /// Whether this mouse event goes to the program: it enabled mouse mode and Shift is not held
    /// (Shift keeps local selection, as in xterm).
    private func reportsMouse(_ event: NSEvent) -> Bool {
        !event.modifierFlags.contains(.shift) && terminal.mouseReporting()
    }

    @discardableResult
    private func report(_ button: MouseButtonView, _ action: MouseActionView, _ event: NSEvent) -> Bool {
        let (row, col) = cell(at: event)
        let flags = event.modifierFlags
        return (try? terminal.mouse(button: button, action: action, row: row, col: col,
                                    shift: false, alt: flags.contains(.option), ctrl: flags.contains(.control))) ?? false
    }

    /// A press sent to the program; its drags and release follow it there even if Shift changes.
    private var mouseButtonDown: MouseButtonView?

    override func scrollWheel(with event: NSEvent) {
        if reportsMouse(event) {
            let lines = Int((event.scrollingDeltaY / (event.hasPreciseScrollingDeltas ? cellSize.height : 1)).rounded())
            for _ in 0..<abs(lines) { report(lines > 0 ? .wheelUp : .wheelDown, .press, event) }
            return
        }
        let lines = Int32((event.scrollingDeltaY / (event.hasPreciseScrollingDeltas ? cellSize.height : 1)).rounded())
        if lines != 0 { terminal.scroll(lines: lines) }
    }

    private var dragged = false

    /// Viewport cell under a mouse event, clamped to the grid.
    private func cell(at event: NSEvent) -> (row: UInt16, col: UInt16) {
        let inset = gridInset
        let p = convert(event.locationInWindow, from: nil).applying(CGAffineTransform(translationX: -inset.width, y: -inset.height))
        let col = max(0, Int(p.x / cellSize.width)), row = max(0, Int(p.y / cellSize.height))
        return (UInt16(min(row, Int(gridSize.rows) - 1).clamped), UInt16(min(col, Int(gridSize.cols) - 1).clamped))
    }

    override func mouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        if event.modifierFlags.contains(.command), openURL(at: event) { return }
        if reportsMouse(event) { return press(.left, event) }
        let (row, col) = cell(at: event)
        dragged = false
        terminal.selectStart(row: row, col: col, clicks: UInt8(min(event.clickCount, 3)))
    }

    override func mouseDragged(with event: NSEvent) {
        if let button = mouseButtonDown { report(button, .motion, event); return }
        dragged = true
        let (row, col) = cell(at: event)
        terminal.selectExtend(row: row, col: col)
    }

    override func mouseUp(with event: NSEvent) {
        if release(event) { return }
        // A plain click (no drag) places nothing to copy.
        if !dragged && event.clickCount == 1 { return terminal.clearSelection() }
        if copyOnSelect, let text = terminal.selectionText() { TerminalClipboard.copy(text) }
    }

    /// ⌘-click: opens the http(s) URL under the pointer in the default browser. The core only
    /// returns http and https URLs; the scheme is checked again before anything opens.
    private func openURL(at event: NSEvent) -> Bool {
        lastOpenedURL = nil
        let (row, col) = cell(at: event)
        guard let text = terminal.urlAt(row: row, col: col), let url = Self.openableURL(text) else { return false }
        lastOpenedURL = text
        if openURLs { NSWorkspace.shared.open(url) }
        return true
    }

    static func openableURL(_ text: String) -> URL? {
        guard let url = URL(string: text), let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme), url.host != nil else { return nil }
        return url
    }

    /// The last URL a ⌘-click resolved (UI driver); `openURLs` false keeps the driver from launching a browser.
    private(set) var lastOpenedURL: String?
    var openURLs = true

    override func flagsChanged(with event: NSEvent) {
        super.flagsChanged(with: event)
        // A pointing hand while ⌘ is held tells the user URLs are clickable.
        if event.modifierFlags.contains(.command) { NSCursor.pointingHand.set() } else { NSCursor.iBeam.set() }
    }

    @objc override func selectAll(_ sender: Any?) {
        terminal.selectAll()
        if copyOnSelect, let text = terminal.selectionText() { TerminalClipboard.copy(text) }
    }

    private func press(_ button: MouseButtonView, _ event: NSEvent) {
        terminal.clearSelection()
        mouseButtonDown = button
        report(button, .press, event)
    }

    /// Sends the release of a reported press; false when the press was a local selection.
    private func release(_ event: NSEvent) -> Bool {
        guard let button = mouseButtonDown else { return false }
        mouseButtonDown = nil
        report(button, .release, event)
        return true
    }

    override func rightMouseDown(with event: NSEvent) {
        guard reportsMouse(event) else { return super.rightMouseDown(with: event) }
        press(.right, event)
    }

    override func rightMouseDragged(with event: NSEvent) {
        if let button = mouseButtonDown { report(button, .motion, event) }
    }

    override func rightMouseUp(with event: NSEvent) {
        if !release(event) { super.rightMouseUp(with: event) }
    }

    override func otherMouseDown(with event: NSEvent) {
        if reportsMouse(event) { press(.middle, event) }
    }

    override func otherMouseDragged(with event: NSEvent) {
        if let button = mouseButtonDown { report(button, .motion, event) }
    }

    override func otherMouseUp(with event: NSEvent) {
        _ = release(event)
    }

    /// Hover reports for any-event tracking (DECSET 1003); the core drops them in other modes.
    override func mouseMoved(with event: NSEvent) {
        if mouseButtonDown == nil, reportsMouse(event) { report(.none, .motion, event) }
    }

    override func updateTrackingAreas() {
        super.updateTrackingAreas()
        trackingAreas.forEach(removeTrackingArea)
        addTrackingArea(NSTrackingArea(rect: .zero, options: [.mouseMoved, .activeInKeyWindow, .inVisibleRect], owner: self))
    }

    @objc func copy(_ sender: Any?) {
        guard let text = terminal.selectionText() else { return QuietLaunch.beep() }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    override func becomeFirstResponder() -> Bool { needsDisplay = true; onFocus?(); return true }
    override func resignFirstResponder() -> Bool { needsDisplay = true; return true }
}

/// Maps key events to the byte sequences an xterm-compatible program expects.
/// Keys that scroll the view through history instead of reaching the program; positive is up.
/// ⇧Page Up/Down and ⌘Page Up/Down a page, ⌘↑/⌘↓ a line, ⌘Home/⌘End to the top or bottom.
enum ScrollKeys {
    /// Far enough to reach either end of any scrollback (the core clamps).
    static let toEnd: Int32 = 1_000_000
    static let pageUp: UInt16 = 0x74, pageDown: UInt16 = 0x79, home: UInt16 = 0x73, end: UInt16 = 0x77, up: UInt16 = 0x7E, down: UInt16 = 0x7D

    static func lines(keyCode: UInt16, flags: NSEvent.ModifierFlags, pageRows: Int) -> Int32? {
        let mods = flags.intersection([.command, .shift, .option, .control])
        let page = Int32(max(1, pageRows - 1))
        switch (keyCode, mods) {
        case (pageUp, .shift), (pageUp, .command): return page
        case (pageDown, .shift), (pageDown, .command): return -page
        case (up, .command): return 1
        case (down, .command): return -1
        case (home, .command): return toEnd
        case (end, .command): return -toEnd
        default: return nil
        }
    }
}

enum KeyEncoder {
    static func bytes(for event: NSEvent, appCursor: Bool) -> [UInt8]? {
        if event.modifierFlags.contains(.command) { return nil }  // menu shortcuts (copy, paste, close tab)
        if let bytes = controlBytes(for: event, appCursor: appCursor) { return bytes }
        guard let chars = event.characters, !chars.isEmpty else { return nil }
        return Array(chars.utf8)
    }

    /// Keys that are not text: editing and cursor keys, and Ctrl combinations. Nil for text,
    /// which goes through the input method instead.
    static func controlBytes(for event: NSEvent, appCursor: Bool) -> [UInt8]? {
        let flags = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        if flags.contains(.command) { return nil }
        let csi: (String) -> [UInt8] = { Array("\u{1b}[\($0)".utf8) }
        let cursor: (String) -> [UInt8] = { Array((appCursor ? "\u{1b}O" : "\u{1b}[").utf8) + Array($0.utf8) }
        switch Int(event.keyCode) {
        case 36, 76: return [0x0d]                                  // return, keypad enter
        case 48: return flags.contains(.shift) ? csi("Z") : [0x09]  // tab / back-tab
        case 51: return [0x7f]                                      // backspace
        case 53: return [0x1b]                                      // escape
        case 117: return csi("3~")                                  // forward delete
        case 123: return cursor("D")
        case 124: return cursor("C")
        case 125: return cursor("B")
        case 126: return cursor("A")
        case 115: return cursor("H")                                // home
        case 119: return cursor("F")                                // end
        case 116: return csi("5~")                                  // page up
        case 121: return csi("6~")                                  // page down
        default: break
        }
        if flags.contains(.control), let c = event.charactersIgnoringModifiers?.lowercased().unicodeScalars.first {
            switch c {
            case "a"..."z": return [UInt8(c.value - 96)]
            case "@", " ": return [0]
            case "[": return [0x1b]
            case "\\": return [0x1c]
            case "]": return [0x1d]
            default: break
            }
        }
        return nil
    }
}

// MARK: Input method

extension TerminalNSView: @preconcurrency NSTextInputClient {
    func insertText(_ string: Any, replacementRange: NSRange) {
        let text = (string as? NSAttributedString)?.string ?? (string as? String) ?? ""
        markedText = ""
        needsDisplay = true
        if !text.isEmpty { send(Array(text.utf8)) }
    }

    /// Keys the input method did not turn into text (for example Option-arrow): the usual encoding.
    override func doCommand(by selector: Selector) {
        guard let event = interpretingEvent,
              let bytes = KeyEncoder.bytes(for: event, appCursor: screen?.appCursor ?? false) else { return }
        send(bytes)
    }

    func setMarkedText(_ string: Any, selectedRange: NSRange, replacementRange: NSRange) {
        markedText = (string as? NSAttributedString)?.string ?? (string as? String) ?? ""
        needsDisplay = true
    }

    func unmarkText() {
        markedText = ""
        needsDisplay = true
    }

    func selectedRange() -> NSRange { NSRange(location: markedText.utf16.count, length: 0) }

    func markedRange() -> NSRange {
        markedText.isEmpty ? NSRange(location: NSNotFound, length: 0) : NSRange(location: 0, length: markedText.utf16.count)
    }

    func hasMarkedText() -> Bool { !markedText.isEmpty }

    func attributedSubstring(forProposedRange range: NSRange, actualRange: NSRangePointer?) -> NSAttributedString? { nil }

    func validAttributesForMarkedText() -> [NSAttributedString.Key] { [] }

    /// The cursor cell in screen coordinates, so the candidate window opens next to it.
    func firstRect(forCharacterRange range: NSRange, actualRange: NSRangePointer?) -> NSRect {
        guard let s = screen, let window else { return .zero }
        let rect = NSRect(x: CGFloat(s.cursorCol) * cellSize.width, y: CGFloat(s.cursorRow) * cellSize.height,
                          width: cellSize.width, height: cellSize.height)
        return window.convertToScreen(convert(rect.offsetBy(dx: gridInset.width, dy: gridInset.height), to: nil))
    }

    func characterIndex(for point: NSPoint) -> Int { NSNotFound }
}

private extension Int {
    /// Non-negative, for converting a clamped grid index to `UInt16`.
    var clamped: Int { Swift.max(0, self) }
}

extension NSColor {
    convenience init(rgb: UInt32) {
        self.init(srgbRed: CGFloat((rgb >> 16) & 0xff) / 255, green: CGFloat((rgb >> 8) & 0xff) / 255,
                  blue: CGFloat(rgb & 0xff) / 255, alpha: 1)
    }
}

/// Whether the tab around this view is the one showing (`TerminalNSView.isShown`). True by
/// default: a torn-off tab window shows its only tab.
private struct TabShownKey: EnvironmentKey {
    static let defaultValue = true
}

extension EnvironmentValues {
    var tabShown: Bool {
        get { self[TabShownKey.self] }
        set { self[TabShownKey.self] = newValue }
    }
}

struct TerminalViewRepresentable: NSViewRepresentable {
    let tab: TerminalTab
    let pane: TerminalPane
    let isActive: Bool
    @Environment(\.tabShown) private var tabShown
    @Environment(AppearanceSettings.self) private var settings
    @Environment(ThemesModel.self) private var themes
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(SettingsModel.self) private var appSettings
    /// Read so a change of the app's light or dark look updates the view: Match app theme repaints open terminals.
    @Environment(\.colorScheme) private var colorScheme

    private var terminal: Terminal { pane.terminal }

    func makeNSView(context: Context) -> TerminalNSView {
        let v = TerminalNSView(terminal: terminal, font: font)
        applyTheme(v)
        applyBehaviour(v)
        v.onTitle = { [pane] title in pane.remoteTitle = title }
        v.onExit = { [pane, tab, sessions] in
            pane.ended = true
            if tab.ended { sessions.sessionEnded(tab) }
        }
        v.onLinkStatus = { [pane] status in pane.linkStatus = status }
        v.onInput = { [sessions, terminal] bytes in sessions.broadcast(bytes, from: terminal) }
        v.onClipboard = { [pane] req in
            if req.ask { pane.clipboardRequest = req.text } else { TerminalClipboard.copy(req.text) }
        }
        // Focus follows clicks: a pane that becomes first responder becomes the tab's focused pane.
        v.onFocus = { [tab, pane] in if tab.focusedPane != pane.id { tab.focusedPane = pane.id } }
        v.wantsFocus = isActive && tab.focusedPane == pane.id
        v.isShown = tabShown
        return v
    }

    func updateNSView(_ view: TerminalNSView, context: Context) {
        view.isShown = tabShown
        view.wantsFocus = isActive && tab.focusedPane == pane.id
        view.setFont(font)
        applyTheme(view)
        applyBehaviour(view)
    }

    /// The connection's own or inherited font over the app's, then the tab's zoom (⌘+ ⌘−).
    private var font: TerminalFontView {
        _ = model.revision
        let app = settings.terminalFont
        let base = tab.connectionId.flatMap { id in try? model.library?.terminalFont(connectionId: id, app: app) } ?? effectiveTerminalFont(app: app)
        let size = Int(base.size) + tab.zoom
        return TerminalFontView(family: base.family, size: UInt32(min(TerminalTab.zoomRange.upperBound, max(TerminalTab.zoomRange.lowerBound, size))),
                                ligatures: base.ligatures)
    }

    /// Cursor, bell, copy on select and scrollback from Settings › Terminal.
    private func applyBehaviour(_ view: TerminalNSView) {
        view.cursorStyle = appSettings.value("terminal.cursor-style")
        view.bellStyle = appSettings.value("terminal.bell")
        TermEventsRuntime.shared.programNotifications = appSettings.value("terminal.program-notifications") != "false"
        view.copyOnSelect = appSettings.value("terminal.copy-on-select") == "true"
        let lines = UInt32(appSettings.value("terminal.scrollback")) ?? 10_000
        if view.appliedScrollback != lines {
            view.appliedScrollback = lines
            terminal.setScrollback(lines: lines)
        }
    }

    /// The connection's own or inherited theme, else the app's; re-applied only when it or the
    /// theme's colours (`themes.revision`) change.
    private func applyTheme(_ view: TerminalNSView) {
        let own = tab.connectionId.flatMap { id in (try? model.library?.terminalTheme(connectionId: id)) ?? nil }
        let id = own ?? AppearanceSettings.terminalThemeId(settings.terminalTheme, appIsDark: colorScheme == .dark)
        let policy = appSettings.value("terminal.osc52")
        let key = "\(id)#\(themes.revision)#\(model.revision)#\(policy)"
        guard view.appliedTheme != key else { return }
        view.appliedTheme = key
        themes.apply(id, to: terminal)
        terminal.setClipboardPolicy(policy: policy)
    }
}
