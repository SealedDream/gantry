import AppKit
import CoreText
import SwiftUI
import BastionCore

/// Terminal fonts for every view that draws terminal text: the terminal itself and font previews
/// (Settings › Terminal, the Fonts page of the property dialog). The core owns the bundled font,
/// the suggested families and the glyph classes (`termfonts`); this file registers the bundled
/// files, builds the fonts with fallback to the bundled Nerd Font, and draws the glyph classes
/// that must meet the cell edges.
@MainActor
enum TerminalFonts {
    /// Family of the bundled Nerd Font (JetBrains Mono Nerd Font Mono, OFL 1.1).
    static let bundledFamily = bundledTerminalFont()

    /// The family a stored `terminal.font-family` names: `bundled` (the shared default, which
    /// Windows maps to its own bundled font) is the Mac's bundled Nerd Font.
    static func family(_ stored: String) -> String { stored == "bundled" ? bundledFamily : stored }

    /// Registers the bundled font files for this process: from the app bundle's Resources/Fonts,
    /// else (a development build) from the repository's `assets/fonts`. Safe to call repeatedly.
    static func registerBundledFont() {
        guard !registered else { return }
        registered = true
        guard let dir = fontsDirectory() else { return NSLog("Gantry: bundled terminal font not found") }
        for file in bundledTerminalFontFiles() {
            var error: Unmanaged<CFError>?
            if !CTFontManagerRegisterFontsForURL(dir.appendingPathComponent(file) as CFURL, .process, &error) {
                NSLog("Gantry: could not register %@: %@", file, error.map { "\($0.takeRetainedValue())" } ?? "unknown")
            }
        }
    }

    private static var registered = false

    private static func fontsDirectory() -> URL? {
        let fm = FileManager.default
        if let r = Bundle.main.resourceURL?.appendingPathComponent("Fonts"), fm.fileExists(atPath: r.path) { return r }
        // A development build: .build/out/Products/<config>/Bastion, then up to the repository root.
        var dir = Bundle.main.executableURL?.resolvingSymlinksInPath().deletingLastPathComponent()
        for _ in 0..<8 {
            guard let d = dir else { break }
            let candidate = d.appendingPathComponent("assets/fonts")
            if fm.fileExists(atPath: candidate.path) { return candidate }
            dir = d.deletingLastPathComponent()
        }
        return nil
    }

    /// Families a picker lists: the core's suggestions that are installed, then the other
    /// installed fixed-pitch families, by name.
    static func families() -> [TerminalFontFamily] {
        registerBundledFont()
        let installed = Set(NSFontManager.shared.availableFontFamilies)
        let suggested = suggestedTerminalFonts().filter { installed.contains($0.family) }
        let known = Set(suggested.map(\.family))
        let fixed = (NSFontManager.shared.availableFontNames(with: .fixedPitchFontMask) ?? [])
            .compactMap { NSFont(name: $0, size: 12)?.familyName }
        let others = Set(fixed).subtracting(known).filter { !$0.hasPrefix(".") }.sorted()
        return suggested + others.map { TerminalFontFamily(family: $0, label: $0) }
    }

    /// Regular and bold faces of `family` at `size`, falling back to the bundled font for glyphs
    /// the family lacks (Nerd Font icons, Powerline) and to it entirely when the family is missing.
    static func fonts(family: String, size: CGFloat) -> (regular: NSFont, bold: NSFont) {
        registerBundledFont()
        let base = face(family: family, size: size) ?? face(family: bundledFamily, size: size)
            ?? .monospacedSystemFont(ofSize: size, weight: .regular)
        let bold = NSFontManager.shared.convert(base, toHaveTrait: .boldFontMask)
        return (withFallback(base), withFallback(bold))
    }

    private static func face(family: String, size: CGFloat) -> NSFont? {
        NSFontManager.shared.font(withFamily: family, traits: [], weight: 5, size: size)
    }

    /// Adds the bundled Nerd Font to the cascade list so missing glyphs come from it before the
    /// system's fallback (which has no private-use icons).
    private static func withFallback(_ font: NSFont) -> NSFont {
        guard font.familyName != bundledFamily else { return font }
        let nerd = NSFontDescriptor(fontAttributes: [.family: bundledFamily])
        let d = font.fontDescriptor.addingAttributes([.cascadeList: [nerd]])
        return NSFont(descriptor: d, size: font.pointSize) ?? font
    }

    /// Cell size for a font: the advance of "M" and the line height in whole points.
    static func cellSize(_ font: NSFont) -> CGSize {
        let advance = ("M" as NSString).size(withAttributes: [.font: font]).width
        return CGSize(width: advance, height: ceil(font.ascender - font.descender + font.leading))
    }

    /// Glyph class per cell text, cached: ASCII and most text never reach the core.
    static func glyphClass(_ text: String) -> GlyphClassView {
        guard let first = text.unicodeScalars.first, first.value >= 0x2500 else { return .text }
        if let c = classCache[text] { return c }
        let c = terminalGlyphClass(text: text)
        if classCache.count < 4096 { classCache[text] = c }
        return c
    }

    private static var classCache: [String: GlyphClassView] = [:]
}

/// Draws box drawing, block elements and Powerline separators as shapes that fill their cell (in
/// a flipped view), so neighbouring cells join without the gaps a font's own glyphs leave when its
/// line height differs from the cell. Returns false for a character it does not draw; the caller
/// then uses the font.
enum CellGlyphs {
    static func draw(_ text: String, in rect: NSRect, color: NSColor) -> Bool {
        guard let c = text.unicodeScalars.first?.value else { return false }
        color.set()
        switch c {
        case 0x2500...0x257f: return drawBox(c, in: rect)
        case 0x2580...0x259f: return drawBlock(c, in: rect, color: color)
        case 0xe0b0...0xe0bf: return drawPowerline(c, in: rect)
        default: return false
        }
    }

    /// Arms of a box-drawing character: left, right, up, down; 0 none, 1 light, 2 heavy.
    private static func arms(_ c: UInt32) -> (Int, Int, Int, Int)? {
        switch c {
        case 0x2500: (1, 1, 0, 0)
        case 0x2501: (2, 2, 0, 0)
        case 0x2502: (0, 0, 1, 1)
        case 0x2503: (0, 0, 2, 2)
        case 0x250c, 0x256d: (0, 1, 0, 1)
        case 0x250f: (0, 2, 0, 2)
        case 0x2510, 0x256e: (1, 0, 0, 1)
        case 0x2513: (2, 0, 0, 2)
        case 0x2514, 0x2570: (0, 1, 1, 0)
        case 0x2517: (0, 2, 2, 0)
        case 0x2518, 0x256f: (1, 0, 1, 0)
        case 0x251b: (2, 0, 2, 0)
        case 0x251c: (0, 1, 1, 1)
        case 0x2523: (0, 2, 2, 2)
        case 0x2524: (1, 0, 1, 1)
        case 0x252b: (2, 0, 2, 2)
        case 0x252c: (1, 1, 0, 1)
        case 0x2533: (2, 2, 0, 2)
        case 0x2534: (1, 1, 1, 0)
        case 0x253b: (2, 2, 2, 0)
        case 0x253c: (1, 1, 1, 1)
        case 0x254b: (2, 2, 2, 2)
        case 0x2574: (1, 0, 0, 0)
        case 0x2575: (0, 0, 1, 0)
        case 0x2576: (0, 1, 0, 0)
        case 0x2577: (0, 0, 0, 1)
        default: nil
        }
    }

    /// Lines, corners, tees and crosses (light and heavy) and the rounded corners Starship's
    /// two-line prompts use; others (dashed, double) fall back to the font.
    private static func drawBox(_ c: UInt32, in r: NSRect) -> Bool {
        guard let a = arms(c) else { return false }
        let light = max(1, (r.width / 8).rounded())
        let w = { (n: Int) in n == 2 ? light * 2 : light }
        let (cx, cy) = (r.midX, r.midY)
        if (0x256d...0x2570).contains(c) {
            // A quarter arc from the vertical arm's edge to the horizontal arm's edge.
            let path = NSBezierPath()
            path.lineWidth = light
            let h = a.0 > 0 ? r.minX : r.maxX, v = a.2 > 0 ? r.minY : r.maxY
            path.move(to: NSPoint(x: cx, y: v))
            path.curve(to: NSPoint(x: h, y: cy), controlPoint1: NSPoint(x: cx, y: cy), controlPoint2: NSPoint(x: cx, y: cy))
            path.stroke()
            return true
        }
        if a.0 > 0 { NSRect(x: r.minX, y: cy - w(a.0) / 2, width: cx - r.minX + w(a.0) / 2, height: w(a.0)).fill() }
        if a.1 > 0 { NSRect(x: cx - w(a.1) / 2, y: cy - w(a.1) / 2, width: r.maxX - cx + w(a.1) / 2, height: w(a.1)).fill() }
        if a.2 > 0 { NSRect(x: cx - w(a.2) / 2, y: r.minY, width: w(a.2), height: cy - r.minY + w(a.2) / 2).fill() }
        if a.3 > 0 { NSRect(x: cx - w(a.3) / 2, y: cy - w(a.3) / 2, width: w(a.3), height: r.maxY - cy + w(a.3) / 2).fill() }
        return true
    }

    /// Full and partial blocks and the three shades.
    private static func drawBlock(_ c: UInt32, in r: NSRect, color: NSColor) -> Bool {
        switch c {
        case 0x2580: NSRect(x: r.minX, y: r.minY, width: r.width, height: r.height / 2).fill()
        case 0x2581...0x2588:
            let h = r.height * CGFloat(c - 0x2580) / 8
            NSRect(x: r.minX, y: r.maxY - h, width: r.width, height: h).fill()
        case 0x2589...0x258f: NSRect(x: r.minX, y: r.minY, width: r.width * CGFloat(0x2590 - c) / 8, height: r.height).fill()
        case 0x2590: NSRect(x: r.midX, y: r.minY, width: r.width / 2, height: r.height).fill()
        case 0x2591...0x2593:
            color.withAlphaComponent(CGFloat(c - 0x2590) / 4).setFill()
            r.fill()
        case 0x2594: NSRect(x: r.minX, y: r.minY, width: r.width, height: r.height / 8).fill()
        case 0x2595: NSRect(x: r.maxX - r.width / 8, y: r.minY, width: r.width / 8, height: r.height).fill()
        default: return false
        }
        return true
    }

    /// Triangles and semicircles (E0B0–E0B7) and slants (E0B8–E0BF); odd code points are the
    /// thin outline variants.
    private static func drawPowerline(_ c: UInt32, in r: NSRect) -> Bool {
        let path = NSBezierPath()
        let (l, rt, t, b, mid) = (r.minX, r.maxX, r.minY, r.maxY, r.midY)
        let bulge = r.width * 1.33
        switch c {
        case 0xe0b0, 0xe0b1: path.move(to: NSPoint(x: l, y: t)); path.line(to: NSPoint(x: rt, y: mid)); path.line(to: NSPoint(x: l, y: b))
        case 0xe0b2, 0xe0b3: path.move(to: NSPoint(x: rt, y: t)); path.line(to: NSPoint(x: l, y: mid)); path.line(to: NSPoint(x: rt, y: b))
        case 0xe0b4, 0xe0b5:
            path.move(to: NSPoint(x: l, y: t))
            path.curve(to: NSPoint(x: l, y: b), controlPoint1: NSPoint(x: l + bulge, y: t), controlPoint2: NSPoint(x: l + bulge, y: b))
        case 0xe0b6, 0xe0b7:
            path.move(to: NSPoint(x: rt, y: t))
            path.curve(to: NSPoint(x: rt, y: b), controlPoint1: NSPoint(x: rt - bulge, y: t), controlPoint2: NSPoint(x: rt - bulge, y: b))
        case 0xe0b8, 0xe0b9: path.move(to: NSPoint(x: l, y: t)); path.line(to: NSPoint(x: l, y: b)); path.line(to: NSPoint(x: rt, y: b))
        case 0xe0ba, 0xe0bb: path.move(to: NSPoint(x: rt, y: t)); path.line(to: NSPoint(x: rt, y: b)); path.line(to: NSPoint(x: l, y: b))
        case 0xe0bc, 0xe0bd: path.move(to: NSPoint(x: l, y: t)); path.line(to: NSPoint(x: rt, y: t)); path.line(to: NSPoint(x: l, y: b))
        case 0xe0be, 0xe0bf: path.move(to: NSPoint(x: l, y: t)); path.line(to: NSPoint(x: rt, y: t)); path.line(to: NSPoint(x: rt, y: b))
        default: return false
        }
        if c % 2 == 1 {
            path.lineWidth = max(1, (r.width / 8).rounded())
            path.stroke()
        } else {
            path.close()
            path.fill()
        }
        return true
    }
}

/// Font family picker for Settings › Terminal and the property dialog's Fonts page: the bundled
/// font and suggestions first, then other installed monospaced families. A stored family that is
/// no longer installed stays selectable (marked) so the setting is not silently changed.
struct TerminalFontPicker: View {
    @Binding var selection: String
    @State private var families: [TerminalFontFamily] = []

    var body: some View {
        Picker("Font", selection: $selection) {
            ForEach(families, id: \.family) { Text($0.label).tag($0.family) }
            if !families.isEmpty, !families.contains(where: { $0.family == selection }) {
                Text("\(selection) (not installed)").tag(selection)
            }
        }
        .labelsHidden()
        .fixedSize()
        .onAppear { if families.isEmpty { families = TerminalFonts.families() } }
    }
}

/// A few lines of prompt-style text drawn the way the terminal draws them (font, fallback,
/// Powerline shapes, icons), for font pickers to preview a choice.
struct TerminalFontPreview: NSViewRepresentable {
    let font: TerminalFontView
    var foreground: UInt32 = 0xd8d8d8
    var background: UInt32 = 0x1c1c1e

    /// Sample: a Starship-like prompt (icons, separators, box drawing), ligature pairs, CJK.
    static let sample = [
        "╭─\u{e0b6}\u{f179} mo \u{e0b0} \u{f07c} ~/src/bastion \u{e0b0} \u{e725} main \u{e0b4}",
        "╰─❯ ls -> != == => 0O1lI   日本語 ▁▃▅▇█",
    ]

    func makeNSView(context: Context) -> FontPreviewNSView { FontPreviewNSView() }

    func updateNSView(_ view: FontPreviewNSView, context: Context) {
        view.configure(font: font, lines: Self.sample, foreground: foreground, background: background)
    }
}

final class FontPreviewNSView: NSView {
    private var font: NSFont = .monospacedSystemFont(ofSize: 13, weight: .regular)
    private var ligatures = true
    private var lines: [String] = []
    private var colors: (UInt32, UInt32) = (0xd8d8d8, 0x1c1c1e)
    override var isFlipped: Bool { true }

    func configure(font choice: TerminalFontView, lines: [String], foreground: UInt32, background: UInt32) {
        font = TerminalFonts.fonts(family: choice.family, size: CGFloat(choice.size)).regular
        ligatures = choice.ligatures
        self.lines = lines
        colors = (foreground, background)
        invalidateIntrinsicContentSize()
        needsDisplay = true
    }

    override var intrinsicContentSize: NSSize {
        let cell = TerminalFonts.cellSize(font)
        return NSSize(width: NSView.noIntrinsicMetric, height: cell.height * CGFloat(lines.count) + 16)
    }

    override func draw(_ dirtyRect: NSRect) {
        NSColor(rgb: colors.1).setFill()
        bounds.fill()
        let cell = TerminalFonts.cellSize(font)
        let fg = NSColor(rgb: colors.0)
        let attrs: [NSAttributedString.Key: Any] = [.font: font, .foregroundColor: fg, .ligature: ligatures ? 1 : 0]
        for (row, line) in lines.enumerated() {
            var col = 0
            for ch in line {
                let text = String(ch)
                let rect = NSRect(x: 8 + CGFloat(col) * cell.width, y: 8 + CGFloat(row) * cell.height, width: cell.width, height: cell.height)
                if TerminalFonts.glyphClass(text) == .text || !CellGlyphs.draw(text, in: rect, color: fg) {
                    NSAttributedString(string: text, attributes: attrs).draw(at: rect.origin)
                }
                // East Asian wide characters take two cells, as on the terminal grid.
                col += ch.unicodeScalars.first.map { $0.properties.isEmojiPresentation || (0x2e80...0x9fff).contains($0.value) } == true ? 2 : 1
            }
        }
    }
}
