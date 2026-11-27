#if BASTION_TEST_HOOKS
import AppKit

/// `contrast-tree`: the selected tree row, rendered focused (accent fill, white text) and
/// unfocused (system grey, label text). For each state the fill is sampled beside the text and the
/// text pixel is the one inside the name's frame that differs most from the fill (glyph cores).
/// Writes `CONTRAST tree <state> <accent> <ratio>`, and `FAIL CONTRAST …` under 4.5:1.
/// The Mac tree has no hover fill; the selected tab's wash is checked in tests/selection-contrast.
extension Driver {
    func contrastStep(_ cmd: String, _ arg: String) -> Bool {
        guard cmd == "contrast-tree" else { return false }
        guard let outline, outline.selectedRow >= 0,
              let row = outline.rowView(atRow: outline.selectedRow, makeIfNecessary: false) as? AccentRowView,
              let sv = UIDriver.services else { write("FAIL contrast-tree: no selected accent row"); return true }
        let accent = sv.settings.value("appearance.accent")
        let was = row.isEmphasized
        defer { row.isEmphasized = was; row.needsDisplay = true }
        for (state, emphasized) in [("selected", true), ("selected-unfocused", false)] {
            row.isEmphasized = emphasized
            row.layoutSubtreeIfNeeded()
            guard let m = measure(row) else { write("FAIL contrast-tree \(state): no text in the row"); continue }
            let dark = row.effectiveAppearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
            let line = String(format: "CONTRAST tree %@ %@ %@ %.2f fill %@ text %@", state, accent, dark ? "dark" : "light", m.ratio, m.fill, m.text)
            write(m.ratio < SelectionContrast.requiredRatio ? "FAIL \(line) (under 4.5:1)" : line)
        }
        return true
    }

    /// Contrast between the row's fill and its name text, from a render of the row.
    private func measure(_ row: NSTableRowView) -> (ratio: Double, fill: String, text: String)? {
        guard let rep = row.bitmapImageRepForCachingDisplay(in: row.bounds) else { return nil }
        row.cacheDisplay(in: row.bounds, to: rep)
        let scale = CGFloat(rep.pixelsWide) / max(row.bounds.width, 1)
        func px(_ x: Int, _ y: Int) -> SelectionContrast.RGB? {
            // colorAt tags the pixel Generic RGB, but a window's cache holds the display's colour
            // space ("Color LCD"); read it in the rep's own space (MAC-UI-02: the dark fills read 3.6:1
            // for colours that are 4.6:1 once converted correctly).
            guard let raw = rep.colorAt(x: x, y: y)?.usingColorSpace(.genericRGB) else { return nil }
            let parts = [raw.redComponent, raw.greenComponent, raw.blueComponent, 1]
            guard let c = parts.withUnsafeBufferPointer({ NSColor(colorSpace: rep.colorSpace, components: $0.baseAddress!, count: 4) }).usingColorSpace(.sRGB) else { return nil }
            return .init(r: c.redComponent, g: c.greenComponent, b: c.blueComponent)
        }
        guard let fill = px(Int((DS.Size.selectionInset + 4) * scale), rep.pixelsHigh / 2),
              let field = row.allSubviews(of: NSTextField.self).first(where: { !$0.stringValue.isEmpty && !$0.isHidden }) else { return nil }
        // Bitmap rows run top-down; row views are flipped like the outline, so frames map directly.
        let r = field.convert(field.bounds, to: row)
        let flipped = row.isFlipped
        var best = 1.0
        var text = fill
        for y in stride(from: Int(r.minY * scale), to: Int(r.maxY * scale), by: 1) {
            let by = flipped ? y : rep.pixelsHigh - 1 - y
            for x in stride(from: Int(r.minX * scale), to: Int(r.maxX * scale), by: 1) {
                if let p = px(x, by), SelectionContrast.ratio(p, fill) > best { best = SelectionContrast.ratio(p, fill); text = p }
            }
        }
        func hex(_ c: SelectionContrast.RGB) -> String { String(format: "#%02X%02X%02X", Int(c.r * 255 + 0.5), Int(c.g * 255 + 0.5), Int(c.b * 255 + 0.5)) }
        return (best, hex(fill), hex(text))
    }
}
#endif
