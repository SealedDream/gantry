#if BASTION_TEST_HOOKS
import AppKit

/// `colour-match`: surfaces that must look like one surface are sampled in the window's real
/// picture and compared: the sidebar header against the sidebar body, the titlebar against the
/// toolbar row, the inspector header against its body, and an attached sheet's top against its
/// bottom. Writes `COLOUR-MATCH <pair> a #RRGGBB b #RRGGBB diff <n>` per pair, FAIL over
/// `tolerance` (the white sidebar header under the macOS 27 SDK, owner 2026-11-17). Pairs whose
/// views are not on screen are reported as skipped.
extension Driver {
    /// Largest difference in any sRGB channel (0-255) that still counts as the same surface.
    static let colourTolerance = 6
    /// Distance from the window's top-right corner that clears its rounded edge.
    static let cornerInset: CGFloat = 16

    func colourMatchStep() async {
        guard let window else { return write("FAIL colour-match: no window") }
        await settle(0.3)
        guard let picture = WindowCapture.take(window) else { return write("FAIL colour-match: no picture") }
        let main = Sampler(picture.image, window: window)
        var checked = 0
        for (pair, a, b) in colourPairs(window) {
            guard let a, let b else { write("COLOUR-MATCH \(pair) skipped (not shown)"); continue }
            checked += 1
            report(pair, main.colour(at: a), main.colour(at: b))
        }
        if let sheet = window.attachedSheet, let shot = WindowCapture.take(sheet) {
            let s = Sampler(shot.image, window: sheet)
            let h = sheet.frame.height
            checked += 1
            report("sheet-top/sheet-bottom", s.colour(at: NSPoint(x: 6, y: 6)), s.colour(at: NSPoint(x: 6, y: h - 6)))
        } else {
            write("COLOUR-MATCH sheet-top/sheet-bottom skipped (no sheet)")
        }
        write("COLOUR-MATCH checked \(checked)")
    }

    /// Point pairs in window points, top-down (as the picture and SwiftUI's global frames).
    private func colourPairs(_ window: NSWindow) -> [(String, NSPoint?, NSPoint?)] {
        let height = window.frame.height
        func topDown(_ v: NSView) -> NSRect {
            let r = v.convert(v.bounds, to: nil)
            return NSRect(x: r.minX, y: height - r.maxY, width: r.width, height: r.height)
        }
        var pairs: [(String, NSPoint?, NSPoint?)] = []
        // Sidebar: beside the search field (header) and under the last visible tree row (body).
        let search = window.contentView?.superview?.allSubviews(of: NSTextField.self).first {
            $0.isEditable && ($0.placeholderString ?? $0.placeholderAttributedString?.string) == "Search or connect"
        }
        var body: NSPoint?
        if let outline, outline.numberOfRows > 0, let scroll = outline.enclosingScrollView {
            let last = topDown(outline).minY + outline.rect(ofRow: outline.numberOfRows - 1).maxY
            let area = topDown(scroll)
            if last + 12 < area.maxY - 12 { body = NSPoint(x: area.minX + 4, y: last + 12) }
        }
        pairs.append(("sidebar-header/sidebar-body", search.map { let r = topDown($0); return NSPoint(x: r.minX - 4, y: r.midY) }, body))
        // Titlebar and toolbar row: one unified surface; the right-hand margin holds no item. Inset
        // past the window's rounded corner, which is transparent in the picture.
        let layout = window.contentLayoutRect
        let toolbarBottom = height - layout.maxY
        let x = window.frame.width - Self.cornerInset
        // The top few points carry the window's edge highlight, so the titlebar is read mid-row.
        pairs.append(("titlebar/toolbar", NSPoint(x: x, y: toolbarBottom / 2), NSPoint(x: x, y: toolbarBottom - 3)))
        // Inspector: its header row against the body under it, at the column's trailing margin.
        let f = UIProbe.frames
        if let header = f["inspector-header"] {
            pairs.append(("inspector-header/inspector-body", NSPoint(x: header.maxX - 3, y: header.midY), NSPoint(x: header.maxX - 3, y: header.maxY + 24)))
        } else {
            pairs.append(("inspector-header/inspector-body", nil, nil))
        }
        return pairs
    }

    private func report(_ pair: String, _ a: SelectionContrast.RGB?, _ b: SelectionContrast.RGB?) {
        guard let a, let b else { return write("FAIL COLOUR-MATCH \(pair): outside the picture") }
        let diff = Int(max(abs(a.r - b.r), abs(a.g - b.g), abs(a.b - b.b)) * 255 + 0.5)
        let line = "COLOUR-MATCH \(pair) a \(Self.hex(a)) b \(Self.hex(b)) diff \(diff)"
        write(diff > Self.colourTolerance ? "FAIL \(line) (over \(Self.colourTolerance))" : line)
    }

    static func hex(_ c: SelectionContrast.RGB) -> String {
        String(format: "#%02X%02X%02X", Int(c.r * 255 + 0.5), Int(c.g * 255 + 0.5), Int(c.b * 255 + 0.5))
    }
}

/// Pixels of a window picture by window point (top-down).
private struct Sampler {
    let rep: NSBitmapImageRep
    let scale: CGFloat

    init(_ image: CGImage, window: NSWindow) {
        rep = NSBitmapImageRep(cgImage: image)
        scale = CGFloat(rep.pixelsWide) / max(window.frame.width, 1)
    }

    func colour(at p: NSPoint) -> SelectionContrast.RGB? {
        let x = Int(p.x * scale), y = Int(p.y * scale)
        guard x >= 0, y >= 0, x < rep.pixelsWide, y < rep.pixelsHigh,
              let c = rep.colorAt(x: x, y: y)?.usingColorSpace(.sRGB) else { return nil }
        return .init(r: c.redComponent, g: c.greenComponent, b: c.blueComponent)
    }
}
#endif
