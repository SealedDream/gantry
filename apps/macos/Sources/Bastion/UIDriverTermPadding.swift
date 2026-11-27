#if BASTION_TEST_HOOKS
import AppKit

/// UI-03 checks of the terminal's inner padding and accent selection (UI driver, `term-padding`).
extension Driver {
    private static func snapshot(_ v: TerminalNSView) -> NSBitmapImageRep? {
        guard let rep = v.bitmapImageRepForCachingDisplay(in: v.bounds) else { return nil }
        v.cacheDisplay(in: v.bounds, to: rep)
        return rep
    }

    /// sRGB 0xRRGGBB at a point in view coordinates (the view is flipped; the bitmap's y runs down too).
    private static func pixel(_ rep: NSBitmapImageRep, _ v: TerminalNSView, _ p: NSPoint) -> UInt32? {
        let sx = CGFloat(rep.pixelsWide) / v.bounds.width, sy = CGFloat(rep.pixelsHigh) / v.bounds.height
        guard let c = rep.colorAt(x: Int(p.x * sx), y: Int(p.y * sy))?.usingColorSpace(.sRGB) else { return nil }
        func b(_ x: CGFloat) -> UInt32 { UInt32((x * 255).rounded()) }
        return b(c.redComponent) << 16 | b(c.greenComponent) << 8 | b(c.blueComponent)
    }

    private static func near(_ a: UInt32, _ b: UInt32, _ tol: Int = 6) -> Bool {
        [16, 8, 0].allSatisfy { abs(Int((a >> UInt32($0)) & 0xff) - Int((b >> UInt32($0)) & 0xff)) <= tol }
    }

    func termPadding(_ v: TerminalNSView, row: Int) async {
        v.needsDisplay = true
        await settle(0.3)
        guard let rep = Self.snapshot(v), let bg = Self.pixel(rep, v, NSPoint(x: v.bounds.midX, y: v.bounds.maxY - 20)) else {
            return write("FAIL term-padding: no snapshot")
        }
        let inset = v.gridInset
        var strays = 0
        var y: CGFloat = 1
        while y < v.bounds.height - 1 {
            var x: CGFloat = 1
            while x < inset.width - 1 { if let p = Self.pixel(rep, v, NSPoint(x: x, y: y)), !Self.near(p, bg) { strays += 1 }; x += 1 }
            y += 1
        }
        var x: CGFloat = 1
        while x < v.bounds.width - 1 {
            var yy: CGFloat = 1
            while yy < inset.height - 1 { if let p = Self.pixel(rep, v, NSPoint(x: x, y: yy)), !Self.near(p, bg) { strays += 1 }; yy += 1 }
            x += 1
        }
        write(strays == 0 ? String(format: "TERM-PADDING ok inset=%.0fx%.0f bg=%06x", inset.width, inset.height, bg)
                          : "FAIL term-padding: \(strays) non-background pixels in the padding (bg \(String(format: "%06x", bg)))")
        // Double-click in the left padding, beside <row>: the edge cell's word is selected.
        let cell = v.cellRect(row: row, col: 0)
        let at = v.convert(NSPoint(x: inset.width / 2, y: cell.midY), to: nil)
        for clicks in 1...2 {
            for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
                let e = NSEvent.mouseEvent(with: type, location: at, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                           windowNumber: v.window?.windowNumber ?? 0, context: nil, eventNumber: 0, clickCount: clicks, pressure: 1)!
                if type == .leftMouseDown { v.mouseDown(with: e) } else { v.mouseUp(with: e) }
            }
        }
        await settle(0.3)
        write("TERM-PADDING selection \(v.terminal.selectionText() ?? "<none>")")
        v.needsDisplay = true
        await settle(0.3)
        guard let rep2 = Self.snapshot(v), let fill = Self.pixel(rep2, v, NSPoint(x: cell.minX + 1, y: cell.minY + 1)) else {
            return write("FAIL term-padding: no snapshot after select")
        }
        // The bitmap's colour space differs from the drawing's, so compare against what it must not be: the theme
        // background and the old fixed selection blue.
        let tinted = !Self.near(fill, bg, 12) && !Self.near(fill, 0x264f78, 12)
        write(tinted ? String(format: "TERM-PADDING accent ok fill=%06x bg=%06x", fill, bg)
                     : String(format: "FAIL term-padding: selection fill %06x is not the accent tint (bg %06x)", fill, bg))
        // Copy on select (set earlier by the suite) puts the selected word on the clipboard.
        let selected = v.terminal.selectionText() ?? ""
        let clip = commands.pasteboard.string(forType: .string) ?? ""
        write(!selected.isEmpty && clip == selected ? "TERM-PADDING copied \(clip)" : "FAIL term-padding: clipboard '\(clip)', selection '\(selected)'")
    }
}
#endif
