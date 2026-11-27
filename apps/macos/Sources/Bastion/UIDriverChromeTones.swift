#if BASTION_TEST_HOOKS
import AppKit

/// UI-06 `chrome-tones off|dark|light [floor]`: the tones the main window applied, then a picture of the window. Off: no
/// tones. Otherwise the tones must be dark or light as asked, and in the picture the sidebar, the active tab and the
/// toolbar band must show their tone (pixels within 3 per channel: sRGB vs Display P3 rounding) and the text on each
/// must reach `floor` (default 4.5; 7 with Increase Contrast): the pixel that differs most from the tone is the text.
/// Writes `CHROME-TONES …` per surface and `FAIL CHROME-TONES …` for any miss.
extension Driver {
    private static let tolerance = 3.0 / 255.0
    private static let minShare = 0.4

    func chromeTonesStep(_ arg: String) async -> Bool {
        let p = arg.split(separator: " ").map(String.init)
        let want = p.first ?? "off"
        let floor = p.count > 1 ? Double(p[1]) ?? 4.5 : 4.5
        await settle(0.5)
        guard let tones = DriverEvents.chromeTones else {
            write(want == "off" ? "CHROME-TONES off" : "FAIL CHROME-TONES \(want): the window shows stock colours")
            return true
        }
        let t = tones.raw
        guard want != "off" else { write("FAIL CHROME-TONES off: tones are on (sidebar \(hex(t.sidebar)))"); return true }
        guard (want == "dark") == t.isDark else { write("FAIL CHROME-TONES \(want): the tones are \(t.isDark ? "dark" : "light")"); return true }
        write("CHROME-TONES \(want) sidebar=\(hex(t.sidebar)) tabStrip=\(hex(t.tabStrip)) activeTab=\(hex(t.activeTab)) text=\(hex(t.text)) accentUsable=\(tones.accentUsable)")
        guard let window, let picture = await settledPicture(of: window) else { write("FAIL CHROME-TONES: no picture of the main window"); return true }
        let image = picture.image
        let scale = CGFloat(image.width) / max(window.frame.width, 1)
        guard let data = image.dataProvider?.data, let bytes = CFDataGetBytePtr(data) else { write("FAIL CHROME-TONES: unreadable picture"); return true }
        let bpr = image.bytesPerRow, bpp = image.bitsPerPixel / 8
        let bgra = image.bitmapInfo.contains(.byteOrder32Little)
        func px(_ x: Int, _ y: Int) -> SelectionContrast.RGB {
            let o = y * bpr + x * bpp
            let (r, g, b) = bgra ? (bytes[o + 2], bytes[o + 1], bytes[o]) : (bytes[o], bytes[o + 1], bytes[o + 2])
            return .init(r: Double(r) / 255, g: Double(g) / 255, b: Double(b) / 255)
        }
        /// A window-coordinate rect (origin bottom-left) as picture pixels.
        func box(_ r: NSRect) -> (Int, Int, Int, Int) {
            let x0 = max(0, Int(r.minX * scale)), x1 = min(image.width, Int(r.maxX * scale))
            let y0 = max(0, Int((window.frame.height - r.maxY) * scale)), y1 = min(image.height, Int((window.frame.height - r.minY) * scale))
            return (x0, y0, x1, y1)
        }
        func check(_ name: String, _ rect: NSRect?, _ rgb: UInt32, textFloor: Double) {
            guard let rect, rect.width > 4, rect.height > 4 else { return write("FAIL CHROME-TONES \(name): not on screen") }
            let tone = SelectionContrast.RGB(r: Double(rgb >> 16 & 0xff) / 255, g: Double(rgb >> 8 & 0xff) / 255, b: Double(rgb & 0xff) / 255)
            let (x0, y0, x1, y1) = box(rect.insetBy(dx: 2, dy: 2))
            var n = 0, hit = 0, best = 1.0
            for y in stride(from: y0, to: y1, by: 2) { for x in stride(from: x0, to: x1, by: 2) {
                let c = px(x, y); n += 1
                if abs(c.r - tone.r) <= Self.tolerance && abs(c.g - tone.g) <= Self.tolerance && abs(c.b - tone.b) <= Self.tolerance { hit += 1 }
                else { best = max(best, SelectionContrast.ratio(c, tone)) }
            } }
            let share = n > 0 ? Double(hit) / Double(n) : 0
            let line = String(format: "CHROME-TONES %@ tone %@ share %.0f%% text %.2f", name, hex(rgb), share * 100, best)
            write(share < Self.minShare || best < textFloor ? "FAIL \(line) (needs \(Int(Self.minShare * 100))%% and \(textFloor):1)" : line)
        }
        func frame(_ name: String) -> NSRect? {
            guard let v = DriverEvents.headerViews[name]?.view, v.window === window else { return nil }
            return v.convert(v.bounds, to: nil)
        }
        check("sidebar", frame("library-sidebar"), t.sidebar, textFloor: floor)
        check("active-tab", frame("active-tab"), t.activeTab, textFloor: floor)
        check("library-switcher", frame("library-switcher"), t.toolbar, textFloor: floor)
        // The toolbar band: right of the tabs, under the title bar's top edge (no controls there in a wide window).
        let content = window.contentLayoutRect
        let band = NSRect(x: window.frame.width * 0.62, y: content.maxY + 4, width: window.frame.width * 0.12, height: max(8, window.frame.height - content.maxY - 8))
        check("toolbar", band, t.toolbar, textFloor: 1)
        return true
    }

    /// `chrome-tones-windows <main>|<torn>` (each off, dark or light): the main window's tones and each torn-off
    /// window's, which must match.
    func chromeTonesWindowsStep(_ arg: String) async {
        await settle(0.5)
        let main = DriverEvents.chromeTones.map { "\($0.raw.isDark ? "dark" : "light") sidebar \(hex($0.raw.sidebar))" } ?? "off"
        let others = DriverEvents.windowChromeTones.values.map { t in t.map { "\($0.raw.isDark ? "dark" : "light") strip \(hex($0.raw.tabStrip))" } ?? "off" }.sorted()
        let want = arg.split(separator: "|").map(String.init)
        let kind = { (s: String) in s.split(separator: " ").first.map(String.init) ?? "off" }
        let ok = want.count == 2 && kind(main) == want[0] && !others.isEmpty && others.allSatisfy { kind($0) == want[1] }
        write("\(ok ? "" : "FAIL ")CHROME-TONES-WINDOWS main=\(main) torn=[\(others.joined(separator: ", "))] (want \(arg))")
    }

    private func hex(_ v: UInt32) -> String { String(format: "#%06x", v) }
}
#endif
