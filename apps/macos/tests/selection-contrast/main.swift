import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}
typealias C = SelectionContrast

// The palette (core/src/theme.rs ACCENTS).
let accents: [(String, Int)] = [("electric", 0x2E6BFF), ("cyan", 0x00A8D1), ("violet", 0x7D5CFF),
                                ("emerald", 0x0FA673), ("amber", 0xE6940A), ("rose", 0xED405E)]
func rgb(_ h: Int) -> C.RGB { C.RGB(r: Double(h >> 16 & 255) / 255, g: Double(h >> 8 & 255) / 255, b: Double(h & 255) / 255) }

check(abs(C.ratio(.white, .black) - 21) < 0.01, "white on black is 21:1")
check(abs(C.ratio(.white, .white) - 1) < 0.001, "same colour is 1:1")
check(C.ratio(.white, rgb(0x00A8D1)) < 4.5, "raw cyan fails with white text (the owner's report)")
for (name, hex) in accents {
    let fill = C.readableFill(for: rgb(hex))
    let r = C.ratio(.white, fill)
    print(String(format: "  %@ fill #%02X%02X%02X white %.2f", name, Int(fill.r * 255 + 0.5), Int(fill.g * 255 + 0.5), Int(fill.b * 255 + 0.5), r))
    check(r >= C.requiredRatio, "\(name): white text on the selection fill is at least 4.5:1")
    check(C.ratio(.white, rgb(hex)) >= C.minimumRatio ? fill == rgb(hex) : true, "\(name): a readable accent is not darkened")
}
// Tabs: the selected tab is a 16 % accent wash over the light strip with primary (black) text.
let strip = C.RGB(r: 0.96, g: 0.96, b: 0.96)
for (name, hex) in accents {
    let wash = strip.mixed(with: rgb(hex), 0.16)
    check(C.ratio(C.RGB(r: 0, g: 0, b: 0).mixed(with: .white, 0.15), wash) >= C.requiredRatio, "\(name): selected tab text on its wash")
}
exit(failures == 0 ? 0 : 1)
