// Unit test for WindowLaunch: clamping to the screen and the fallback to the main screen.
import CoreGraphics
var failures = 0
func check(_ ok: Bool, _ what: String) { print(ok ? "PASS" : "FAIL", what); if !ok { failures += 1 } }
let main = CGRect(x: 0, y: 0, width: 1512, height: 944)
let right = CGRect(x: 1512, y: 0, width: 2560, height: 1415)
check(WindowLaunch.centred(width: 1280, height: 800, in: main) == CGRect(x: 116, y: 72, width: 1280, height: 800), "a fixed size is centred on its screen")
check(WindowLaunch.centred(width: 4000, height: 3000, in: main) == main, "a fixed size larger than the screen is clamped to it")
check(WindowLaunch.clamp(CGRect(x: 100, y: 50, width: 1000, height: 700), to: main) == CGRect(x: 100, y: 50, width: 1000, height: 700), "a frame that fits stays")
check(WindowLaunch.clamp(CGRect(x: 1000, y: 600, width: 1000, height: 700), to: main) == CGRect(x: 512, y: 244, width: 1000, height: 700), "a frame running off the screen moves back inside")
check(WindowLaunch.clamp(CGRect(x: -50, y: -20, width: 2500, height: 1300), to: main) == main, "a frame larger than the screen shrinks to it")
check(WindowLaunch.visibleArea(for: CGRect(x: 2000, y: 100, width: 1200, height: 800), screens: [main, right], main: main) == right, "a frame on the second screen opens there")
check(WindowLaunch.visibleArea(for: CGRect(x: 5000, y: 100, width: 1200, height: 800), screens: [main], main: main) == main, "a saved screen that is gone falls back to the main screen")
check(WindowLaunch.Mode(rawValue: "full-screen") == .fullScreen && WindowLaunch.Mode(rawValue: "x") == nil, "modes match the core ids")
if failures > 0 { fatalError("\(failures) failed") }
