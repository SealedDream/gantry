import CoreGraphics
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}

let t0 = Date(timeIntervalSince1970: 1_000)

// Cap: the least recently shown goes first.
let cache = PreviewCache<Int, String>(limit: 3)
for i in 0..<3 { cache.store("img\(i)", for: i, now: t0) }
_ = cache.image(for: 0)
cache.store("img3", for: 3, now: t0)
check(cache.count == 3, "cache never holds more than its limit")
check(cache.image(for: 1) == nil, "least recently shown image dropped first")
check(cache.image(for: 0) == "img0", "recently shown image kept")
check(PreviewCache<Int, String>().limit == TabPreviewRules.cacheLimit, "default cap is 64")

// Refresh at most once a second.
check(cache.needsRefresh(9, now: t0), "missing image needs a refresh")
check(!cache.needsRefresh(3, now: t0.addingTimeInterval(0.5)), "no refresh within a second")
check(cache.needsRefresh(3, now: t0.addingTimeInterval(1.0)), "refresh after a second")

// Lock and closed tabs.
cache.retain([0, 3])
check(cache.count == 2 && cache.image(for: 2) == nil, "closed tabs leave the cache")
cache.clear()
check(cache.count == 0, "lock clears every image")

// Who may show the remote screen.
check(TabPreviewRules.mayShowImage(previewsOn: true, locked: false, connectionHidesPreview: false), "shown normally")
check(!TabPreviewRules.mayShowImage(previewsOn: true, locked: true, connectionHidesPreview: false), "never while locked")
check(!TabPreviewRules.mayShowImage(previewsOn: true, locked: false, connectionHidesPreview: true), "never for Hide tab preview")
check(!TabPreviewRules.mayShowImage(previewsOn: false, locked: false, connectionHidesPreview: false), "never with previews off")

// Sizes and grid.
check(TabPreviewRules.scaledSize(CGSize(width: 1920, height: 1080)) == CGSize(width: 480, height: 270), "1080p scales to 480 wide")
check(TabPreviewRules.scaledSize(CGSize(width: 300, height: 200)) == CGSize(width: 300, height: 200), "small pictures are not enlarged")
check(TabPreviewRules.scaledSize(.zero) == .zero, "empty picture stays empty")
check(TabPreviewRules.columns(forWidth: 100) == 1, "at least one column")
check(TabPreviewRules.columns(forWidth: 1040) == 4, "1040 pt gives four columns")
check(TabPreviewRules.move(0, dx: 0, dy: 1, count: 10, columns: 4) == 4, "down moves one row")
check(TabPreviewRules.move(9, dx: 1, dy: 0, count: 10, columns: 4) == 9, "right stops at the last tile")
check(TabPreviewRules.move(1, dx: 0, dy: -1, count: 10, columns: 4) == 0, "up stops at the first tile")
check(TabPreviewRules.move(0, dx: 1, dy: 0, count: 0, columns: 4) == 0, "empty overview")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
