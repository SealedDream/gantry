import CoreGraphics
import Foundation

/// Rules for tab previews and the tab overview (B11, `docs/plans/B11-PREVIEWS.md`). Foundation only, so
/// `tests/tab-preview-test.sh` compiles it on its own.
enum TabPreviewRules {
    /// Pointer rest on a tab before its preview shows.
    static let hoverDelay: TimeInterval = 0.4
    /// A preview image is refreshed at most this often, and only while a preview or the overview is shown.
    static let refreshInterval: TimeInterval = 1.0
    /// Most previews kept; the least recently shown goes first.
    static let cacheLimit = 64
    /// Longest side of a preview image, in pixels.
    static let maxImageSide: CGFloat = 480
    /// The overview's tile width target; columns = max(1, floor(width / this)).
    static let tileWidth: CGFloat = 260

    static func columns(forWidth width: CGFloat) -> Int { max(1, Int((width / tileWidth).rounded(.down))) }

    /// Size of a preview for a picture of `size`: aspect kept, longest side at most `maxImageSide`, never enlarged.
    static func scaledSize(_ size: CGSize) -> CGSize {
        guard size.width > 0, size.height > 0 else { return .zero }
        let scale = min(1, maxImageSide / max(size.width, size.height))
        return CGSize(width: (size.width * scale).rounded(), height: (size.height * scale).rounded())
    }

    /// Whether a tab may show its remote screen: previews on, not locked, the connection does not hide it.
    static func mayShowImage(previewsOn: Bool, locked: Bool, connectionHidesPreview: Bool) -> Bool {
        previewsOn && !locked && !connectionHidesPreview
    }

    /// Overview keyboard: the index after an arrow key in a grid of `count` tiles and `columns` columns.
    static func move(_ index: Int, dx: Int, dy: Int, count: Int, columns: Int) -> Int {
        guard count > 0 else { return 0 }
        let next = index + dx + dy * max(1, columns)
        return min(max(next, 0), count - 1)
    }
}

/// In-memory preview images, one per tab, capped and least-recently-shown first out. Never written anywhere.
/// `Image` is `CGImage` in the app and a stand-in in the test.
final class PreviewCache<Key: Hashable, Image> {
    private struct Entry {
        let image: Image
        let taken: Date
        var shown: UInt64
    }

    private var entries: [Key: Entry] = [:]
    private var clock: UInt64 = 0
    let limit: Int

    init(limit: Int = TabPreviewRules.cacheLimit) { self.limit = max(1, limit) }

    var count: Int { entries.count }

    /// The image for `key`, marking it as just shown.
    func image(for key: Key) -> Image? {
        guard var entry = entries[key] else { return nil }
        clock += 1
        entry.shown = clock
        entries[key] = entry
        return entry.image
    }

    /// Whether `key` needs a new image at `now` (none yet, or the last is older than the refresh interval).
    func needsRefresh(_ key: Key, now: Date) -> Bool {
        guard let entry = entries[key] else { return true }
        return now.timeIntervalSince(entry.taken) >= TabPreviewRules.refreshInterval
    }

    func store(_ image: Image, for key: Key, now: Date) {
        clock += 1
        entries[key] = Entry(image: image, taken: now, shown: clock)
        while entries.count > limit, let oldest = entries.min(by: { $0.value.shown < $1.value.shown })?.key {
            entries.removeValue(forKey: oldest)
        }
    }

    func remove(_ key: Key) { entries.removeValue(forKey: key) }

    /// Keep only the keys still open.
    func retain(_ keys: Set<Key>) { entries = entries.filter { keys.contains($0.key) } }

    /// Lock or previews turned off: drop every image at once.
    func clear() { entries.removeAll() }
}
