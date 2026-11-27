import CoreGraphics

/// Settings › General › Window at launch (core `window.launch`, `window.launch-width`, `window.launch-height`; owner
/// 2026-11-15). The size rules, shared with Windows (apps/windows/WindowLaunch.cs). CoreGraphics only, so
/// tests/window-launch builds it alone. Frames are in AppKit screen points.
enum WindowLaunch {
    static let settingId = "window.launch", widthId = "window.launch-width", heightId = "window.launch-height"
    enum Mode: String { case remember, fixed, maximized, fullScreen = "full-screen" }

    /// A size never larger than the visible area, centred in it.
    static func centred(width: CGFloat, height: CGFloat, in visible: CGRect) -> CGRect {
        let w = min(max(width, 1), visible.width), h = min(max(height, 1), visible.height)
        return CGRect(x: visible.minX + (visible.width - w) / 2, y: visible.minY + (visible.height - h) / 2, width: w, height: h).integral
    }

    /// A remembered frame fitted to the visible area: shrunk to fit, then moved inside it.
    static func clamp(_ frame: CGRect, to visible: CGRect) -> CGRect {
        let w = min(max(frame.width, 1), visible.width), h = min(max(frame.height, 1), visible.height)
        let x = min(max(frame.minX, visible.minX), visible.maxX - w)
        let y = min(max(frame.minY, visible.minY), visible.maxY - h)
        return CGRect(x: x, y: y, width: w, height: h)
    }

    /// The visible area a frame belongs to: the screen it overlaps most, else the main screen (its monitor is gone).
    static func visibleArea(for frame: CGRect, screens: [CGRect], main: CGRect) -> CGRect {
        var best: CGRect?
        var bestArea: CGFloat = 0
        for screen in screens {
            let overlap = screen.intersection(frame)
            guard !overlap.isNull else { continue }
            let area = overlap.width * overlap.height
            if area > bestArea { bestArea = area; best = screen }
        }
        return best ?? main
    }
}
