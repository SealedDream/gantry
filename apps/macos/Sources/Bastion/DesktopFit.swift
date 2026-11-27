import AppKit
import BastionCore

/// How a remote desktop meets its tab (connection property `display.fit`, RDP and VNC).
enum DesktopFit: String {
    /// The server's desktop follows the tab's size; a server that refuses is scaled to fit.
    case fit
    /// The desktop at its own size, 1:1, centred.
    case fixed
    /// The desktop at its own size, scaled to the tab, keeping its shape.
    case scale

    static let propertyKey = "display.fit"
    static let resolutionKey = "rdp.resolution"
    /// Used before any desktop tab has been laid out and no window is open.
    static let fallbackSize = (width: 1280, height: 800)

    static func of(_ library: Library?, connectionId: String?) -> DesktopFit {
        value(propertyKey, library: library, connectionId: connectionId).flatMap(DesktopFit.init(rawValue:)) ?? .fit
    }

    /// The size an RDP connect asks for: the tab's for Fit to tab (or Desktop size Window), else
    /// the connection's Desktop size.
    static func rdpConnectSize(_ library: Library?, connectionId: String?) -> (width: UInt16, height: UInt16) {
        let tab = tabSize()
        guard of(library, connectionId: connectionId) != .fit,
              let parsed = parse(value(resolutionKey, library: library, connectionId: connectionId)) else {
            return (UInt16(clamping: tab.width), UInt16(clamping: tab.height))
        }
        return (UInt16(clamping: parsed.width), UInt16(clamping: parsed.height))
    }

    /// "1920x1080" → (1920, 1080); "window", empty or malformed → nil.
    static func parse(_ value: String?) -> (width: Int, height: Int)? {
        guard let parts = value?.split(separator: "x"), parts.count == 2,
              let w = Int(parts[0]), let h = Int(parts[1]), w > 0, h > 0 else { return nil }
        return (w, h)
    }

    /// The last laid-out desktop tab, else the key window's content area, in points.
    static func tabSize() -> (width: Int, height: Int) {
        if let last = RemoteDesktopCanvas.lastViewSize { return (Int(last.width), Int(last.height)) }
        if let rect = NSApp.keyWindow?.contentLayoutRect, rect.width >= 1, rect.height >= 1 {
            return (Int(rect.width), Int(rect.height))
        }
        return fallbackSize
    }

    private static func value(_ key: String, library: Library?, connectionId: String?) -> String? {
        guard let library, let id = connectionId else { return nil }
        return (try? library.propertyValues(id: id))?.first { $0.key == key }?.effective
    }
}
