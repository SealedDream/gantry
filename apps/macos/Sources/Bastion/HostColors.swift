import AppKit
import SwiftUI
import BastionCore

/// Per-host colours (core `hostcolors`, the `host_color` property, inherited from folders). Worked
/// out once per tree change for every connection, so the tab strip, terminal border and tree badge
/// read a dictionary instead of calling the core on every redraw.
@MainActor
final class HostColors {
    static let shared = HostColors()

    struct Paint: Equatable {
        let accent: NSColor
        let text: NSColor
        let tint: NSColor
        /// Text-safe tone for a coloured name (core-checked 4.5:1, light and dark). `nil` for the
        /// production fallback, which keeps the plain label colour.
        var name: NSColor? = nil
        /// The connection is marked privileged: the session strip says "Production".
        var privileged = false
    }

    /// Coloured text only while Increase Contrast is off; the icon keeps the colour either way.
    static var tintsText: Bool { !NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast }

    private var byConnection: [String: Paint] = [:]
    /// Connections tagged production (accessibility and the UI driver).
    private(set) var productionIds: Set<String> = []

    func paint(for connectionId: String?) -> Paint? {
        connectionId.flatMap { byConnection[$0] }
    }

    /// A folder's own or inherited colour (the core lists folders with connections, UI-01).
    func folderPaint(for folderId: String) -> Paint? { byConnection[folderId] }

    /// Called by `LibraryModel` whenever the tree is replaced.
    func refresh(library: Library?, tree: FolderView?) {
        guard let library else { byConnection = [:]; return }
        // One core call for all connections: one `hostColor(id:)` per connection resolved each with a
        // walk of the whole tree (~120 ms per library edit at 5,000 connections).
        var next: [String: Paint] = [:]
        for entry in (try? library.hostColors()) ?? [] {
            guard let paint = Self.paint(entry.color) else { continue }
            next[entry.id] = paint
        }
        // TERM-MARKS: production-tagged connections without a colour of their own get the red accent.
        let production = ProductionAccent.ids(in: tree)
        for id in production where next[id] == nil { next[id] = ProductionAccent.paint }
        productionIds = production
        byConnection = next
    }

    static func paint(_ v: HostColorView) -> Paint? {
        guard let accent = color(hex: v.accent), let text = color(hex: v.text), let tint = color(hex: v.tint),
              let light = color(hex: v.fgLight), let dark = color(hex: v.fgDark) else { return nil }
        let name = NSColor(name: nil) { $0.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light }
        return Paint(accent: accent, text: text, tint: tint, name: name, privileged: v.privileged)
    }

    /// `#rrggbb` or `#rrggbbaa`.
    static func color(hex: String) -> NSColor? {
        let s = hex.hasPrefix("#") ? String(hex.dropFirst()) : hex
        guard s.count == 6 || s.count == 8, let v = UInt64(s, radix: 16) else { return nil }
        let (rgb, alpha) = s.count == 8 ? (v >> 8, Double(v & 0xff) / 255) : (v, 1.0)
        return NSColor(srgbRed: Double(rgb >> 16 & 0xff) / 255, green: Double(rgb >> 8 & 0xff) / 255,
                       blue: Double(rgb & 0xff) / 255, alpha: alpha)
    }
}
