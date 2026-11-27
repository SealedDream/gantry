import AppKit

/// The owner-approved connection icon set (D12, `docs/design/ICON-SET.md`): one coloured tile per
/// connection type, a monochrome glyph for Increase Contrast, and folder / credential outlines in
/// an identity colour. Drawn from the shared SVGs, never from SF Symbols or brand art.
enum ConnectionIcons {
    /// Core icon id → art name in `docs/design/icons`.
    static let artForId: [String: String] = [
        "ssh": "ssh", "services": "ssh", "processes": "ssh", "eventlog": "ssh",
        "telnet": "telnet",
        "local-terminal": "local", "local": "local", "powershell": "local", "wsl": "local",
        "rdp": "rdp", "vnc": "vnc", "serial": "serial",
        "sftp": "files", "scp": "files", "ftp": "files", "ftps": "files",
        "web": "web",
        // Official plugins: own marks in each product's colours (not the vendors' logos).
        // Keyed by the icon id `Icons.pluginIcon` gives each plugin connection type.
        "proxmox": "proxmox", "vcenter": "vmware", "esxi": "vmware", "plugin-postgres": "postgres",
        "plugin-docker": "docker",
    ]

    /// Art for a core icon id, or nil when the id is not a connection type in the set.
    static func art(for id: String) -> String? { artForId[id] }

    /// The tile (or, under Increase Contrast, the monochrome glyph in the label colour) for a
    /// connection type. Follows light and dark at draw time; cached per art, size and label.
    @MainActor static func tile(_ art: String, size: CGFloat, label: String) -> NSImage {
        let mono = NSWorkspace.shared.accessibilityDisplayShouldIncreaseContrast
        return cached("\(art)|\(size)|\(label)|\(mono)", size: size, label: label) { dark in
            mono ? recolor(art + "-mono", NSColor.labelColor) : tileSource(art, dark: dark)
        }
    }

    /// A monochrome drawing (`<art>-mono`, `folder`, `credential`) in `color`, resolved per appearance.
    @MainActor static func glyph(_ art: String, color: NSColor, token: String, size: CGFloat, label: String) -> NSImage {
        cached("\(art)|\(token)|\(size)|\(label)", size: size, label: label) { _ in recolor(art, color) }
    }

    // MARK: - Drawing

    @MainActor private static func cached(_ key: String, size: CGFloat, label: String,
                                          source: @escaping @Sendable (Bool) -> String?) -> NSImage {
        if let hit = imageCache[key] { return hit }
        let image = NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
            let dark = NSAppearance.currentDrawing().bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            guard let svg = source(dark), let drawn = svgImage(svg) else { return false }
            drawn.draw(in: rect)
            return true
        }
        image.accessibilityDescription = label
        imageCache[key] = image
        return image
    }
    @MainActor private static var imageCache: [String: NSImage] = [:]

    /// The tile SVG; in dark mode the SSH tile turns on its 1 px inner edge (owner, 2026-11-14).
    static func tileSource(_ art: String, dark: Bool) -> String? {
        guard let svg = ConnectionIconArt.svg[art] else { return nil }
        guard dark, svg.contains("class=\"dark-edge\"") else { return svg }
        return svg.replacingOccurrences(of: "stroke-opacity=\"0\"", with: "stroke-opacity=\".22\"")
    }

    /// The SVG with `currentColor` replaced by `color` resolved in the current drawing appearance.
    private static func recolor(_ art: String, _ color: NSColor) -> String? {
        guard let svg = ConnectionIconArt.svg[art] else { return nil }
        return svg.replacingOccurrences(of: "currentColor", with: hex(color))
    }

    static func hex(_ color: NSColor) -> String {
        guard let c = color.usingColorSpace(.sRGB) else { return "#808080" }
        func byte(_ v: CGFloat) -> Int { Int((min(max(v, 0), 1) * 255).rounded()) }
        return String(format: "#%02X%02X%02X", byte(c.redComponent), byte(c.greenComponent), byte(c.blueComponent))
    }

    /// Parsed SVG images, keyed by source text (a handful of variants in all).
    private static func svgImage(_ svg: String) -> NSImage? {
        svgLock.lock(); defer { svgLock.unlock() }
        if let hit = svgCache[svg] { return hit }
        let image = NSImage(data: Data(svg.utf8))
        svgCache[svg] = image
        return image
    }
    nonisolated(unsafe) private static var svgCache: [String: NSImage] = [:]
    private static let svgLock = NSLock()

    /// Art the map needs that is missing or does not parse. Empty when in sync with `docs/design/icons`.
    static func missingArt() -> [String] {
        let names = Set(artForId.values).flatMap { [$0, $0 + "-mono"] } + ["folder", "credential"]
        return names.filter { name in ConnectionIconArt.svg[name].flatMap(svgImage) == nil }.sorted()
    }
}
