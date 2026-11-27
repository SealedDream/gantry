import AppKit
import SwiftUI
import BastionCore

/// Maps the core's icon ids (`icons.rs`) to SF Symbols and its tint tokens (`theme.rs`) to colours,
/// so the tree, inspector and menus share one picture language with the Windows app.
enum Icons {
    /// SF Symbol per core icon id. `coverageProblems()` checks it against the core list.
    static let symbols: [String: String] = [
        // Owner feedback 10: SSH and RDP must be told apart at a glance.
        "ssh": "terminal.fill",
        "rdp": "desktopcomputer",
        "vnc": "rectangle.inset.filled.on.rectangle",
        "web": "globe",
        "sftp": "externaldrive.connected.to.line.below",
        "scp": "doc.on.doc",
        "ftp": "arrow.up.arrow.down.square",
        "ftps": "arrow.up.arrow.down.square",
        "telnet": "keyboard",
        "serial": "cable.connector",
        "powershell": "chevron.left.forwardslash.chevron.right",
        "local-terminal": "apple.terminal",
        "local": "apple.terminal",
        "services": "gearshape.2",
        "processes": "cpu",
        "eventlog": "list.bullet.rectangle",
        "wsl": "pc",
        "esxi": "server.rack",
        "vcenter": "square.stack.3d.up",
        "proxmox": "cube",
        "hyperv": "square.3.layers.3d",
        "docker": "shippingbox",
        "kubernetes": "helm",
        "cluster": "circle.grid.cross",
        "datacenter": "building.2",
        "storage": "internaldrive",
        "network": "network",
        "vm-running": "play.circle",
        "vm-stopped": "stop.circle",
        "vm-suspended": "pause.circle",
        "vm-unknown": "questionmark.circle",
        "container": "shippingbox.circle",
        "credential": "key",
        "task": "bolt",
        "gateway": "point.3.connected.trianglepath.dotted",
        "folder": "folder",
        "favorite": "star.fill",
        "workspace": "rectangle.stack",
        "keyboard": "keyboard",
        "settings": "gearshape",
        "appearance": "paintpalette",
        "defaults": "slider.horizontal.3",
        "vault": "lock.shield",
        "security": "hand.raised",
        "update": "arrow.down.circle",
        "about": "info.circle",
        // Not a core id: the PostgreSQL plugin type (`pluginIcon`); its tile comes from ConnectionIcons.
        "plugin-postgres": "cylinder.split.1x2",
    ]

    /// SF Symbol for an action glyph name from the registry (`MenuItemView.glyph`).
    static let actionSymbols: [String: String] = [
        "connect": "play.fill", "tab": "plus.rectangle", "window": "macwindow", "fullscreen": "arrow.up.left.and.arrow.down.right",
        "reconnect": "arrow.clockwise", "disconnect": "xmark.circle", "sftp": "externaldrive.connected.to.line.below",
        "copy": "doc.on.clipboard", "add": "plus", "folder-add": "folder.badge.plus", "expand": "chevron.down.square",
        "collapse": "chevron.up.square", "sort": "arrow.up.arrow.down", "rename": "pencil", "duplicate": "plus.square.on.square", "template": "doc.badge.plus",
        "move": "folder", "favorite": "star", "properties": "slider.horizontal.3", "trash": "trash",
        "import": "square.and.arrow.down", "export": "square.and.arrow.up", "workspace": "rectangle.stack",
        "appearance": "paintpalette", "credential": "key", "gateway": "point.3.connected.trianglepath.dotted", "task": "bolt",
        "console": "terminal", "ssh": "terminal", "rdp": "display", "vnc": "rectangle.inset.filled.on.rectangle",
        "power-start": "play.fill", "power-shutdown": "power", "power-reboot": "restart.circle", "power-stop": "stop.circle",
        "power-reset": "arrow.clockwise", "power-suspend": "pause.circle", "power-resume": "play.circle",
        "monitor": "gauge.with.dots.needle.33percent", "snapshot": "camera", "backup": "tray.full", "refresh": "arrow.clockwise",
        "options": "slider.horizontal.3",
    ]

    static func symbol(_ id: String) -> String { symbols[id] ?? "questionmark.square.dashed" }

    /// Core icon (full label and tint token) for a protocol wire name or icon id. Cached: it never changes.
    @MainActor static func info(_ id: String) -> IconView {
        if let hit = cache[id] { return hit }
        let v = pluginIcon(id) ?? iconFor(id: id)
        cache[id] = v
        return v
    }
    @MainActor private static var cache: [String: IconView] = [:]

    /// Drops cached plugin-type icons after plugins change.
    @MainActor static func forgetPluginIcons() { cache = cache.filter { !$0.key.contains("/") } }

    /// A plugin connection type (`<plugin id>/<type id>`) of a known kind: its icon from the core
    /// set and the type's name, instead of the core's unknown-type folder (PLUG-08 Mac).
    @MainActor private static func pluginIcon(_ id: String) -> IconView? {
        guard let type = PluginEntries.types.first(where: { $0.id == id }) else { return nil }
        // `iconId` is the art key for the known types (ConnectionIcons); `kind` the core icon for the tint.
        let kind: String, iconId: String?
        switch id.hasSuffix(".docker/host") ? "docker" : id.split(separator: "/").last {
        case "postgres": (kind, iconId) = ("storage", "plugin-postgres")
        case "pve": (kind, iconId) = ("proxmox", nil)
        case "vcenter", "esxi": (kind, iconId) = ("vcenter", nil)
        case "docker": (kind, iconId) = ("network", "plugin-docker")
        default: (kind, iconId) = ("network", nil)
        }
        let base = iconFor(id: kind)
        return IconView(id: iconId ?? base.id, label: type.name, tint: base.tint)
    }

    /// Colour for a core token in the dark or light appearance.
    static func color(_ token: String, dark: Bool) -> NSColor {
        (dark ? darkTokens : lightTokens)[token] ?? .secondaryLabelColor
    }

    /// A colour that follows the appearance of whatever draws it.
    static func dynamicColor(_ token: String) -> NSColor {
        NSColor(name: nil) { appearance in
            color(token, dark: appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua)
        }
    }

    private static let darkTokens = parse(themeColors(dark: true))
    private static let lightTokens = parse(themeColors(dark: false))

    private static func parse(_ tokens: [ColorTokenView]) -> [String: NSColor] {
        Dictionary(uniqueKeysWithValues: tokens.map { t in
            let v = UInt32(t.hex.dropFirst(), radix: 16) ?? 0
            return (t.name, NSColor(srgbRed: CGFloat((v >> 16) & 0xff) / 255, green: CGFloat((v >> 8) & 0xff) / 255,
                                    blue: CGFloat(v & 0xff) / 255, alpha: 1))
        })
    }

    /// Tinted symbol image for AppKit cells, labelled with the full name.
    /// Connection types and folder / credential come from the approved set (`ConnectionIcons`);
    /// everything else stays an SF Symbol. `pointSize` is the symbol size; the tile is drawn
    /// at the matching 16 / 20 px row size.
    @MainActor static func image(_ id: String, pointSize: CGFloat) -> NSImage? {
        let info = info(id)
        let side = tileSide(pointSize)
        if let art = ConnectionIcons.art(for: id) ?? ConnectionIcons.art(for: info.id) {
            return ConnectionIcons.tile(art, size: side, label: info.label)
        }
        if info.id == "folder" || info.id == "credential" {
            return ConnectionIcons.glyph(info.id, color: dynamicColor(info.tint), token: info.tint, size: side, label: info.label)
        }
        return tinted(symbol(info.id), token: info.tint, pointSize: pointSize, label: info.label)
    }

    /// Image side for a symbol point size: a 13 pt symbol fills about a 16 px box.
    static func tileSide(_ pointSize: CGFloat) -> CGFloat { (pointSize * 1.25).rounded() }

    /// Cached per symbol, colour token, size and label: tree cells ask for the same few images on
    /// every reload, and building a configured symbol image costs more than the rest of a cell.
    /// The colour is dynamic, so a cached image still follows light and dark.
    static func tinted(_ symbol: String, token: String, pointSize: CGFloat, label: String) -> NSImage? {
        let key = "\(symbol)|\(token)|\(pointSize)|\(label)"
        if let hit = tintedCache.object(forKey: key as NSString) { return hit }
        let config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: .regular)
            .applying(.init(paletteColors: [dynamicColor(token)]))
        let image = NSImage(systemSymbolName: symbol, accessibilityDescription: label)?.withSymbolConfiguration(config)
        if let image { tintedCache.setObject(image, forKey: key as NSString) }
        return image
    }
    nonisolated(unsafe) private static let tintedCache = NSCache<NSString, NSImage>()

    /// Core icon ids without a symbol here, or whose symbol this macOS lacks. Empty when in sync.
    @MainActor static func coverageProblems() -> [String] {
        let core = Set(allIcons().map(\.id))
        return core.subtracting(symbols.keys).map { "no symbol for \($0)" }
            + core.filter { NSImage(systemSymbolName: symbol($0), accessibilityDescription: nil) == nil }.map { "missing SF Symbol for \($0)" }
    }
}

/// A protocol or object icon in its tint, with the full name as tooltip and accessibility label.
struct ObjectIcon: View {
    let id: String
    var size: CGFloat = 14

    var body: some View {
        let info = Icons.info(id)
        Group {
            if ConnectionIcons.art(for: id) ?? ConnectionIcons.art(for: info.id) != nil
                || info.id == "folder" || info.id == "credential",
               let image = Icons.image(id, pointSize: size) {
                Image(nsImage: image).resizable().frame(width: Icons.tileSide(size), height: Icons.tileSide(size))
            } else {
                Image(systemName: Icons.symbol(info.id))
                    .font(DS.Font.size(size))
                    .foregroundStyle(Color(nsColor: Icons.dynamicColor(info.tint)))
            }
        }
            .frame(width: max(size + 4, Icons.tileSide(size)))
            .help(info.label)
            .accessibilityLabel(info.label)
    }
}
