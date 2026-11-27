import AppKit
import SwiftUI
import BastionCore

/// Icons a user can give one connection instead of its type icon (core `model::ICONS`). The
/// core owns the list and refuses other names; this only draws a name it sends. Same 24-unit
/// stroke drawings as Tauri (`ui-tauri/src/lib/icons.js`), so the four apps show one picture.
enum OwnIcons {
    static let paths: [String: String] = [
        "server": "M4 4h16v6H4zM4 14h16v6H4zM7.5 7h.01M7.5 17h.01",
        "desktop": "M3 4h18v12H3zM8 20h8M12 16v4",
        "terminal": "M4 5h16v14H4zM7.5 9.5l3 2.5-3 2.5M12.5 15h4",
        "database": "M5 6c0-1.7 3.1-3 7-3s7 1.3 7 3v12c0 1.7-3.1 3-7 3s-7-1.3-7-3zM5 6c0 1.7 3.1 3 7 3s7-1.3 7-3M5 12c0 1.7 3.1 3 7 3s7-1.3 7-3",
        "network": "M9 3h6v5H9zM12 8v4M5 12h14M5 12v4M12 12v4M19 12v4M3 16h4v4H3zM10 16h4v4h-4zM17 16h4v4h-4z",
        "cloud": "M7 18h10a4 4 0 00.5-8 6 6 0 00-11.4 1.6A3.2 3.2 0 007 18z",
        "container": "M3 7.5L12 3l9 4.5v9L12 21l-9-4.5zM3 7.5l9 4.5 9-4.5M12 12v9",
        "globe": "M12 3a9 9 0 100 18 9 9 0 000-18zM3 12h18M12 3c2.4 2.5 3.5 5.5 3.5 9s-1.1 6.5-3.5 9M12 3c-2.4 2.5-3.5 5.5-3.5 9s1.1 6.5 3.5 9",
        "shield": "M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6z",
        "storage": "M3 6h7l2 2h9v11H3z",
    ]

    /// The names the core accepts, in its order, limited to ones this app can draw.
    @MainActor static let names: [String] = connectionIconNames().filter { paths[$0] != nil }

    /// Display name for a menu, tooltip or screen reader ("database" → "Database").
    static func label(_ name: String) -> String { name.prefix(1).uppercased() + name.dropFirst() }

    /// SVG source for one icon in a 24-unit box, stroked in black; nil for an unknown name.
    static func svg(_ name: String) -> String? {
        guard let d = paths[name] else { return nil }
        return """
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="none" \
        stroke="#000" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"><path d="\(d)"/></svg>
        """
    }

    /// Template image at `side` points, tinted by the view that shows it.
    @MainActor static func image(_ name: String, side: CGFloat) -> NSImage? {
        let key = "\(name)@\(side)"
        if let hit = cache[key] { return hit }
        guard let source = svg(name), let svgImage = NSImage(data: Data(source.utf8)) else { return nil }
        let image = NSImage(size: NSSize(width: side, height: side), flipped: false) { rect in
            svgImage.draw(in: rect)
            return true
        }
        image.isTemplate = true
        image.accessibilityDescription = label(name)
        cache[key] = image
        return image
    }
    @MainActor private static var cache: [String: NSImage] = [:]
}

/// A connection's icon: its own choice when set, tinted with its type colour, else the type icon.
struct ConnectionIcon: View {
    let proto: String
    let own: String?
    var size: CGFloat = 14

    var body: some View {
        if let own, let image = OwnIcons.image(own, side: Icons.tileSide(size)) {
            let info = Icons.info(proto)
            Image(nsImage: image).renderingMode(.template).resizable()
                .frame(width: Icons.tileSide(size), height: Icons.tileSide(size))
                .foregroundStyle(Color(nsColor: Icons.dynamicColor(info.tint)))
                .frame(width: max(size + 4, Icons.tileSide(size)))
                .help("\(info.label) · \(OwnIcons.label(own))")
                .accessibilityLabel(info.label)
        } else {
            ObjectIcon(id: proto, size: size)
        }
    }
}

/// Row of icon choices for one connection: the type icon (default) and each own icon. Picking
/// one saves it at once; picking the current own icon again clears it, as in Tauri.
struct OwnIconPicker: View {
    let connection: ConnectionView
    @Environment(LibraryModel.self) private var model

    var body: some View {
        let current = connection.ownIcon
        VStack(alignment: .leading, spacing: DS.Space.xxs) {
            Text(current.map(OwnIcons.label) ?? "Default for \(Icons.info(connection.protocol).label)")
                .font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 28, maximum: 32), spacing: DS.Space.xxs)],
                      alignment: .leading, spacing: DS.Space.xxs) {
                choice(nil, selected: current == nil)
                ForEach(OwnIcons.names, id: \.self) { choice($0, selected: current == $0) }
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Icon")
        }
    }

    private func choice(_ name: String?, selected: Bool) -> some View {
        let label = name.map(OwnIcons.label) ?? "Default"
        return Button { pick(name) } label: {
            ConnectionIcon(proto: connection.protocol, own: name, size: 14)
                .frame(width: 28, height: 28)
                .background(selected ? Color.accentColor.opacity(0.18) : .clear, in: RoundedRectangle(cornerRadius: 5))
                .overlay(RoundedRectangle(cornerRadius: 5).strokeBorder(selected ? Color.accentColor : .clear, lineWidth: 1.5))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(label)
        .accessibilityLabel(label)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .uiProbe("icon-\(name ?? "default")")
    }

    private func pick(_ name: String?) {
        let id = connection.id
        let next = name == connection.ownIcon ? nil : name
        model.mutate { try $0.setIcon(id: id, icon: next) }
    }
}
