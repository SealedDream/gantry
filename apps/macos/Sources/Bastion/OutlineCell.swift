import AppKit
import BastionCore

/// One tree row: tinted object icon, name, then separate trailing indicators for session state,
/// favourite and source problems. Never a lowercase protocol label.
final class OutlineCell: NSTableCellView {
    static let identifier = NSUserInterfaceItemIdentifier("OutlineCell")

    private let icon = NSImageView()
    private let name = NSTextField(labelWithString: "")
    private let detail = NSTextField(labelWithString: "")
    private let status = NSImageView()
    private let star = NSImageView()
    private let warning = NSImageView()
    /// Per-host colour badge (`host_color`).
    private let badge = NSView(frame: NSRect(x: 0, y: 0, width: 8, height: 8))

    override init(frame: NSRect) {
        super.init(frame: frame)
        identifier = Self.identifier
        name.lineBreakMode = .byTruncatingTail
        detail.textColor = .secondaryLabelColor
        detail.font = .monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
        star.image = Icons.tinted("star.fill", token: "favorite", pointSize: 9, label: "Favorite")
        star.toolTip = "Favorite"
        warning.image = NSImage(systemSymbolName: "exclamationmark.triangle", accessibilityDescription: "Removed from SSH config")?
            .withSymbolConfiguration(.init(pointSize: 10, weight: .regular))
        warning.contentTintColor = .secondaryLabelColor
        warning.toolTip = "Removed from SSH config"
        imageView = icon
        textField = name
        // Frame layout, not a stack view with constraints: filtering a large tree creates many
        // cells at once, and Auto Layout per cell dominated that cost.
        badge.wantsLayer = true
        badge.layer?.cornerRadius = 4
        for v in [icon, name, detail, warning, status, star, badge] as [NSView] { addSubview(v) }
    }

    override func layout() {
        super.layout()
        let h = bounds.height, gap: CGFloat = 6
        func place(_ v: NSView, x: CGFloat, width: CGFloat) {
            // A label's height is its font's line height: asking the text field for its fitting
            // size measured the text on every layout (nm-22: most of a filter keystroke's cell cost).
            let vh = min(h, (v as? NSTextField).map { Self.lineHeight($0.font) } ?? v.fittingSize.height)
            v.frame = NSRect(x: x, y: ((h - vh) / 2).rounded(), width: max(0, width), height: vh)
        }
        var right = bounds.width - 6
        for v in [star, status, warning, detail, badge] as [NSView] where !v.isHidden {
            if v === badge {
                right -= 8
                v.frame = NSRect(x: right, y: ((h - 8) / 2).rounded(), width: 8, height: 8)
                right -= gap
                continue
            }
            let w = v.fittingSize.width
            right -= w
            place(v, x: right, width: w)
            right -= gap
        }
        var left: CGFloat = 2
        if !icon.isHidden { place(icon, x: left, width: 18); left += 18 + gap }
        place(name, x: left, width: right - left)
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    /// A label field's height for `font` (line height plus the cell's 2 pt), cached per font.
    private static func lineHeight(_ font: NSFont?) -> CGFloat {
        let font = font ?? .systemFont(ofSize: NSFont.systemFontSize)
        if let hit = lineHeights[font] { return hit }
        let probe = NSTextField(labelWithString: "Ag")
        probe.font = font
        let value = probe.fittingSize.height
        lineHeights[font] = value
        return value
    }
    @MainActor private static var lineHeights: [NSFont: CGFloat] = [:]

    /// `collapsedSessions`: a library connection whose open sessions are hidden by its collapsed
    /// disclosure shows their count after its name (UI-05).
    @MainActor func configure(_ node: OutlineNode, state: SessionStateLabel?, iconSize: CGFloat, collapsedSessions: Int = 0, connectedInside: Int = 0) {
        name.isEditable = false
        icon.contentTintColor = nil
        warning.isHidden = true
        star.isHidden = true
        status.isHidden = true
        detail.isHidden = true
        badge.isHidden = true
        toolTip = nil
        name.font = DS.Role.itemName
        detail.font = DS.Role.secondary
        name.textColor = .labelColor
        // AppKit restyles a source-list group row's `textField` (dimmed to near-invisible here), so
        // a section header keeps its label out of that slot and styles it itself.
        textField = node.isGroup ? nil : name
        switch node.kind {
        case .group(let title):
            icon.isHidden = true
            name.font = DS.Role.sectionLabel
            name.textColor = .secondaryLabelColor
            name.stringValue = title
            setAccessibilityLabel(title)
        case .folder(let f):
            icon.isHidden = false
            icon.image = Icons.image("folder", pointSize: iconSize)
            icon.toolTip = "Folder"
            name.stringValue = f.name
            if let p = HostColors.shared.folderPaint(for: f.id) {
                icon.contentTintColor = p.accent
                if HostColors.tintsText, let tone = p.name { name.textColor = tone }
            }
            let count = f.connectionCount
            let label = "\(count) connection\(count == 1 ? "" : "s")"
            detail.stringValue = "\(count)"
            detail.isHidden = count == 0
            detail.toolTip = label
            var connectedText: String?
            if connectedInside > 0 {
                connectedText = "\(connectedInside) connected"
                status.isHidden = false
                status.image = Icons.tinted("circle.fill", token: "status.connected", pointSize: 7, label: connectedText!)
                status.toolTip = "\(connectedText!) inside"
                detail.stringValue = "\(connectedInside)/\(count)"
                detail.toolTip = "\(connectedText!) of \(label)"
            }
            setAccessibilityLabel(["\(f.name), folder, \(label)", connectedText].compactMap { $0 }.joined(separator: ", "))
        case .connection(let c):
            let info = Icons.info(c.protocol)
            icon.isHidden = false
            if let own = c.ownIcon, let image = OwnIcons.image(own, side: Icons.tileSide(iconSize)) {
                icon.image = image
                icon.contentTintColor = Icons.dynamicColor(info.tint)
            } else {
                icon.image = Icons.image(c.protocol, pointSize: iconSize)
            }
            icon.toolTip = info.label
            name.stringValue = c.name
            toolTip = "\(info.label) · \(c.username.map { "\($0)@" } ?? "")\(c.host)\(c.port.map { ":\($0)" } ?? "")"
            star.isHidden = !c.favorite || node.isFavoriteMirror
            if let p = HostColors.shared.paint(for: c.id) {
                // UI-01: the icon takes the identity colour, the name a text-safe tone of it.
                icon.contentTintColor = p.accent
                if HostColors.tintsText, let tone = p.name { name.textColor = tone }
                badge.isHidden = false
                badge.layer?.backgroundColor = p.accent.cgColor
                badge.toolTip = "Host colour"
            }
            // PLUG-03a: an entry of a type this build cannot open carries the core's fixed text.
            let warningText = PluginEntries.unavailable(c) ?? (c.sourceStatus == "removed-from-source" ? "Removed from SSH config" : nil)
            warning.isHidden = warningText == nil
            warning.toolTip = warningText
            warning.setAccessibilityLabel(warningText)
            if let why = PluginEntries.unavailable(c) {
                name.textColor = .secondaryLabelColor
                toolTip = "\(c.name) · \(why)"
            }
            if let state {
                status.isHidden = false
                status.image = Icons.tinted(state.symbol, token: state.token, pointSize: state.pointSize, label: state.label)
                status.toolTip = state.label
            }
            if collapsedSessions > 0 {
                let label = "\(collapsedSessions) session\(collapsedSessions == 1 ? "" : "s")"
                detail.stringValue = "(\(collapsedSessions))"
                detail.isHidden = false
                detail.toolTip = label
            }
            let sessions = collapsedSessions > 0 ? "\(collapsedSessions) session\(collapsedSessions == 1 ? "" : "s")" : nil
            setAccessibilityLabel([c.name, info.label, PluginEntries.unavailable(c), state?.label, sessions, c.favorite ? "favorite" : nil].compactMap { $0 }.joined(separator: ", "))
        case .session(let s, let parent):
            icon.isHidden = false
            icon.image = Self.dot(s.state)
            icon.toolTip = s.state.label.capitalized
            name.stringValue = s.title
            let text = [s.title, s.state.label, parent.map { "session of \($0)" }].compactMap { $0 }.joined(separator: ", ")
            toolTip = text
            setAccessibilityLabel(text)
        case .tool(let tool, let c):
            icon.isHidden = false
            icon.image = Icons.image(tool.iconId, pointSize: iconSize)
            name.stringValue = tool.label
            toolTip = "\(tool.label) of \(c.name) (read-only)"
            setAccessibilityLabel("\(tool.label), \(c.name)")
        case .generated(let g):
            icon.isHidden = false
            name.stringValue = g.title
            toolTip = g.tip
            switch g.kind {
            case .item(let p):
                icon.image = Icons.image(p, pointSize: iconSize)
                icon.toolTip = Icons.info(p).label
                setAccessibilityLabel("\(g.title), generated \(Icons.info(p).label)")
            case .group:
                icon.image = Icons.image("folder", pointSize: iconSize)
                setAccessibilityLabel("\(g.title), generated folder")
            case .status:
                icon.image = NSImage(systemSymbolName: "exclamationmark.triangle", accessibilityDescription: nil)
                name.textColor = .secondaryLabelColor
                setAccessibilityLabel("\(g.title), \(g.tip)")
            }
        case .pluginItem(let r):
            // Plain text from the plugin, in the library's own row style (plugin API 1.3).
            icon.isHidden = false
            name.stringValue = r.label
            switch r.kind {
            case .item(_, let hasChildren, let menu):
                icon.image = NSImage(systemSymbolName: hasChildren ? "square.stack.3d.up" : "desktopcomputer", accessibilityDescription: nil)
                let open = menu.first { $0.id == "open" }.map { ", double-click: \($0.title)" } ?? ""
                toolTip = r.label
                setAccessibilityLabel("\(r.label), from the plugin\(open)")
            case .status(let text):
                icon.image = NSImage(systemSymbolName: "ellipsis", accessibilityDescription: nil)
                name.textColor = .secondaryLabelColor
                toolTip = text
                setAccessibilityLabel(text)
            }
        case .tasks:
            icon.isHidden = false
            icon.image = AppIcons.image(.tasks, pointSize: iconSize)
            name.stringValue = "Tasks"
            setAccessibilityLabel("Tasks, folder")
        case .triggers:
            icon.isHidden = false
            icon.image = AppIcons.image(.triggers, pointSize: iconSize)
            name.stringValue = "Triggers"
            toolTip = "Run actions when terminal output matches"
            setAccessibilityLabel("Triggers")
        case .task(let t):
            icon.isHidden = false
            icon.image = NSImage(systemSymbolName: t.builtin ? "bolt.horizontal" : "terminal", accessibilityDescription: nil)
            name.stringValue = t.name
            star.isHidden = !t.favorite
            toolTip = t.builtin && t.kind != "custom" ? "Built-in task" : ([t.program] + t.args).joined(separator: " ") + (t.builtin ? " (edited built-in)" : "")
            setAccessibilityLabel([t.name, "task", t.favorite ? "favorite" : nil].compactMap { $0 }.joined(separator: ", "))
        }
        needsLayout = true
    }

    /// Layout-fit (UI-05): the icon or dot overlapping the name, the count or a trailing mark
    /// overlapping the name or clipped by the cell. Empty when it fits.
    /// The trailing warning marker's text when shown (UI tests).
    var markerText: String? { warning.isHidden ? nil : warning.toolTip }

    func fitProblems() -> [String] {
        var out: [String] = []
        let trailing = [detail, status, star, warning, badge].filter { !$0.isHidden }
        if !icon.isHidden, icon.frame.maxX > name.frame.minX + 0.5 { out.append("icon overlaps name") }
        for v in trailing {
            if v.frame.minX < name.frame.maxX - 0.5 { out.append("\(type(of: v)) overlaps name") }
            if v.frame.maxX > bounds.maxX + 0.5 || v.frame.minX < 0 { out.append("\(type(of: v)) clipped") }
        }
        if !detail.isHidden, detail.fittingSize.width > detail.frame.width + 0.5 { out.append("count clipped") }
        if name.frame.width < 1 { out.append("no room for name") }
        return out
    }

    /// The 8 pt status dot of a session row, in the state's colour (it follows light and dark).
    @MainActor static func dot(_ state: SessionRow.State) -> NSImage {
        if let hit = dots[state] { return hit }
        let color = Icons.dynamicColor(state.token)
        let image = NSImage(size: NSSize(width: 8, height: 8), flipped: false) { rect in
            color.setFill()
            NSBezierPath(ovalIn: rect).fill()
            return true
        }
        image.accessibilityDescription = state.label
        dots[state] = image
        return image
    }
    @MainActor private static var dots: [SessionRow.State: NSImage] = [:]

    /// Make the name editable and focus it; the outline's text delegate commits or cancels.
    func beginRename(in window: NSWindow?) {
        name.isEditable = true
        window?.makeFirstResponder(name)
        name.currentEditor()?.selectAll(nil)
    }
}

/// Distinct shape and colour per session state, so no single dot means several things.
struct SessionStateLabel {
    let symbol: String
    let token: String
    let label: String
    let pointSize: CGFloat

    static func of(_ id: String, in s: SessionSnapshot) -> SessionStateLabel? {
        if s.connected.contains(id) { return .init(symbol: "circle.fill", token: "status.connected", label: "Connected", pointSize: 7) }
        if s.connecting.contains(id) { return .init(symbol: "circle.dotted", token: "status.connecting", label: "Connecting", pointSize: 9) }
        if s.failed.contains(id) { return .init(symbol: "exclamationmark.circle.fill", token: "status.failed", label: "Session ended", pointSize: 10) }
        return nil
    }
}
