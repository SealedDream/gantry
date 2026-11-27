import AppKit
import SwiftUI

/// One entry of an `IconMenuButton`: a titled action, or a separator.
struct IconMenuItem {
    let title: String
    var symbol: String?
    var enabled = true
    var action: () -> Void = {}
    var isSeparator = false

    static var separator: IconMenuItem { IconMenuItem(title: "", isSeparator: true) }
}

/// A quiet icon button (24 pt square, tooltip) that opens a native menu under itself: the "…" overflow
/// of the button-row restyle. A real button, not a pop-up, so it measures as a normal hit target.
struct IconMenuButton: NSViewRepresentable {
    let symbol: String
    let help: String
    let items: [IconMenuItem]
    var identifier: String = ""

    func makeNSView(context: Context) -> MenuIconButton {
        let b = MenuIconButton()
        b.setAccessibilityIdentifier(identifier)
        b.setAccessibilityLabel(help)
        return b
    }

    func updateNSView(_ b: MenuIconButton, context: Context) {
        b.image = NSImage(systemSymbolName: symbol, accessibilityDescription: help)?.withSymbolConfiguration(.init(pointSize: 12, weight: .regular))
        b.toolTip = help
        b.items = items
    }

    func sizeThatFits(_ proposal: ProposedViewSize, nsView: MenuIconButton, context: Context) -> CGSize? {
        CGSize(width: IconHitTargetLabelStyle.side, height: IconHitTargetLabelStyle.side)
    }
}

/// A cell that is exactly the shared icon-button square (IconHitTargetLabelStyle.side), so the layout-fit check sees no hidden padding.
final class MenuIconCell: NSButtonCell {
    override var cellSize: NSSize { MainActor.assumeIsolated { NSSize(width: IconHitTargetLabelStyle.side, height: IconHitTargetLabelStyle.side) } }
    override func cellSize(forBounds rect: NSRect) -> NSSize { cellSize }
}

final class MenuIconButton: NSButton {
    override class var cellClass: AnyClass? { get { MenuIconCell.self } set {} }

    var items: [IconMenuItem] = []
    private var actions: [() -> Void] = []

    init() {
        super.init(frame: .zero)
        bezelStyle = .regularSquare
        isBordered = false
        imagePosition = .imageOnly
        imageScaling = .scaleProportionallyDown
        contentTintColor = .secondaryLabelColor
        target = self
        action = #selector(show)
    }
    required init?(coder: NSCoder) { fatalError("not used") }

    override var intrinsicContentSize: NSSize { NSSize(width: IconHitTargetLabelStyle.side, height: IconHitTargetLabelStyle.side) }
    override var fittingSize: NSSize { intrinsicContentSize }

    @objc private func show() {
        let menu = NSMenu()
        actions = items.map(\.action)
        for (i, item) in items.enumerated() {
            if item.isSeparator { menu.addItem(.separator()); continue }
            let m = NSMenuItem(title: item.title, action: #selector(pick(_:)), keyEquivalent: "")
            m.target = self
            m.tag = i
            m.isEnabled = item.enabled
            if let s = item.symbol { m.image = NSImage(systemSymbolName: s, accessibilityDescription: nil) }
            menu.addItem(m)
        }
        menu.popUp(positioning: nil, at: NSPoint(x: 0, y: bounds.height + 4), in: self)
    }

    @objc private func pick(_ sender: NSMenuItem) { actions[sender.tag]() }
}

extension View {
    /// A button row's quiet icon button: borderless, 24 pt hit target, tooltip that also shows while disabled.
    /// Use on a `Button("Name", systemImage: …)`; the name stays its accessibility label.
    func quietIcon(_ tip: String) -> some View {
        labelStyle(.iconHitTarget).buttonStyle(.borderless).iconTip(tip)
    }
}
