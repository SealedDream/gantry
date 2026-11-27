import AppKit
import SwiftUI

// Owner round 3, item 8: icon-only buttons must name themselves on hover. SwiftUI's `.help`
// shows nothing while a button is disabled (Download, Edit, Rename until a file is selected), so
// the SFTP bar looked as if it had no tooltips. This sets an AppKit tool tip on a view laid over
// the button; that view takes no clicks (hitTest nil). Where the button is itself an AppKit
// control (borderless style), the control under the pointer gets the same tool tip.

extension View {
    /// `.help(text)` plus a tool tip that also shows while the control is disabled.
    func iconTip(_ text: String) -> some View {
        help(text).overlay(ToolTipLayer(text: text))
    }
}

private struct ToolTipLayer: NSViewRepresentable {
    let text: String
    func makeNSView(context: Context) -> TipView { TipView(text) }
    func updateNSView(_ view: TipView, context: Context) { if view.toolTip != text { view.toolTip = text } }

    final class TipView: NSView, NSViewToolTipOwner {
        func view(_ view: NSView, stringForToolTip tag: NSView.ToolTipTag, point: NSPoint, userData data: UnsafeMutableRawPointer?) -> String {
            toolTip ?? ""
        }
        init(_ text: String) { super.init(frame: .zero); toolTip = text }
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if TestHooks.isScripted, window != nil, let text = toolTip { DriverEvents.headerViews["tip-" + text] = WeakView(self) }
            DispatchQueue.main.async { [weak self] in self?.tipControlUnder() }
        }

        override func layout() {
            super.layout()
            // Never during layout: changing a SwiftUI-managed control there re-entered layout until
            // AppKit gave up ("more Update Constraints passes than views", 2026-11-20 crashes).
            DispatchQueue.main.async { [weak self] in self?.tipControlUnder() }
        }

        private weak var tipped: NSView?
        private var tipTag: NSView.ToolTipTag?
        private var tipRect: NSRect = .zero

        /// A borderless SwiftUI button is a real AppKit button (`SwiftUIAppKitButton`): it is the
        /// view under the pointer, so AppKit shows its tool tip, and `.help` left none (owner round
        /// 4, item 6: no tips in the SFTP bar). Adds a tool tip rect on that control. Not its
        /// `toolTip` property: SwiftUI owns that and resets it, which looped layout.
        private func tipControlUnder() {
            guard let window, let root = superview?.superview ?? superview else { return }
            let frame = convert(bounds, to: nil)
            guard let control = Self.control(at: NSPoint(x: frame.midX, y: frame.midY), in: root, window: window) else { return }
            if control === tipped && control.bounds == tipRect { return }
            if let tag = tipTag { tipped?.removeToolTip(tag) }
            tipTag = control.addToolTip(control.bounds, owner: self, userData: nil)
            tipped = control
            tipRect = control.bounds
        }

        deinit { MainActor.assumeIsolated { if let tag = tipTag { tipped?.removeToolTip(tag) } } }

        private static func control(at point: NSPoint, in view: NSView, window: NSWindow) -> NSControl? {
            for sub in view.subviews.reversed() where !(sub is TipView) && !sub.isHidden {
                guard sub.convert(sub.bounds, to: nil).contains(point) else { continue }
                if let c = sub as? NSControl { return c }
                if let c = control(at: point, in: sub, window: window) { return c }
            }
            return nil
        }
        required init?(coder: NSCoder) { fatalError("not used") }
        override func hitTest(_ point: NSPoint) -> NSView? { nil }
    }
}
