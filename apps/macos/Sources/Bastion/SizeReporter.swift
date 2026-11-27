import AppKit
import SwiftUI

/// Reports the size of the view it backs on the next turn of the main run loop, once per change.
/// With the macOS 27 SDK an `onGeometryChange` action is queued inside SwiftUI's update and runs within
/// the window's Update Constraints pass; when a split view's columns were still settling, each queued
/// action asked for another pass, until AppKit aborted the app ("more Update Constraints in Window passes
/// than there are views", #1104). Reported from here, a size never runs inside a layout pass.
/// Use as `.background(SizeReporter { size in … })`.
struct SizeReporter: NSViewRepresentable {
    let changed: (CGSize) -> Void

    func makeNSView(context: Context) -> ReporterView { ReporterView(changed: changed) }
    func updateNSView(_ view: ReporterView, context: Context) { view.changed = changed }

    final class ReporterView: NSView {
        var changed: (CGSize) -> Void
        private var reported: CGSize?
        private var scheduled = false

        init(changed: @escaping (CGSize) -> Void) {
            self.changed = changed
            super.init(frame: .zero)
        }

        required init?(coder: NSCoder) { nil }

        override func setFrameSize(_ newSize: NSSize) {
            super.setFrameSize(newSize)
            scheduleReport()
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if window != nil { scheduleReport() }
        }

        /// Hit testing passes through: the reporter only measures.
        override func hitTest(_ point: NSPoint) -> NSView? { nil }

        private func scheduleReport() {
            guard !scheduled else { return }
            scheduled = true
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.scheduled = false
                let size = self.frame.size
                guard self.window != nil, size != self.reported else { return }
                self.reported = size
                self.changed(size)
            }
        }
    }
}
