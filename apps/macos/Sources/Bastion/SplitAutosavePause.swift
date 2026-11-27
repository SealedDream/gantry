import AppKit
import SwiftUI

/// Pauses the window's NSSplitView autosave while a panel slides. NavigationSplitView's split
/// view saves its layout on every divider move, and each save reads the whole autosave
/// dictionary from NSUserDefaults: during the library slide that was the longest main-thread
/// gap (OF-B profile). The name comes back once the slide has ended, so the final layout is
/// still saved.
struct SplitAutosavePause: NSViewRepresentable {
    /// Changes whenever a slide starts.
    let trigger: Bool
    /// How long the slide runs; the autosave is restored after it.
    static let pauseDuration: TimeInterval = 0.45

    func makeNSView(context: Context) -> PauseView { PauseView(trigger: trigger) }
    func updateNSView(_ view: PauseView, context: Context) { view.update(trigger: trigger) }

    final class PauseView: NSView {
        private var trigger: Bool
        private var saved: [(NSSplitView, NSSplitView.AutosaveName)] = []
        private var restore: DispatchWorkItem?

        init(trigger: Bool) {
            self.trigger = trigger
            super.init(frame: .zero)
        }

        required init?(coder: NSCoder) { nil }

        func update(trigger new: Bool) {
            guard new != trigger else { return }
            trigger = new
            pause()
        }

        private func pause() {
            guard let root = window?.contentView else { return }
            for split in root.allSplitViews() {
                guard let name = split.autosaveName, !name.isEmpty else { continue }
                saved.append((split, name))
                split.autosaveName = nil
            }
            restore?.cancel()
            let item = DispatchWorkItem { [weak self] in self?.resume() }
            restore = item
            DispatchQueue.main.asyncAfter(deadline: .now() + SplitAutosavePause.pauseDuration, execute: item)
        }

        private func resume() {
            let pending = saved
            saved = []
            restore = nil
            for (split, name) in pending where split.autosaveName == nil {
                // Setting the name restores the frames saved under it, which are from before the
                // slide: the collapsed column came back at full width (owner point 25). Drop them so
                // nothing stale is restored, then save the current layout under the name.
                UserDefaults.standard.removeObject(forKey: "NSSplitView Subview Frames \(name)")
                split.autosaveName = name
                split.adjustSubviews()
            }
        }
    }
}

private extension NSView {
    func allSplitViews() -> [NSSplitView] {
        subviews.flatMap { view -> [NSSplitView] in
            let own = (view as? NSSplitView).map { [$0] } ?? []
            return own + view.allSplitViews()
        }
    }
}
