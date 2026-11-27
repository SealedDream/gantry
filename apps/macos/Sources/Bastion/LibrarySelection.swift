import Foundation
import QuartzCore
import Observation

/// The library selection, held outside `ContentView`'s state so only the views that read it
/// (sidebar, inspector, toolbar actions) re-render when it changes. As `@State` on the window's
/// root, every click re-ran the whole split view's body and layout (~200-450 ms with 5,000
/// connections). The window reads only `isConnection`, which changes far less often.
@MainActor @Observable
final class LibrarySelection {
    private(set) var id: String?
    /// Whether `id` is a connection (the inspector shows only for one); written only when it changes.
    private(set) var isConnection = false
    /// `id` as the inspector shows it: it follows `id` once the page for the new selection has
    /// drawn, so the inspector's re-render is not part of the click (MAC-SELECT-SPEED). Views that
    /// decide what the page shows read `id`; only the inspector reads this.
    private(set) var shownId: String?

    /// `id` without observation, for AppKit code that runs inside a SwiftUI update (the tree's
    /// `updateNSView`): reading `id` there made the sidebar re-render on every selection.
    @ObservationIgnored private(set) var current: String?
    /// Posted (object: this selection) when `id` changes, after it changed, on the main thread.
    static let changed = Notification.Name("bastion.library-selection.changed")

    /// `isConnection`: whether `new` names a connection in the library.
    func set(_ new: String?, isConnection conn: Bool) {
        let moved = new != id
        if moved { id = new; current = new }
        if conn != isConnection { isConnection = conn }
        scheduleShown()
        if moved { NotificationCenter.default.post(name: Self.changed, object: self) }
    }

    /// Once the Core Animation transaction holding this change has been committed, that is once
    /// the frame with the new page is drawn (a main-queue hop runs before that commit). The timer
    /// is a fallback for when no frame is committed or a later block replaces this one: the
    /// inspector never stays behind.
    private func scheduleShown() {
        guard shownId != id else { return }
        let follow: @Sendable () -> Void = { [weak self] in
            MainActor.assumeIsolated {
                guard let self, self.shownId != self.id else { return }
                self.shownId = self.id
                RenderCount.hit("inspector-follow")
            }
        }
        // Added to the transaction now being built (implicit, committed with the frame), after any
        // completion block already there; not a nested transaction, which commits at once when none is open.
        let earlier = CATransaction.completionBlock()
        CATransaction.setCompletionBlock { earlier?(); follow() }
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.followLimit, execute: follow)
    }

    /// The longest the inspector waits for the frame with the new page.
    private static let followLimit = DispatchTimeInterval.milliseconds(250)
}
