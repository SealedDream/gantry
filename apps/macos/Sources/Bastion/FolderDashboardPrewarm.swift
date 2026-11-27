import SwiftUI

/// Builds the folder page once, after the first sheet's warm-up. The first folder the user selected
/// paid for the page's SwiftUI type metadata, view graph, buttons and table (perf budgets on a
/// 5,000-connection library: one 149–162 ms gap on the first folder; with an offscreen copy built
/// here it was still 55–63 ms, the real window's first mount). Now the session area mounts its own
/// dashboard here, hidden (`SessionTabsView`), so the first select only changes its folder.
@MainActor
enum FolderDashboardPrewarm {
    private(set) static var isDone = false

    static func run(commands: Commands, sessions: SessionsModel) {
        guard !isDone else { return }
        isDone = true
        // A real folder, so the page builds its table rows; the root when there are no subfolders.
        guard let root = commands.model.tree, sessions.folderPage == nil else { return }
        sessions.folderPageWarm = root.folders.first?.id ?? root.id
    }
}
