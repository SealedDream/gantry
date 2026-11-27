import SwiftUI

/// Whether the inspector shows. Read only in the small views and the modifier below, never in
/// `ContentView.body`: read there, every New Connection open, manager panel and connection select
/// re-ran the window's body (the split view, its sheets and overlays) two or three times, and the
/// window re-laid out with it (MAC-NEWCONN-STALL, 2026-11-16).
@MainActor
struct InspectorDemand {
    /// Launch finished and the document gate open (values: ContentView re-runs when they change).
    let isOpen: Bool
    let commands: Commands
    let sessions: SessionsModel
    let sel: LibrarySelection

    /// Owner 2026-11-05/07 (feedback 6, 8): only a connection's page or a picked Recent Sessions row
    /// shows the inspector; an open service and the bare start page never do. New Connection always does.
    var wanted: Bool { column || formOverlay }

    /// New Connection while the column is closed: the form shows over the sessions' trailing edge.
    /// Opening the column for it uncollapsed the split view item and re-laid out the whole window.
    var formOverlay: Bool { isOpen && commands.addConnection != nil && !column }

    /// The inspector the selection and the saved toggle ask for (without a New Connection form).
    var column: Bool {
        guard isOpen else { return false }
        if let forced = commands.tree.inspectorOverride { return forced }
        guard commands.tree.inspectorShown && !commands.tree.inspectorHiddenByWidth else { return false }
        if let page = sessions.connectionPage { return sel.isConnection && page == sel.id }
        return sessions.mainTabs.isEmpty && sessions.startPick != nil
    }
}

/// The inspector column on the split view. Its shown state is observed in this body only.
struct InspectorColumnHost<Panel: View>: ViewModifier {
    let demand: InspectorDemand
    /// The inspector draws over the sessions (full screen, or a window too narrow for the column).
    let asOverlay: Bool
    let maxWidth: CGFloat
    let panel: Panel

    func body(content: Content) -> some View {
        // Observed here; the binding below reads it again when SwiftUI asks (closures outlive this body).
        let _ = demand.column
        // Compare SwiftUI's write-back with what the binding shows: in full screen the column is
        // always closed (the overlay shows instead), so comparing with `wanted` alone turned a
        // write-back of `false` into a toggle.
        // Only a close is the user's: the column has no gesture that opens it, so a write-back of `true`
        // is SwiftUI repeating the old value after the saved choice went off, and toggling on it saved it
        // as on again (a1-logins-fit, MAC-876-FOLLOWUPS).
        content.inspector(isPresented: Binding(get: { [demand, asOverlay] in demand.column && !asOverlay },
                                               set: { [demand, asOverlay] in
                                                   if !$0 && demand.column && !asOverlay { demand.commands.tree.toggleInspector() } })) {
            panel.inspectorColumnWidth(min: DS.Size.inspectorMin, ideal: min(DS.Size.inspectorIdeal, maxWidth), max: maxWidth)
        }
    }
}

/// The full-screen (or too-narrow) inspector, and the New Connection form while the column is
/// closed, over the sessions' trailing edge.
struct InspectorOverlayLayer<Panel: View>: View {
    let demand: InspectorDemand
    let asOverlay: Bool
    let reduceMotion: Bool
    let panel: Panel

    var body: some View {
        ZStack(alignment: .trailing) {
            if asOverlay && demand.column {
                InspectorOverlay { panel }
                    .transition(reduceMotion ? .opacity : .move(edge: .trailing))
            }
            // Mounted from launch, shown only while New Connection is open with the column closed.
            if demand.isOpen { NewConnectionOverlay(shown: demand.formOverlay) }
        }
    }
}

/// Publishes the shown state for the toggles and the connection page's overlay inset, and hides or
/// shows the inspector as sessions open and the selection changes.
struct InspectorDemandWatch: View {
    let demand: InspectorDemand
    let asOverlay: Bool

    var body: some View {
        let wanted = demand.wanted
        SessionOpenWatch(commands: demand.commands)
            .background(SelectionWatch(sel: demand.sel, commands: demand.commands))
            .background(InspectorContextWatch(sel: demand.sel, commands: demand.commands))
            .onChange(of: wanted, initial: true) { _, on in demand.commands.tree.inspectorPresented = on }
            // The page's inset is read by the connection page alone: an environment value on the
            // session area invalidated the whole window's layout on every sheet (QA P1: 300-700 ms).
            .onChange(of: asOverlay && wanted, initial: true) { _, on in
                let inset = on ? DS.Size.inspectorIdeal : 0
                if demand.commands.tree.inspectorOverlayInset != inset { demand.commands.tree.inspectorOverlayInset = inset }
            }
    }
}

/// Runs the router's requests (menu items, shortcuts, the palette). Its own view, with the router
/// from the environment: read in ContentView.body, every route set and then cleared the request and
/// re-ran the window's body twice (MAC-NEWCONN-STALL, 2026-11-16).
struct RouteWatch: View {
    @Environment(AppRouter.self) private var router
    let handle: (String) -> Void

    var body: some View {
        Color.clear.onChange(of: router.request) { _, target in
            guard let target else { return }
            router.request = nil
            handle(target)
        }
    }
}
