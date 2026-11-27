import SwiftUI

/// The window's library, session and inspector columns and its toolbar, in their own view. Whether
/// the library shows is read here and nowhere in `ContentView.body`: a library toggle re-runs this
/// body only. When the window's body read it, every toggle re-made all of the window's sheets and
/// overlays and re-rendered the inspector, shown or not (MAC-STALLS profile).
struct LibraryColumns: View {
    let sel: LibrarySelection
    @Binding var search: String
    let searchFocused: FocusState<Bool>.Binding
    @Binding var showingImport: Bool
    @Binding var showingQuickConnect: Bool
    let addMenu: AddMenuState
    let demand: InspectorDemand
    let inspectorAsOverlay: Bool
    let inspectorMaxNow: CGFloat
    let fullScreen: Bool
    let reduceMotion: Bool
    /// The library was shown or hidden: the window checks again whether its columns fit.
    let libraryShownChanged: () -> Void
    @Environment(LibraryModel.self) private var model
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    @Environment(SettingsModel.self) private var settings

    static func autoHide(_ settings: SettingsModel) -> Bool { settings.value("tree.auto-hide") == "true" }

    /// The library column as drawn. When the window is too narrow for library + page + inspector
    /// and the user brought the inspector back, the library steps aside so the three column
    /// minimums never exceed the window (MAC-INSPECTOR-FIT). The narrow check itself keeps using
    /// the user's library choice, so collapsing here does not flip it back.
    static func libraryDisplayed(tree: TreeStateModel, settings: SettingsModel, inspectorAsOverlay: Bool) -> Bool {
        // Only a column needs the room: an overlay inspector (full screen, or a window too narrow for the
        // column) leaves the library where it is.
        tree.libraryShown(autoHide: autoHide(settings)) && !(tree.libraryYieldsToInspector && !inspectorAsOverlay)
    }

    /// Full-screen auto-dock applies: full screen, auto-hide and the dock setting on, column hidden.
    static func autoDockEnabled(tree: TreeStateModel, settings: SettingsModel, fullScreen: Bool) -> Bool {
        // Full screen as before; in a window only while auto-hide (not the user) has hidden it.
        let autoHide = autoHide(settings)
        let hiddenByAutoHide = tree.libraryVisible && !tree.libraryShown(autoHide: autoHide)
        return autoHide && settings.value("tree.full-screen-dock") != "false"
            && (fullScreen ? !tree.libraryShown(autoHide: autoHide) : hiddenByAutoHide)
    }

    private var displayed: Bool { Self.libraryDisplayed(tree: commands.tree, settings: settings, inspectorAsOverlay: inspectorAsOverlay) }

    var body: some View {
        let _ = RenderCount.hit("LibraryColumns")
        let gateOpen = DocumentGate.shared.isOpen
        let shown = displayed
        // SwiftUI writes the shown state back through the setter; only a different value is the user's.
        NavigationSplitView(columnVisibility: Binding(
            get: { displayed ? .all : .detailOnly },
            set: { v in
                if (v != .detailOnly) != displayed { commands.tree.toggleLibrary(autoHide: Self.autoHide(settings)) }
            })) {
            // While the document gate is up nothing of the library or its sessions is built: not in
            // the view tree, the accessibility tree or layout-fit (owner 2026-11-05).
            Group { if gateOpen { LibrarySidebar(sel: sel, search: $search, commands: commands, searchFocus: searchFocused) } else { Color.clear } }
                .modifier(SearchFocus(focused: searchFocused))
                // The start window shows no library chrome: on the sidebar column (as Settings does), the
                // split view's own toggle goes while the gate is up.
                .toolbar(removing: gateOpen ? nil : .sidebarToggle)
                // Outermost on the column: under the `.toolbar(removing:)` above, the rule never reached
                // AppKit's split item (minimum 140, a saved 144 pt column). The Compact switcher then had no
                // room beside the traffic lights and NSToolbar moved it, the tabs and the inspector toggle
                // into » (MAC-HEADER-FIT).
                .navigationSplitViewColumnWidth(min: DS.Size.sidebarMin, ideal: DS.Size.sidebarIdeal)
        } detail: {
            // Its own view (as are the other tab readers): a tab read in this body re-ran it on the
            // first tab and the last close, and with it every .toolbar here (nm-23 local-shell stall).
            SessionDetail(gateOpen: gateOpen, libraryEmpty: model.isEmpty, showingImport: $showingImport)
            // Quick Connect drops from the top of the session area, just under the toolbar: the toolbar's
            // SwiftUI items are rebuilt as tabs and the selection change, and a popover on the bolt
            // closed in the frame it opened (m5/m6, with the app active and the item visible).
            .overlay(alignment: .topTrailing) {
                Color.clear.frame(width: 1, height: 1)
                    .padding(.trailing, DS.Size.quickConnectAnchorInset)
                    .popover(isPresented: $showingQuickConnect, arrowEdge: .bottom) { QuickConnectView() }
                    .allowsHitTesting(false)
            }
        }
        // On the split view, not inside the detail column: there the toolbar inset is applied twice.
        // In full screen the inspector overlays the sessions instead, so the terminal keeps its size.
        // Whether it shows is observed in the modifier, not here (InspectorHost.swift).
        .modifier(InspectorColumnHost(demand: demand, asOverlay: inspectorAsOverlay, maxWidth: inspectorMaxNow,
                                      panel: Group { if demand.isOpen { SelectedInspector(sel: sel, commands: commands, demand: demand) } }))
        // Its own modifier with fixed inputs: a re-run of this body (a library toggle, a tab opening)
        // no longer rebuilds the toolbar's items (MAC-STALLS).
        .modifier(MainWindowToolbar(sel: sel, addMenu: addMenu))
        // Column or full-screen overlay: the toggle closes whichever shows (owner: the button only
        // opened the panel in a full-screen session).
        .background(InspectorDemandWatch(demand: demand, asOverlay: inspectorAsOverlay))
        // Sidebar and inspector slide with a short ease-out; Reduce Motion switches it off.
        // Value-driven, so nothing runs between toggles (no idle CPU).
        .animation(reduceMotion ? DS.Motion.reducedFade : DS.Motion.panel, value: shown)
        .background(SplitAutosavePause(trigger: shown))
        .onChange(of: commands.tree.libraryShown(autoHide: Self.autoHide(settings))) { _, _ in libraryShownChanged() }
        .onChange(of: Self.autoDockEnabled(tree: commands.tree, settings: settings, fullScreen: fullScreen)) { _, on in
            if !on && !AutoDock.shared.docked { AutoDock.shared.dismiss() }
        }
        .onChange(of: shown, initial: true) { _, shown in
            let leading: CGFloat = shown ? 0 : DS.Size.compactHiddenLeading
            if sessions.compactLeading != leading { sessions.compactLeading = leading; sessions.stripRoomChanged() }
        }
    }
}
