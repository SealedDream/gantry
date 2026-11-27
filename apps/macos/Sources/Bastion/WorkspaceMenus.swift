import AppKit
import SwiftUI

/// The workspace commands, wherever they are offered: the library sidebar's header, File ›
/// Workspaces and Window › Workspaces (owner 2026-11-05: not the toolbar). The palette lists
/// the same workspaces (`CommandPalette`).
struct WorkspaceMenuItems: View {
    @Environment(WorkspaceModel.self) private var workspaces
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands
    @Environment(AppRouter.self) private var router

    var body: some View {
        ForEach(workspaces.items, id: \.id) { ws in
            Button { workspaces.open(ws.id, commands: commands) } label: {
                if ws.id == workspaces.currentId { Label(ws.name, systemImage: "checkmark") } else { Text(ws.name) }
            }
        }
        if !workspaces.items.isEmpty { Divider() }
        Button("Save Current Layout…") { router.open("save-workspace") }.disabled(sessions.tabs.isEmpty)
        Button("Manage Workspaces…") { router.open("workspace-manager") }
    }
}

/// One row under the documents in the sidebar header: the current workspace, a menu of the rest.
struct SidebarWorkspaceMenu: View {
    @Environment(WorkspaceModel.self) private var workspaces
    static let markerId = "sidebar-workspace"

    var body: some View {
        Menu {
            WorkspaceMenuItems()
        } label: {
            // The whole row is the click target (a plain menu button sizes to its label).
            HStack(spacing: 6) {
                Image(systemName: Icons.symbol("workspace")).frame(width: 16)
                Text(workspaces.current?.name ?? "No Workspace").lineLimit(1).truncationMode(.middle)
                Spacer(minLength: 4)
                Image(systemName: "chevron.up.chevron.down").imageScale(.small).foregroundStyle(.secondary)
            }
            .padding(.horizontal, 6)
            .frame(maxWidth: .infinity, minHeight: DS.Size.minHitTarget, alignment: .leading)
            .contentShape(Rectangle())
            .background(FrameMarker(id: Self.markerId))
        }
        .menuStyle(.button)
        .buttonStyle(.plain)
        .menuIndicator(.hidden)
        .help(workspaces.current.map { "Workspace “\($0.name)”: open, save or manage workspaces" } ?? "Open, save or manage workspaces")
    }
}

/// An empty AppKit view filling its SwiftUI parent, found by the UI driver by identifier to
/// read where (and how big) a SwiftUI-drawn control is.
struct FrameMarker: NSViewRepresentable {
    let id: String

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        view.identifier = NSUserInterfaceItemIdentifier(id)
        return view
    }

    func updateNSView(_ view: NSView, context: Context) {}
}
