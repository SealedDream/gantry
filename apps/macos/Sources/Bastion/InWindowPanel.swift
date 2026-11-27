import SwiftUI

/// Manager dialogs shown as a panel inside the main window instead of an AppKit sheet.
/// A window-modal sheet on macOS renders the whole parent window into a bitmap for its dimming
/// mask on every animation step (`NSSheetEffectDimmingView _rebuildMask`); with the window full
/// screen that alone stalled the main thread 55–85 ms per open (perf budgets, 2026-11-16).
/// The panel is plain SwiftUI over the window: a static scrim and the dialog, no animation.
enum WindowPanel: String, Identifiable, CaseIterable {
    case gateways = "gateway-manager"
    case tunnels = "tunnel-manager"
    case hostCAs = "host-cas"
    case workspaces = "workspace-manager"
    case passwordGenerator = "password-generator"
    // The tool sheets, moved for the same cause (census 2026-11-17: 550-950 ms per open and close).
    case agentKeys = "ssh-agent"
    case themes = "terminal-themes"
    case snippets = "snippets"
    case auditLog = "audit-log"
    case plugins = "plugins"
    case activity = "activity"
    case recentlyDeleted = "recently-deleted"
    case hostStatus = "host-status"
    case triggers = "triggers"
    case runOnHosts = "run-on-hosts"
    case tasks = "tasks-page"
    /// Export Library; the request is `Commands.exportRequest`.
    case export = "export-library"
    /// Import and export results; the report is `Commands.importReport`.
    case importReport = "import-report"
    /// KeePass import; the request is `Commands.keepassRequest`.
    case keepass = "import-keepass"

    var id: String { rawValue }

    /// A click outside closes it (owner round 2, item 2). Not for panels that hold typed work
    /// (a query, a command, an export or import in progress): a stray click must not lose it.
    var closesOnOutsideClick: Bool {
        switch self {
        case .runOnHosts, .export, .keepass, .snippets, .triggers, .gateways, .tunnels: false
        default: true
        }
    }

    var title: String {
        switch self {
        case .gateways: "Gateways"
        case .tunnels: "Tunnels"
        case .hostCAs: "Host Certificate Authorities"
        case .workspaces: "Workspaces"
        case .passwordGenerator: "Password Generator"
        case .agentKeys: "SSH Agent"
        case .themes: "Terminal Themes"
        case .snippets: "Snippets"
        case .auditLog: "Audit Log"
        case .plugins: "Plugins"
        case .activity: "Activity"
        case .recentlyDeleted: "Recently Deleted"
        case .hostStatus: "Host Status"
        case .triggers: "Triggers"
        case .runOnHosts: "Run Command on Hosts"
        case .tasks: "Tasks"
        case .export: "Export"
        case .importReport: "Import"
        case .keepass: "KeePass Import"
        }
    }

    /// The UI driver waits for this probe to time an open.
    var probe: String { "panel-" + rawValue }
}

extension View {
    /// A dialog's size: exactly this as a sheet (sheets take the ideal size), at most this in a
    /// window panel, which is never wider or taller than the window. No height: the content's own.
    func panelFrame(width: CGFloat, height: CGFloat? = nil) -> some View {
        frame(minWidth: 0, idealWidth: width, maxWidth: width,
              minHeight: height == nil ? nil : 0, idealHeight: height, maxHeight: height)
    }
}

private struct PanelCloseKey: EnvironmentKey {
    static let defaultValue: (@MainActor @Sendable () -> Void)? = nil
}

extension EnvironmentValues {
    /// Set inside a `WindowPanel`; views shown both there and in a sheet close through `PanelDismiss`.
    var panelClose: (@MainActor @Sendable () -> Void)? {
        get { self[PanelCloseKey.self] }
        set { self[PanelCloseKey.self] = newValue }
    }
}

/// Closes the view the way it was shown: the window panel when there is one, else the sheet.
struct PanelDismiss: DynamicProperty {
    @Environment(\.panelClose) private var panelClose
    @Environment(\.dismiss) private var sheetDismiss

    @MainActor func callAsFunction() {
        if let panelClose { panelClose() } else { sheetDismiss() }
    }
}

/// Hosts the open `WindowPanel` over the window content. Clicks outside the dialog are absorbed
/// (it is modal to the window, like the sheet it replaces); Escape and ⌘. close it.
struct WindowPanelHost: ViewModifier {
    /// `commands.panel` is observed in this body, not the window's: read there, every manager panel
    /// re-ran ContentView.body (MAC-NEWCONN-STALL, 2026-11-16). From the environment, so the modifier
    /// has a dynamic property and its own body: one made only of `let`s is evaluated inline.
    @Environment(Commands.self) private var commands
    private var panel: WindowPanel? { commands.panel }
    private var close: @MainActor @Sendable () -> Void { { [commands] in commands.panel = nil } }
    private static let cornerRadius: CGFloat = 10
    private static let margin: CGFloat = 16

    func body(content: Content) -> some View {
        content
            .accessibilityHidden(panel != nil)
            .overlay {
                if let panel {
                    ZStack {
                        Color.black.opacity(0.12)
                            .contentShape(Rectangle())
                            // A click outside the panel closes it, as Esc does (owner round 2, item 2).
                            .onTapGesture { if panel.closesOnOutsideClick { close() } }
                            .accessibilityHidden(true)
                        panelContent(panel)
                            .environment(\.panelClose, close)
                            .background(.background, in: RoundedRectangle(cornerRadius: Self.cornerRadius))
                            .overlay(RoundedRectangle(cornerRadius: Self.cornerRadius).strokeBorder(.separator))
                            .shadow(color: .black.opacity(0.18), radius: 12, y: 4)
                            .onExitCommand(perform: close)
                            .accessibilityElement(children: .contain)
                            .accessibilityLabel(panel.title)
                            .accessibilityAddTraits(.isModal)
                            .uiProbe(panel.probe)
                            .id(panel)
                            // Never wider or taller than the window: a sheet could overhang it, a panel cannot.
                            .padding(Self.margin)
                    }
                    .transaction { $0.animation = nil }
                }
            }
            .onChange(of: panel) { old, new in PanelFocus.shared.move(open: new != nil, wasOpen: old != nil) }
    }

    @ViewBuilder private func panelContent(_ panel: WindowPanel) -> some View {
        switch panel {
        case .gateways: GatewayManagerView()
        case .tunnels: TunnelManagerView()
        case .hostCAs: HostCAManagerView()
        case .workspaces: WorkspaceManagerView()
        case .passwordGenerator: PasswordGeneratorSheet()
        case .agentKeys: AgentKeysView()
        case .themes: ThemeEditorView()
        case .snippets: SnippetsView()
        case .auditLog: AuditLogView()
        case .plugins: PluginsView()
        case .activity: ActivityView()
        case .recentlyDeleted: RecentlyDeletedView()
        case .hostStatus: HostStatusPanel()
        case .triggers: TriggerManagerView()
        case .runOnHosts: MultiExecView()
        case .tasks: TasksPage()
        case .export: if let r = commands.exportRequest { ExportSheet(request: r) }
        case .importReport: if let r = commands.importReport { ImportReportSheet(report: r) }
        case .keepass: if let r = commands.keepassRequest { KeePassImportSheet(request: r) }
        }
    }
}

/// Keyboard focus follows the panel, as it follows a sheet (a sheet is its own key window). Left on
/// the view under the panel (the terminal, the library tree), Return and Escape went there: Return
/// reached a shell or opened a tree row, and the panel's default button never saw it.
@MainActor
final class PanelFocus {
    static let shared = PanelFocus()
    private weak var window: NSWindow?
    private weak var previous: NSResponder?

    func move(open: Bool, wasOpen: Bool) {
        if open && !wasOpen {
            guard let w = NSApp.mainWindow ?? NSApp.keyWindow ?? NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain }) else { return }
            window = w
            previous = w.firstResponder
            // The window itself: key equivalents (the panel's .defaultAction / .cancelAction) and
            // cancelOperation (onExitCommand) then reach the panel first.
            w.makeFirstResponder(nil)
        } else if !open && wasOpen {
            defer { window = nil; previous = nil }
            guard let w = window, let view = previous as? NSView, view.window === w else { return }
            w.makeFirstResponder(view)
        }
    }
}
