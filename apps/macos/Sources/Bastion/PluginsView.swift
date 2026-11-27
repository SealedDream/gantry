import AppKit
import SwiftUI
import UniformTypeIdentifiers
import BastionCore

/// Plugins page (PLUG-06a part 1, Native Mac): the installed plugins, the catalogue state and the
/// update plan, over the core's PLUG-04b exports. Install from a file, remove (keep or delete
/// data), refresh the catalogue. Running plugins (renderers, tabs) is PLUG-06a part 2.
struct PluginsView: View {
    enum Tab: String, CaseIterable, Identifiable {
        case installed = "Installed", catalogue = "Catalogue", updates = "Updates"
        var id: String { rawValue }
    }

    /// Posted by the UI driver (`plugins-tab <name>`) to switch tabs in a test run.
    static let selectTab = Notification.Name("BastionPluginsSelectTab")

    private var dismiss = PanelDismiss()
    @State private var tab: Tab = .installed
    @State private var installed: [InstalledPluginView] = []
    @State private var updates: [PluginUpdateView] = []
    @State private var policy = pluginPolicyState()
    @State private var refreshOutcome: String?
    @State private var message: String?
    @State private var busy = false
    @State private var removing: InstalledPluginView?
    @State private var selected: String?
    @State private var confirmUnverified: URL?
    @State private var confirmOpen: InstalledPluginView?

    private var selectedPlugin: InstalledPluginView? { installed.first { $0.id == selected } }

    private var dataDir: String { LibraryModel.dataDir.path }

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 8) {
                Picker("", selection: $tab) {
                    ForEach(Tab.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().fixedSize()
                .accessibilityIdentifier("plugins-tabs")
                Spacer(minLength: 8)
                if busy { ProgressView().controlSize(.small) }
            }
            .controlSize(.small)
            .padding(10)
            if let banner = PluginsPage.policyBanner(policy) {
                Text(banner).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, 10).padding(.bottom, 6)
                    .help(banner).accessibilityIdentifier("plugins-policy")
            }
            Divider()
            content.frame(maxWidth: .infinity, maxHeight: .infinity)
            Divider()
            footer
        }
        .panelFrame(width: 760, height: 500)
        .task { await reload() }
        .onReceive(NotificationCenter.default.publisher(for: Self.selectTab)) { note in
            if let name = note.object as? String, let t = Tab(rawValue: name) { tab = t }
        }
        .confirmationDialog(removing.map { "Remove \($0.id)?" } ?? "", isPresented: Binding(get: { removing != nil }, set: { if !$0 { removing = nil } })) {
            Button("Remove, Keep Data") { if let p = removing { Task { await remove(p, deleteData: false) } } }
            Button("Remove and Delete Data", role: .destructive) { if let p = removing { Task { await remove(p, deleteData: true) } } }
            Button("Cancel", role: .cancel) {}
        }
        .confirmationDialog("Install an unverified plugin?", isPresented: Binding(get: { confirmUnverified != nil }, set: { if !$0 { confirmUnverified = nil } })) {
            Button("Install") { if let u = confirmUnverified { Task { await install(u) } } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("No signed record: Gantry cannot check who made it.")
        }
        .confirmationDialog("Open an unverified plugin?", isPresented: Binding(get: { confirmOpen != nil }, set: { if !$0 { confirmOpen = nil } })) {
            Button("Open") { if let p = confirmOpen { PluginViewWindow.show(pluginId: p.id, unverified: true); dismiss() } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text(PluginsText.unverifiedRun)
        }
    }

    /// PLUG-06a part 2: opens the plugin's view in a tab (PLUG-06c); the helper starts then. An
    /// Unverified plugin asks first, each time (no stored "Allow unverified" setting yet).
    private func openPlugin(_ p: InstalledPluginView) {
        if p.tier == "unverified" { confirmOpen = p } else { PluginViewWindow.show(pluginId: p.id, unverified: false); dismiss() }
    }

    @ViewBuilder private var content: some View {
        switch tab {
        case .installed: installedTable
        case .catalogue: catalogueState
        case .updates: updatesTable
        }
    }

    private var installedTable: some View {
        Table(installed, selection: $selected) {
            TableColumn("Plugin") { p in Text(p.id).help(p.id) }.width(min: 140, ideal: 240)
            TableColumn("Version") { p in Text(p.version) }.width(min: 60, ideal: 80)
            TableColumn("Badge") { p in Text(PluginsText.badge(p.tier)) }.width(min: 70, ideal: 90)
            TableColumn("Status") { p in
                let why = PluginsPage.loadBlock(p)
                Text(why ?? "Allowed").foregroundStyle(why == nil ? Color.secondary : Color.red).help(why ?? "Policy allows it")
            }
            .width(min: 80, ideal: 200)
        }
        .overlay { if installed.isEmpty { Text("No plugins installed").foregroundStyle(.secondary) } }
        .accessibilityLabel("Installed plugins")
    }

    private var catalogueState: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(PluginsText.catalogueText(refreshOutcome)).accessibilityIdentifier("plugins-catalogue-state")
            Text("Only signed catalogue entries are offered.").foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
    }

    private var updatesTable: some View {
        Table(updates) {
            TableColumn("Plugin") { u in Text(u.id).help(u.id) }.width(min: 140, ideal: 240)
            TableColumn("From") { u in Text(u.from) }.width(min: 60, ideal: 80)
            TableColumn("To") { u in Text(u.to) }.width(min: 60, ideal: 80)
            TableColumn("Note") { u in
                Text(u.needsConsent ? "Asks for new permissions" : "").help(u.needsConsent ? "Review before updating" : "")
            }
            .width(min: 80, ideal: 200)
        }
        .overlay { if updates.isEmpty { Text("No updates").foregroundStyle(.secondary) } }
        .accessibilityLabel("Plugin updates")
    }

    private var footer: some View {
        HStack(spacing: 8) {
            if let message { Text(message).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail).help(message).accessibilityIdentifier("plugins-message") }
            Spacer(minLength: 8)
            if tab == .installed {
                Button("Open") { if let p = selectedPlugin { openPlugin(p) } }
                    .disabled(busy || selectedPlugin.map { PluginsPage.loadBlock($0) != nil } ?? true)
                    .help("Open the selected plugin")
                Button("Remove…", systemImage: "trash") { removing = selectedPlugin }.disabled(busy || selectedPlugin == nil)
                    .quietIcon("Remove the selected plugin")
            }
            Button("Refresh Catalogue", systemImage: "arrow.clockwise") { Task { await refresh() } }.disabled(busy || policy.pluginsDisabled)
                .quietIcon("Fetch the signed plugin catalogue")
            Button("Install from File…", systemImage: "plus") { pickFile() }.disabled(busy || policy.pluginsDisabled)
                .quietIcon("Install a .gantryplugin file")
            Button("Done") { dismiss() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
        }
        .controlSize(.small)
        .padding(10)
    }

    // MARK: - Actions

    private func reload() async {
        let dir = dataDir
        // Installed plugins' connection types: their library entries open (or stop opening).
        PluginEntries.reload()
        let result = await Task.detached(priority: .userInitiated) {
            Result { (try pluginsInstalled(dataDir: dir), try pluginsUpdates(dataDir: dir)) }
        }.value
        policy = pluginPolicyState()
        switch result {
        case .success(let (i, u)): installed = i; updates = u
        case .failure(let e): message = "Plugins unavailable: \(e.userMessage)"
        }
    }

    private func refresh() async {
        busy = true
        defer { busy = false }
        let dir = dataDir, mirror = PluginsPage.mirror
        let result = await Task.detached(priority: .userInitiated) { Result { try pluginsRefresh(dataDir: dir, mirror: mirror) } }.value
        switch result {
        case .success(let outcome): refreshOutcome = outcome; message = nil
        case .failure(let e): message = "Refresh failed: \(e.userMessage)"
        }
        await reload()
    }

    private func pickFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.allowedContentTypes = ["gantryplugin", "bastionplugin"].compactMap { UTType(filenameExtension: $0) }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        // A signed record beside the file (`<name>.sig`) installs it at its tier with no question
        // (PLUG-12). Only the core's "unverified" refusal leads to the unverified question.
        Task { await install(url, allowUnverified: false) }
    }

    private func install(_ url: URL, allowUnverified: Bool = true) async {
        busy = true
        defer { busy = false }
        let dir = dataDir, path = url.path
        let result = await Task.detached(priority: .userInitiated) { Result { try pluginInstallFile(dataDir: dir, path: path, allowUnverified: allowUnverified) } }.value
        switch result {
        case .success(let kind): message = PluginsText.installText(kind, file: url.lastPathComponent)
        case .failure(FfiError.Failed(_, "unverified")) where !allowUnverified:
            if policy.forbidUnverified || policy.officialOnly {
                message = "Policy forbids unverified plugins"
            } else {
                confirmUnverified = url
            }
        case .failure(let e): message = "Not installed: \(e.userMessage)"
        }
        await reload()
    }

    private func remove(_ p: InstalledPluginView, deleteData: Bool) async {
        busy = true
        defer { busy = false }
        let dir = dataDir, id = p.id
        let result = await Task.detached(priority: .userInitiated) { Result { try pluginRemove(dataDir: dir, id: id, deleteData: deleteData) } }.value
        switch result {
        case .success: message = deleteData ? "Removed \(id) and its data" : "Removed \(id)"
        case .failure(let e): message = "Not removed: \(e.userMessage)"
        }
        await reload()
    }
}

extension InstalledPluginView: Identifiable {}
extension PluginUpdateView: Identifiable {}

/// The page's wording and decisions, kept out of the view so they are testable.
enum PluginsPage {
    /// A catalogue mirror folder for test runs only (`BASTION_PLUGIN_MIRROR`); `nil` in other builds.
    static var mirror: String? { TestHooks.env("BASTION_PLUGIN_MIRROR") }

    /// The banner for the policy in force (`PluginsText.policyBanner`).
    static func policyBanner(_ p: PluginPolicyView) -> String? {
        PluginsText.policyBanner(error: p.error, disabled: p.pluginsDisabled, officialOnly: p.officialOnly,
                                 forbidUnverified: p.forbidUnverified, listedOnly: p.allowedIds != nil)
    }

    /// Why the plugin may not load under the policy in force, or `nil`. An Unverified plugin counts
    /// as allowed here because Open asks the user first; Safe mode is off.
    static func loadBlock(_ p: InstalledPluginView) -> String? {
        pluginMayLoad(id: p.id, tier: p.tier, allowUnverified: p.tier == "unverified", safeMode: false)
    }
}
