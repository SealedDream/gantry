import SwiftUI
import BastionCore

/// Pages and commands opened from places other than the main window (Settings links, the command
/// palette). The main window observes `request` and presents what it names.
@MainActor @Observable
final class AppRouter {
    var request: String?

    func open(_ target: String) {
        request = target
        // Sheets belong to the main window; bring it forward.
        NSApp.windows.first { $0.contentView?.firstSubview(of: KeyOutlineView.self) != nil }?.makeKeyAndOrderFront(nil)
    }
}

/// Settings window: categories from the core (only those with real settings) and search across
/// every setting. Rows are generated from the core definitions; each saves on change.
struct SettingsView: View {
    @Environment(SettingsModel.self) private var settings
    @State private var category: String? = "general"
    @State private var query = ""

    var body: some View {
        NavigationSplitView {
            List(selection: $category) {
                ForEach(settings.categories, id: \.id) { c in
                    Label(c.label, systemImage: Icons.symbol(c.icon)).tag(c.id)
                }
                Label("Plugins", systemImage: AppIcons.plugins.rawValue).tag(Self.pluginsPage)
                Label("Managed Policy", systemImage: "building.columns").tag(Self.policyPage)
            }
            .frame(minWidth: 200)
            .searchable(text: $query, placement: .sidebar, prompt: "Search settings")
            .toolbar(removing: .sidebarToggle)
            // Outermost, as in LibraryColumns (#1432): under .toolbar(removing:) the rule never reached
            // AppKit's split item, so the sidebar could shrink below 200 pt.
            .navigationSplitViewColumnWidth(min: 200, ideal: 210, max: 260)
        } detail: {
            Group {
                if !query.trimmingCharacters(in: .whitespaces).isEmpty {
                    SearchResults(query: query)
                } else if category == "about" {
                    AboutPage()
                } else if category == Self.policyPage {
                    PolicyPage()
                } else if category == Self.pluginsPage {
                    PluginsView()
                } else if category == "keyboard" {
                    KeyboardSettingsPage()
                } else {
                    // Clicking into the sidebar's search field clears the selection; show General
                    // rather than an empty page.
                    SettingsPage(definitions: settings.definitions(in: category ?? "general"),
                                 showsInterfaceSize: (category ?? "general") == "appearance")
                }
            }
            .frame(minWidth: 420, maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
            .navigationTitle(title)
        }
        .frame(minWidth: 680, minHeight: 420)
        // Pages opened from a Settings link attach to this window, so they appear in front of it
        // instead of on the main window behind it.
        .sheet(item: Binding(get: { settings.pendingSheet.map(SettingsSheet.init) }, set: { settings.pendingSheet = $0?.id })) { sheet in
            sheet.view
        }
        .onAppear(perform: takePending)
        .onChange(of: settings.pendingQuery) { takePending() }
        .onChange(of: settings.pendingCategory) { takePending() }
        .alert("Setting not saved", isPresented: Binding(get: { settings.error != nil }, set: { if !$0 { settings.error = nil } })) {
            Button("OK") { settings.error = nil }
        } message: { Text(settings.error ?? "") }
    }
}

extension SettingsView {
    /// Not a core settings category: the read-only managed policy (`PolicyPage`).
    static let policyPage = "policy"
    /// Not a core settings category: install, catalogue and updates (`PluginsView`).
    static let pluginsPage = "plugins"

    private func takePending() {
        if let c = settings.pendingCategory {
            settings.pendingCategory = nil
            query = ""
            category = c
        }
        guard let q = settings.pendingQuery else { return }
        settings.pendingQuery = nil
        query = q
    }

    /// The window title names the page, so the toolbar band carries information.
    private var title: String {
        if !query.trimmingCharacters(in: .whitespaces).isEmpty { return "Search" }
        if category == Self.policyPage { return "Managed Policy" }
        if category == Self.pluginsPage { return "Plugins" }
        return settings.categories.first { $0.id == category }?.label ?? "Settings"
    }
}

private struct SettingsPage: View {
    let definitions: [SettingDefView]
    var showsInterfaceSize = false

    var body: some View {
        Form {
            if showsInterfaceSize { InterfaceSizeRow() }
            ForEach(definitions, id: \.id) { SettingRow(def: $0) }
        }
        .formStyle(.grouped)
    }
}

/// Settings and keyboard shortcuts matching the query, by category.
private struct SearchResults: View {
    let query: String
    @Environment(SettingsModel.self) private var settings
    @Environment(ShortcutsModel.self) private var shortcuts

    var body: some View {
        let hits = settings.search(query)
        let keys = shortcuts.search(query)
        if hits.isEmpty && keys.isEmpty {
            ContentUnavailableView.search(text: query)
        } else {
            Form {
                ForEach(settings.categories.filter { c in hits.contains { $0.category == c.id } }, id: \.id) { c in
                    Section(c.label) {
                        ForEach(hits.filter { $0.category == c.id }, id: \.id) { SettingRow(def: $0) }
                    }
                }
                if !keys.isEmpty {
                    Section("Keyboard Shortcuts") {
                        ShortcutList(items: keys)
                    }
                }
            }
            .formStyle(.grouped)
        }
    }
}

/// One setting: label with its one-line help underneath, the control on the right.
private struct SettingRow: View {
    let def: SettingDefView
    @Environment(SettingsModel.self) private var settings
    @Environment(AppearanceSettings.self) private var appearance
    @Environment(ThemesModel.self) private var themes
    @Environment(AppRouter.self) private var router
    @Environment(CredentialsModel.self) private var credentials
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        if def.kind == "link" {
            Button(action: openLink) {
                HStack {
                    label
                    Spacer()
                    Image(systemName: "chevron.right").foregroundStyle(.tertiary)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(def.help)
        } else {
            LabeledContent { control } label: { label }
                .help(def.help)
        }
    }

    private var label: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(def.label)
            Text(def.help).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(2)
        }
    }

    @ViewBuilder private var control: some View {
        switch def.kind {
        case "toggle" where def.id == TelnetPolicy.settingId:
            AllowTelnetToggle(label: def.label)
        case "toggle":
            Toggle(def.label, isOn: Binding(get: { settings.value(def.id) == "true" }, set: { settings.set(def.id, $0 ? "true" : "false") }))
                .labelsHidden()
                .toggleStyle(.switch)
        case "integer":
            let n = Int(settings.value(def.id)) ?? Int(def.defaultValue) ?? 0
            Stepper(value: Binding(get: { n }, set: { settings.set(def.id, String($0)) }), in: Int(def.min)...Int(def.max)) {
                Text("\(n) \(def.unit)").monospacedDigit()
            }
        case "text":
            SettingTextField(def: def, multiline: false)
        case "multiline":
            SettingTextField(def: def, multiline: true)
        case "choice" where def.id == "terminal.theme":
            // Bundled and the user's own themes (the core's static list has only the bundled ones).
            Picker(def.label, selection: Binding(get: { settings.value(def.id) }, set: { settings.set(def.id, $0) })) {
                Text("Match app theme").tag(AppearanceSettings.matchAppTheme)
                ForEach(themes.items, id: \.id) { Text($0.name).tag($0.id) }
            }
            .labelsHidden()
            .fixedSize()
        case "choice" where def.id == "terminal.font-family":
            VStack(alignment: .trailing, spacing: DS.Space.xs) {
                TerminalFontPicker(selection: Binding(get: { TerminalFonts.family(settings.value(def.id)) }, set: { settings.set(def.id, $0) }))
                TerminalFontPreview(font: appearance.terminalFont)
                    .frame(width: 440)
                    .accessibilityLabel("Font preview")
            }
        case "choice" where def.id == "appearance.accent":
            AccentSwatches(selection: Binding(get: { appearance.accent }, set: { appearance.accent = $0 }))
        default:
            Picker(def.label, selection: Binding(get: { settings.value(def.id) }, set: { settings.set(def.id, $0) })) {
                ForEach(def.options, id: \.id) { Text($0.label).tag($0.id) }
            }
            .labelsHidden()
            .fixedSize()
        }
    }

    private func openLink() {
        guard let target = def.link else { return }
        switch target {
        case "credential-manager", "vaultwarden":
            credentials.source = target == "vaultwarden" ? .vaultwarden : .local
            openWindow(id: CredentialManagerView.windowId)
            bringToFront(CredentialManagerView.windowId)
        case "keyboard-shortcuts": settings.pendingCategory = "keyboard"
        case "window-current-size": WindowLaunchApplier.useCurrentSize(settings: settings)
        case _ where SettingsSheet.handles(target): settings.pendingSheet = target
        default: router.open(target)
        }
    }
}

/// Accent palette as swatches (the colours themselves are the clearest label).
struct AccentSwatches: View {
    @Binding var selection: AppearanceSettings.Accent

    var body: some View {
        HStack(spacing: DS.Space.xs) {
            ForEach(AppearanceSettings.Accent.allCases) { accent in
                Button { selection = accent } label: {
                    Circle()
                        .fill(accent.color)
                        .frame(width: DS.Size.swatch, height: DS.Size.swatch)
                        .overlay {
                            if selection == accent { Circle().strokeBorder(.primary, lineWidth: 2).padding(-3) }
                        }
                }
                .buttonStyle(.plain)
                .help(accent.label)
                .accessibilityLabel(accent.label)
                .accessibilityAddTraits(selection == accent ? .isSelected : [])
            }
        }
    }
}

private struct AboutPage: View {
    var body: some View {
        Form {
            LabeledContent("Version", value: appVersion())
            LabeledContent("Library") { Text(LibraryModel.libraryPath.path).textSelection(.enabled).truncationMode(.middle) }
            LabeledContent("Settings") { Text(SettingsModel.path.path).textSelection(.enabled).truncationMode(.middle) }
        }
        .formStyle(.grouped)
    }
}

/// A Settings link target shown as a sheet on the Settings window.
struct SettingsSheet: Identifiable {
    let id: String

    static func handles(_ target: String) -> Bool {
        ["terminal-themes", "ssh-sources", "ssh-import", "workspace-manager"].contains(target) || target.hasPrefix("defaults:")
    }

    @ViewBuilder var view: some View {
        switch id {
        case "terminal-themes": ThemeEditorView()
        case "ssh-sources": SshSourcesView(checkOnAppear: false)
        case "ssh-import": SshImportView()
        case "workspace-manager": WorkspaceManagerView()
        default:
            let p = String(id.dropFirst("defaults:".count))
            if let type = defaultSettingTypes.first(where: { $0.protocolName == p }) {
                PropertyEditor(target: .type(protocolName: type.protocolName, label: type.label))
            }
        }
    }
}

/// Order a SwiftUI `Window` scene in front once it exists: `openWindow` reuses an open window
/// without raising it above the window the request came from.
@MainActor func bringToFront(_ windowId: String) {
    DispatchQueue.main.async {
        QuietLaunch.activate()
        NSApp.windows.first { $0.identifier?.rawValue.hasPrefix(windowId) == true }?.makeKeyAndOrderFront(nil)
    }
}

/// The app's own UI scale (`UIZoom`). Only here: ⌘+ / ⌘- / ⌘0 zoom the session, not the app
/// (owner feedback 2026-11-07 #13).
private struct InterfaceSizeRow: View {
    var body: some View {
        Picker(selection: Binding(get: { UIZoom.shared.scale }, set: { UIZoom.shared.set($0) })) {
            ForEach(UIZoom.steps, id: \.self) { Text("\(Int(($0 * 100).rounded())) %").tag($0) }
        } label: {
            VStack(alignment: .leading, spacing: 2) {
                Text("Interface size")
                Text("Text and controls of the app. ⌘+ and ⌘- zoom the session instead.")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityIdentifier("setting-interface-size")
    }
}

/// A free-text setting (LOG-CORE-02: log folder, redaction patterns). Saved on Return or when the
/// field loses focus; the core validates it and a refusal shows in the settings error.
private struct SettingTextField: View {
    let def: SettingDefView
    let multiline: Bool
    @Environment(SettingsModel.self) private var settings
    @State private var draft = ""
    @FocusState private var focused: Bool

    var body: some View {
        Group {
            if multiline {
                TextEditor(text: $draft).font(DS.Font.body.monospaced()).frame(width: 320, height: 72)
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(.separator))
            } else {
                TextField(def.label, text: $draft, prompt: Text("Default")).labelsHidden().textFieldStyle(.roundedBorder).frame(width: 320)
                    .onSubmit(save)
            }
        }
        .multilineTextAlignment(.leading)
        .focused($focused)
        .onChange(of: focused) { _, now in if !now { save() } }
        .onAppear { draft = settings.value(def.id) }
        .onDisappear(perform: save)
    }

    private func save() {
        if draft != settings.value(def.id) { settings.set(def.id, draft) }
    }
}
