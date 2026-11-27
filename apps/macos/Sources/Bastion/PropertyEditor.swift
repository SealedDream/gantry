import SwiftUI
import BastionCore

/// What the property editor edits: one connection, a folder's defaults, or a connection
/// type's Default Settings.
enum EditorTarget: Identifiable {
    case connection(id: String, name: String, protocolName: String)
    case folder(id: String, name: String)
    case type(protocolName: String, label: String)

    var id: String {
        switch self {
        case .connection(let id, _, _), .folder(let id, _): id
        case .type(let p, _): "type:\(p)"
        }
    }

    var title: String {
        switch self {
        case .connection(_, let name, _): name
        case .folder(_, let name): "\(name) — Folder Defaults"
        case .type(_, let label): "\(label) — Default Settings"
        }
    }

    /// A plugin type (`<plugin id>/<type id>`) takes its installed type's icon (PVE-TLS).
    @MainActor var symbol: String {
        switch self {
        case .connection(_, _, let p), .type(let p, _): p.contains("/") ? Icons.symbol(Icons.info(p).id) : protocolSymbol(p)
        case .folder: "folder"
        }
    }

    var isDefaults: Bool {
        if case .connection = self { return false }
        return true
    }
}

/// Readable text for an FFI error (`Failed(message:)` carries the core's sentence).
func errorText(_ error: Error) -> String {
    if case FfiError.Failed(let message, _)? = error as? FfiError { return message }
    let raw = "\(error)"
    guard let start = raw.range(of: "message: \""), raw.hasSuffix("\")") else { return raw }
    return String(raw[start.upperBound..<raw.index(raw.endIndex, offsetBy: -2)])
}

/// Royal TS-style settings dialog: "<Type> Connection Settings" with the type icon and a
/// favourite star, grouped pages on the left (each with a large icon and an explanation), and
/// Discard changes / Apply & Close. The same layout edits folders and Default Settings. The
/// schema comes from the core, so a page appears only when Bastion honours its settings.
struct PropertyEditor: View {
    let target: EditorTarget
    @Environment(LibraryModel.self) private var model
    @Environment(ThemesModel.self) private var themes
    @Environment(CredentialsModel.self) private var credentials
    @Environment(\.dismiss) private var dismiss
    @Environment(\.density) private var density
    @State private var defs: [PropertyDefView] = []
    @State private var values: [String: PropertyValueView] = [:]
    /// Pending text per key; an empty string means "reset to inherited".
    @State private var edits: [String: String] = [:]
    @State private var failures: [String: String] = [:]
    @State private var page: String?
    /// The last test passed: the footer shows a tick for `TestOutcome.okSeconds`.
    @State private var testPassed = false
    /// The last test failed (or did not start): its report shows in a popover on the button.
    @State private var testFailed = false
    @State private var search = ""
    @State private var loadError: String?
    @State private var credentialDraft = CredentialDraft()
    @State private var customProps: [CustomPropertyView] = []
    @State private var customEdits: [String: String] = [:]
    @State private var newPropName = ""
    /// Unsaved edits of a plugin entry's own fields, by key.
    @State private var pluginEdits: [String: String] = [:]
    @State private var connectionTest = ConnectionTest()
    @Environment(SessionsModel.self) private var sessions
    @Environment(Commands.self) private var commands

    private var pages: [EditorPage] {
        let used = Set(defs.map(EditorPage.pageId(for:)))
        var extra: Set<String> = []
        if case .connection(_, _, let p) = target {
            extra.insert("custom")
            if p == "ssh" { extra.insert("tunnels") }
        }
        return EditorPage.all(for: target).filter { used.contains($0.id) || extra.contains($0.id) }
    }

    private var groups: [String] {
        let first = EditorPage.mainGroup(for: target)
        return [first] + EditorPage.groupOrder.filter { g in pages.contains { $0.group == g } }
    }

    private var currentPage: EditorPage? { pages.first { $0.id == (page ?? pages.first?.id) } }

    private var visible: [PropertyDefView] {
        if !search.isEmpty {
            return defs.filter { [$0.label, $0.help, $0.category].contains { $0.localizedCaseInsensitiveContains(search) } }
        }
        return defs.filter { EditorPage.pageId(for: $0) == currentPage?.id }
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            HStack(spacing: 0) {
                navigation
                Divider()
                fields
            }
            Divider()
            // Test Connection takes no room of its own (owner round 3, item 1): a tick that fades
            // in the footer when it passes, a small closable popover on the button when it fails.
            footer
        }
        .onDisappear { connectionTest.cancel() }
        .onChange(of: connectionTest.running) { _, running in if !running { testFinished() } }
        .onChange(of: connectionTest.driverShown) { _, _ in testFinished() }
        .onChange(of: connectionTest.startError) { _, e in if e != nil { testFailed = true } }
        // SEC-07: a test that stopped at an unknown host key asks here; closing the prompt any way is a no.
        .sheet(item: Binding(get: { connectionTest.hostKeyQuestion }, set: { if $0 == nil { connectionTest.declineHostKey() } })) { question in
            TestHostKeyPrompt(question: question, test: connectionTest)
        }
        .onAppear { connectionTest.registerForDriver() }
        .frame(width: DS.Size.editorWidth, height: DS.Size.editorHeight)
        .onAppear(perform: load)
        .onAppear { PropertyEditorDriver.state = driverState }
        .onAppear {
            if let start = commands.editorStartPage { page = start; commands.editorStartPage = nil }
        }
    }

    private var header: some View {
        HStack(spacing: DS.Space.s) {
            Image(systemName: target.symbol)
                .font(DS.Font.size(22, weight: .regular))
                .foregroundStyle(.tint)
                .frame(width: DS.Space.xl)
            VStack(alignment: .leading, spacing: 2) {
                Text(dialogTitle).font(DS.Font.title).lineLimit(1)
                Text(subtitle).font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if case .connection(let id, _, _) = target {
                let favorite = model.connection(id: id)?.favorite ?? false
                Button(favorite ? "Remove from Favorites" : "Add to Favorites", systemImage: favorite ? "star.fill" : "star") {
                    model.mutate { try $0.setFavorite(id: id, favorite: !favorite) }
                }
                .labelStyle(.iconHitTarget)
                .buttonStyle(.borderless)
                .font(DS.Font.title3)
                .foregroundStyle(favorite ? AnyShapeStyle(.yellow) : AnyShapeStyle(.secondary))
                .help(favorite ? "Remove from Favorites" : "Add to Favorites")
            }
        }
        .padding(DS.Space.m)
    }

    private var dialogTitle: String {
        switch target {
        case .connection: "\(EditorPage.mainGroup(for: target)) Connection Settings"
        case .folder: "Folder Settings"
        case .type(_, let label): "\(label) Default Settings"
        }
    }

    private var subtitle: String {
        switch target {
        case .connection(_, let name, _): name
        case .folder(_, let name): "\(name) — connections and sub-folders inside inherit these unless they set their own."
        case .type(let p, _): "Applies to every \(p.uppercased()) connection unless a folder or the connection sets its own."
        }
    }

    private var navigation: some View {
        VStack(alignment: .leading, spacing: 0) {
            TextField("Search settings", text: $search)
                .textFieldStyle(.roundedBorder)
                .padding(DS.Space.xs)
            List(selection: Binding(get: { search.isEmpty ? (page ?? pages.first?.id) : nil },
                                    set: { page = $0; search = "" })) {
                ForEach(groups, id: \.self) { group in
                    Section(group) {
                        ForEach(pages.filter { $0.group == group }) { p in
                            HStack {
                                Label(p.title, systemImage: p.symbol)
                                Spacer()
                                let customised = defs.filter { EditorPage.pageId(for: $0) == p.id && isCustomised($0) }.count
                                if customised > 0 { Badge(text: "\(customised)", color: .accentColor) }
                            }
                            .padding(.vertical, density.rowPadding)
                            .tag(p.id)
                        }
                    }
                    // The sidebar's collapse button is a 15 pt hit target and hiding a group is never wanted here.
                    .collapsible(false)
                }
            }
            .listStyle(.sidebar)
        }
        .frame(width: DS.Size.editorNav)
        // UI driver (`login-page <page id>`): the sidebar's rows carry no AppKit title to click.
        .onReceive(NotificationCenter.default.publisher(for: DriverEvents.pressButton)) { note in
            guard let step = note.object as? String else { return }
            if step.hasPrefix("custom-set:") {
                // `custom-set <name>=<value>`: as typing a new name, Add, then the value ("" removes).
                let kv = step.dropFirst("custom-set:".count).split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
                guard kv.count == 2 else { return }
                if !customProps.contains(where: { $0.name == kv[0] }) { customProps.append(CustomPropertyView(name: kv[0], value: "")) }
                customEdits[kv[0]] = kv[1]
                return
            }
            guard step.hasPrefix("login-page:") else { return }
            page = String(step.dropFirst("login-page:".count))
            search = ""
        }
    }

    private var fields: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: DS.Space.m) {
                if let loadError {
                    Label(loadError, systemImage: "exclamationmark.triangle").foregroundStyle(.red)
                }
                if search.isEmpty, let currentPage { PageHeader(page: currentPage) }
                if visible.isEmpty && !search.isEmpty {
                    Text("No settings match “\(search)”.").foregroundStyle(.secondary)
                }
                if search.isEmpty && currentPage?.id == "credentials" {
                    CredentialsPage(target: target, draft: credentialDraft, values: values,
                                    field: { AnyView(field($0)) }, usernameDef: defs.first { $0.key == "username" })
                    if let f = failures["credentials"] { Text(f).font(DS.Font.caption).foregroundStyle(.red) }
                } else {
                    ForEach(visible, id: \.key) { field($0) }
                }
                if search.isEmpty && currentPage?.id == "custom", case .connection = target { customProperties }
                if search.isEmpty && currentPage?.id == "tunnels" { tunnels }
                if search.isEmpty && currentPage?.id == "main", let entry = pluginEntry { pluginSections(entry.connection) }
                if case .connection(_, _, let p) = target, !connectableProtocols.contains(p), pluginEntry == nil {
                    Label("Opening \(p.uppercased()) sessions is not implemented yet; these values are stored for when it is.",
                          systemImage: "info.circle")
                        .font(DS.Font.caption).foregroundStyle(.secondary)
                }
            }
            .padding(DS.Space.l)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    // MARK: - Plugin entries

    /// What the UI driver checks (`plugin-props-state`): title, icon, certificate section, the
    /// "not implemented" line.
    private var driverState: [String: String] {
        let notImplemented: Bool = { if case .connection(_, _, let p) = target { return !connectableProtocols.contains(p) && pluginEntry == nil }; return false }()
        return ["title": dialogTitle, "icon": target.symbol, "certificate": pluginEntry != nil ? "shown" : "none",
                "notimpl": notImplemented ? "shown" : "none", "test": testableProtocol != nil ? "shown" : "none"]
    }

    /// The plugin type's own fields and the certificate rule, on the main page (PVE-TLS).
    @ViewBuilder private func pluginSections(_ c: ConnectionView) -> some View {
        let fields = (try? model.library?.pluginEntryFields(dataDir: LibraryModel.dataDir.path, id: c.id)) ?? []
        ForEach(fields, id: \.key) { f in
            HStack(alignment: .firstTextBaseline, spacing: DS.Space.s) {
                Text(f.label).font(DS.Font.bodyStrong).frame(width: DS.Size.editorLabel, alignment: .trailing).lineLimit(1)
                TextField(f.label, text: Binding(get: { pluginEdits[f.key] ?? f.value ?? "" }, set: { pluginEdits[f.key] = $0 }))
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier("plugin-field-\(f.key)")
            }
        }
        if let f = failures["plugin"] { Text(f).font(DS.Font.caption).foregroundStyle(.red) }
        HStack(alignment: .firstTextBaseline, spacing: DS.Space.s) {
            Text("Certificate").font(DS.Font.bodyStrong).frame(width: DS.Size.editorLabel, alignment: .trailing)
            PluginEntryTlsRow(connection: c)
        }
        .accessibilityIdentifier("plugin-certificate-section")
    }

    // MARK: - Custom properties and tunnels

    @ViewBuilder private var customProperties: some View {
        Divider()
        ForEach(customProps, id: \.name) { prop in
            HStack(alignment: .firstTextBaseline, spacing: DS.Space.s) {
                Text(prop.name).font(DS.Font.bodyStrong).frame(width: DS.Size.editorLabel, alignment: .trailing).lineLimit(1)
                TextField(prop.name, text: Binding(get: { customEdits[prop.name] ?? prop.value }, set: { customEdits[prop.name] = $0 }))
                    .textFieldStyle(.roundedBorder)
                Button("Remove \(prop.name)", systemImage: "minus.circle") { customEdits[prop.name] = "" }
                    .labelStyle(.iconHitTarget).buttonStyle(.borderless)
            }
        }
        HStack(spacing: DS.Space.s) {
            Text("New property").font(DS.Font.bodyStrong).frame(width: DS.Size.editorLabel, alignment: .trailing)
            TextField("Name", text: $newPropName).textFieldStyle(.roundedBorder).frame(width: 160)
            Button("Add") {
                let n = newPropName.trimmingCharacters(in: .whitespaces)
                guard !n.isEmpty, !customProps.contains(where: { $0.name == n }) else { return }
                customProps.append(CustomPropertyView(name: n, value: ""))
                customEdits[n] = ""
                newPropName = ""
            }
            .disabled(newPropName.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        if let f = failures["custom"] { Text(f).font(DS.Font.caption).foregroundStyle(.red) }
    }

    @ViewBuilder private var tunnels: some View {
        let list = (try? model.library?.tunnels())?.filter { $0.viaId == target.id } ?? []
        if list.isEmpty {
            Text("No saved tunnels use this connection. Create one in Tools › Tunnel Manager.").foregroundStyle(.secondary)
        } else {
            ForEach(list, id: \.id) { t in
                LabeledContent(t.name) {
                    Text(t.kind == "dynamic" ? "SOCKS on localhost:\(t.localPort)"
                         : t.kind == "remote" ? "server :\(t.port) → localhost:\(t.localPort)"
                         : "localhost:\(t.localPort) → \(t.host):\(t.port)")
                        .foregroundStyle(.secondary).monospacedDigit()
                }
            }
        }
    }

    private func field(_ def: PropertyDefView) -> some View {
        let value = values[def.key]
        return VStack(alignment: .leading, spacing: DS.Space.xxs) {
            HStack(alignment: .firstTextBaseline, spacing: DS.Space.s) {
                Text(def.label)
                    .font(DS.Font.bodyStrong)
                    .frame(width: DS.Size.editorLabel, alignment: .trailing)
                input(def, value)
                badge(def, value)
                if def.inheritable && hasOwnValue(def) {
                    Button("Reset", systemImage: "arrow.uturn.backward") {
                        edits[def.key] = ""
                        failures[def.key] = nil
                    }
                    .labelStyle(.iconHitTarget)
                    .buttonStyle(.borderless)
                    .iconTip("Reset to inherited value")
                }
            }
            Text(failures[def.key] ?? help(def, value))
                .font(DS.Font.caption)
                .foregroundStyle(failures[def.key] == nil ? AnyShapeStyle(.secondary) : AnyShapeStyle(.red))
                .padding(.leading, DS.Size.editorLabel + DS.Space.s)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.vertical, density.rowPadding)
    }

    @ViewBuilder private func input(_ def: PropertyDefView, _ value: PropertyValueView?) -> some View {
        let text = Binding(get: { edits[def.key] ?? value?.own ?? "" },
                           set: { edits[def.key] = $0; failures[def.key] = nil })
        let isNumber = def.kind == "port" || def.kind == "seconds"
        if def.kind == "terminaltheme" {
            let list = themes.items
            let inherited = value?.own == nil ? value?.effective.flatMap { id in list.first { $0.id == id }?.name } : nil
            Picker(def.label, selection: Binding(get: { edits[def.key] ?? value?.own ?? "" }, set: { text.wrappedValue = $0 })) {
                Text(inherited.map { "Inherited (\($0))" } ?? "App theme").tag("")
                ForEach(list, id: \.id) { Text($0.name).tag($0.id) }
            }
            .labelsHidden()
            .fixedSize()
            Spacer(minLength: 0)
        } else if def.kind == "terminalfont" {
            // Blank uses the inherited font or the app's (Settings › Terminal).
            let inherited = value?.own == nil ? value?.effective : nil
            let families = TerminalFonts.families()
            Picker(def.label, selection: Binding(get: { edits[def.key] ?? value?.own ?? "" }, set: { text.wrappedValue = $0 })) {
                Text(inherited.map { "Inherited (\($0))" } ?? "App font").tag("")
                ForEach(families, id: \.family) { Text($0.label).tag($0.family) }
                if let own = value?.own, !families.contains(where: { $0.family == own }) { Text("\(own) (not installed)").tag(own) }
            }
            .labelsHidden()
            .fixedSize()
            Spacer(minLength: 0)
        } else if def.kind == "credential" {
            let inherited = value?.own == nil ? value?.effective.flatMap { credentials.credential(id: $0)?.name } : nil
            Picker(def.label, selection: Binding(get: { edits[def.key] ?? value?.own ?? "" }, set: { text.wrappedValue = $0 })) {
                Text(inherited.map { "Inherited (\($0))" } ?? "None").tag("")
                ForEach(credentials.items, id: \.id) { Text($0.name).tag($0.id) }
            }
            .labelsHidden()
            .fixedSize()
            Spacer(minLength: 0)
        } else if def.kind == "gateway" {
            // Blank inherits; the inherited gateway's name is part of the blank entry.
            let gateways = (try? model.library?.gateways()) ?? []
            let inherited = value?.own == nil ? value?.effective.flatMap { id in gateways.first { $0.id == id }?.name } : nil
            Picker(def.label, selection: Binding(get: { edits[def.key] ?? value?.own ?? "" }, set: { text.wrappedValue = $0 })) {
                Text(inherited.map { "Inherited (\($0))" } ?? "None").tag("")
                ForEach(gateways, id: \.id) { Text("\($0.name) — \($0.host)").tag($0.id) }
            }
            .labelsHidden()
            .fixedSize()
            Spacer(minLength: 0)
        } else if def.kind == "choice" {
            Picker(def.label, selection: Binding(get: { edits[def.key] ?? value?.effective ?? "" }, set: { text.wrappedValue = $0 })) {
                ForEach(def.options, id: \.id) { Text($0.label).tag($0.id) }
            }
            .labelsHidden()
            .fixedSize()
            Spacer(minLength: 0)
        } else if def.kind == "toggle" {
            Toggle(def.label, isOn: Binding(get: { (edits[def.key] ?? value?.effective) == "true" }, set: { text.wrappedValue = $0 ? "true" : "false" }))
                .labelsHidden()
                .toggleStyle(.switch)
                .controlSize(.small)
            Spacer(minLength: 0)
        } else if def.kind == "tags" {
            TagField(text: text, suggestions: Tags.all(in: model.tree))
        } else if def.kind == "multiline" {
            TextEditor(text: text)
                .font(DS.Font.body)
                .frame(height: 96)
                .overlay(RoundedRectangle(cornerRadius: 4).strokeBorder(.separator))
        } else {
            // An unset inheritable field shows the value it would inherit as its placeholder.
            TextField(value?.own == nil ? (value?.effective ?? def.label) : def.label, text: text)
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: isNumber ? DS.Size.numberField : .infinity, alignment: .leading)
            if isNumber { Spacer(minLength: 0) }
        }
    }

    @ViewBuilder private func badge(_ def: PropertyDefView, _ value: PropertyValueView?) -> some View {
        if let edit = edits[def.key], edit != (value?.own ?? "") {
            Badge(text: "Modified", color: .orange)
        } else if let value, def.inheritable {
            switch value.source {
            case "own": Badge(text: "Overridden", color: .accentColor)
            case "inherited": Badge(text: "Inherited")
            case "typedefault": Badge(text: "Type default")
            case "builtin": Badge(text: "Default")
            default: EmptyView()
            }
        }
    }

    private func help(_ def: PropertyDefView, _ value: PropertyValueView?) -> String {
        guard def.inheritable, let value else { return def.help }
        var parts = [def.help]
        switch value.source {
        case "inherited": parts.append("Inherited from \(value.from ?? "a folder").")
        case "typedefault": parts.append("From the \((value.from ?? "").uppercased()) Default Settings.")
        case "builtin": parts.append("Built-in default.")
        default: break
        }
        if target.isDefaults {
            let affected = affectedNames(def.key)
            let shown = affected.prefix(4).joined(separator: ", ")
            parts.append(affected.isEmpty ? "No connection takes this value from here."
                         : "Applies to \(affected.count): \(shown)\(affected.count > 4 ? ", …" : "").")
        }
        return parts.joined(separator: " ")
    }

    private var footer: some View {
        HStack {
            if !failures.isEmpty {
                Label("\(failures.count) setting\(failures.count == 1 ? "" : "s") not saved", systemImage: "exclamationmark.circle")
                    .foregroundStyle(.red).font(DS.Font.caption)
            } else if !pendingKeys.isEmpty || credentialDraft.inlineChanged || !pendingCustom.isEmpty {
                Text("Unsaved changes").font(DS.Font.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if testableProtocol != nil {
                if testPassed {
                    Label("Connection OK", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green).font(DS.Font.caption)
                        .transition(.opacity)
                        .accessibilityIdentifier("test-connection-ok")
                }
                if connectionTest.running {
                    ProgressView().controlSize(.small)
                    Button("Cancel Test") { connectionTest.cancel() }
                } else {
                    Button("Test Connection") {
                        testPassed = false; testFailed = false
                        startTest()
                    }
                        .keyboardShortcut("t", modifiers: .command)
                        .help(pluginEntry != nil
                              ? "⌘T: checks the TLS handshake and certificate with the host and port entered here. Nothing is saved."
                              : "⌘T: checks name lookup, port, handshake, host key, jump host and login with what is entered here. Nothing is saved.")
                        .popover(isPresented: $testFailed, arrowEdge: .top) { testFailurePopover }
                        .background(DriverFrame(name: "test-connection"))
                }
            }
            Button("Discard changes", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
            Button("Apply & Close") { if apply() { dismiss() } }
                .keyboardShortcut(.defaultAction).dsPrimaryButton()
        }
        .padding(DS.Space.m)
    }

    // MARK: - Test Connection

    /// What a finished test shows: a fading tick when every step passed, else the failure popover.
    private func testFinished() {
        guard !connectionTest.running else { return }
        if TestOutcome.passed(connectionTest) {
            withAnimation { testPassed = true }
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(TestOutcome.okSeconds))
                withAnimation { testPassed = false }
            }
        } else if connectionTest.report != nil || connectionTest.startError != nil {
            testFailed = true
        }
    }

    private var testFailurePopover: some View {
        VStack(alignment: .leading, spacing: DS.Space.xs) {
            HStack {
                Text("Test failed").font(DS.Font.headline)
                Spacer()
                Button { testFailed = false } label: { Image(systemName: "xmark").iconHitTarget() }
                    .buttonStyle(.borderless).help("Close").accessibilityLabel("Close")
            }
            ConnectionTestResults(test: connectionTest)
        }
        .padding(DS.Space.m)
        .frame(width: TestOutcome.popoverWidth)
        .fixedSize(horizontal: false, vertical: true)
        .accessibilityIdentifier("test-connection-failure")
    }

    /// The edited connection, when it is an entry of an installed plugin's type.
    private var pluginEntry: (connection: ConnectionView, type: PluginTypeView)? {
        guard case .connection(let id, _, _) = target, let c = model.connection(id: id), let type = PluginEntries.type(of: c) else { return nil }
        return (c, type)
    }

    /// A plugin entry gets the core's TLS check under its certificate rule; every other entry
    /// the protocol probe.
    private func startTest() {
        if let (c, type) = pluginEntry {
            let pin = (try? model.library?.pluginEntryTls(id: c.id)).flatMap { $0 }.flatMap { $0.mode == "pinned" ? $0.pinSha256 : nil }
            let port = UInt16(current("port")) ?? type.defaultPort ?? 443
            connectionTest.startPlugin(host: current("host"), port: port, pin: pin, login: pluginLoginTest(c, type: type, host: current("host"), port: port))
        } else if let input = probeInput() {
            connectionTest.start(manager: sessions.manager, library: model.library, input: input)
        }
    }

    /// The login part of a plugin entry's test: only for the saved host and port (an edited
    /// dialog is tested with TLS alone), over the route the entry's tab would take.
    private func pluginLoginTest(_ c: ConnectionView, type: PluginTypeView, host: String, port: UInt16) -> ConnectionTest.PluginLoginTest? {
        guard let library = model.library, host == c.host, port == (c.port ?? type.defaultPort ?? 443) else { return nil }
        var via: PluginRoute?
        if case .route(let r) = PluginEntryRoute.plan(for: c, port: port, library: library, running: sessions.runningTunnels) { via = r }
        return ConnectionTest.PluginLoginTest(library: library, vault: credentials.vault, connectionId: c.id, allowUnverified: type.tier == "Unverified", via: via)
    }

    /// The protocol of an edited connection that has a network target; nil hides the button.
    private var testableProtocol: String? {
        guard case .connection(_, _, let p) = target, p != "local", p != "serial" else { return nil }
        return p
    }

    /// The pending text for `key`, else the effective (own or inherited) value.
    private func current(_ key: String) -> String {
        let text = allEdits[key] ?? values[key]?.effective ?? ""
        return text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Everything the dialog holds now, saved or not. The jump hosts are the saved chain a real
    /// connect dials (gateway, then ProxyJump; see `TestConnectionRoute`), with the dialog's
    /// gateway in place of the saved one when it was changed. Each logs in with a copy of the
    /// target's login, as a real connect does for a hop without a login of its own.
    private func probeInput() -> ProbeInput? {
        guard case .connection(let id, _, let p) = target else { return nil }
        let defaultPort: UInt16 = switch p { case "rdp": 3389; case "vnc": 5900; case "web": 443; case "ftps": 21; default: 22 }
        let user = credentialDraft.mode == .inline && !credentialDraft.username.isEmpty ? credentialDraft.username : current("username")
        let login = credentialDraft.probeLogin(connectionId: id, inherited: values["credential_id"]?.effective, vault: credentials.vault)
        let gatewayId = current("gateway_id")
        let dialogGateway = gatewayId.isEmpty ? nil : (try? model.library?.gateways())??.first(where: { $0.id == gatewayId }).map {
            TestRouteHop(host: $0.host, port: $0.port ?? 22, username: $0.username.flatMap { $0.isEmpty ? nil : $0 } ?? user)
        }
        let saved = model.library.map { sessions.jumpHosts(library: $0, connectionId: id) } ?? []
        let route = TestConnectionRoute.hops(saved: saved.map { SavedHop(key: $0.key, username: $0.username) },
                                             savedGatewayId: (values["gateway_id"]?.effective ?? "").trimmingCharacters(in: .whitespacesAndNewlines),
                                             dialogGatewayId: gatewayId, dialogGateway: dialogGateway)
        let jumps = route.map { ProbeJump(host: $0.host, port: $0.port, username: $0.username, login: login ?? .agent) }
        return ProbeInput(protocol: p, host: current("host"), port: UInt16(current("port")) ?? defaultPort, username: user,
                          login: login, jumps: jumps, pastedKey: credentialDraft.pastedKey,
                          pastedKeyPassphrase: credentialDraft.pastedKey == nil ? nil : credentialDraft.passphrase,
                          connectionId: id)
    }

    // MARK: - Data

    /// Field edits plus the Credentials page's assignment.
    private var allEdits: [String: String] { edits.merging(credentialDraft.propertyEdits) { _, credential in credential } }

    private var pendingKeys: [String] {
        allEdits.filter { key, text in text != (values[key]?.own ?? "") }.map(\.key).sorted()
    }

    private var pendingCustom: [String: String] {
        customEdits.filter { name, text in text != (customProps.first { $0.name == name }?.value ?? "") || text.isEmpty }
    }

    private func hasOwnValue(_ def: PropertyDefView) -> Bool {
        if let edit = edits[def.key] { return !edit.isEmpty }
        return values[def.key]?.own != nil
    }

    private func isCustomised(_ def: PropertyDefView) -> Bool {
        def.inheritable && hasOwnValue(def)
    }

    private func affectedNames(_ key: String) -> [String] {
        guard let library = model.library else { return [] }
        switch target {
        case .folder(let id, _): return (try? library.affectedByDefault(folderId: id, protocolName: nil, key: key)) ?? []
        case .type(let p, _): return (try? library.affectedByDefault(folderId: nil, protocolName: p, key: key)) ?? []
        case .connection: return []
        }
    }

    private func load() {
        guard let library = model.library else { return }
        do {
            let list: [PropertyValueView]
            switch target {
            case .connection(let id, _, let p):
                defs = try propertySchema(protocolName: p, defaultsOnly: false)
                list = try library.propertyValues(id: id)
            case .folder(let id, _):
                defs = try propertySchema(protocolName: nil, defaultsOnly: true)
                list = try library.propertyValues(id: id)
            case .type(let p, _):
                defs = try propertySchema(protocolName: p, defaultsOnly: true)
                list = try library.typeDefaultValues(protocolName: p)
            }
            values = Dictionary(list.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
            if case .connection(let id, _, _) = target {
                let inlineKind = model.connection(id: id)?.inlineCredential
                let inlineUser = inlineKind == nil ? nil : (try? credentials.vault?.inlineFor(connectionId: id))??.username
                credentialDraft.load(values: values, inlineKind: inlineKind, inlineUser: inlineUser)
                customProps = (try? library.customProperties(id: id)) ?? []
                customEdits = [:]
            } else {
                credentialDraft.load(values: values, inlineKind: nil, inlineUser: nil)
            }
            loadError = nil
        } catch {
            loadError = errorText(error)
        }
    }

    private func reloadValues() throws -> [String: PropertyValueView] {
        guard let library = model.library else { return values }
        let list: [PropertyValueView]
        switch target {
        case .connection(let id, _, _), .folder(let id, _): list = try library.propertyValues(id: id)
        case .type(let p, _): list = try library.typeDefaultValues(protocolName: p)
        }
        return Dictionary(list.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
    }

    /// Write every pending change, then save once. Keys the core rejects keep their text and
    /// show its message. Returns true when everything was saved.
    private func apply() -> Bool {
        var failed: [String: String] = [:]
        let pending = pendingKeys
        let merged = allEdits
        let custom = pendingCustom
        let plugin = pluginEdits
        model.mutate { library in
            if case .connection(let id, _, _) = target {
                for (key, text) in plugin {
                    do { try library.setPluginField(dataDir: LibraryModel.dataDir.path, id: id, key: key, value: text.isEmpty ? nil : text) } catch { failed["plugin"] = errorText(error) }
                }
            }
            if case .connection(let id, _, _) = target {
                if let message = credentialDraft.saveInline(connectionId: id, library: library, credentials: credentials) {
                    failed["credentials"] = message
                }
                for (name, text) in custom {
                    do { try library.setCustomProperty(id: id, name: name, value: text.isEmpty ? nil : text) } catch { failed["custom"] = errorText(error) }
                }
            }
            for key in pending {
                let text = merged[key] ?? ""
                let value: String? = text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : text
                do {
                    switch target {
                    case .connection(let id, _, _), .folder(let id, _):
                        try library.setProperty(id: id, key: key, value: value)
                    case .type(let p, _):
                        try library.setTypeDefault(protocolName: p, key: key, value: value)
                    }
                } catch {
                    failed[key] = errorText(error)
                }
            }
        }
        failures = failed
        edits = edits.filter { failed[$0.key] != nil }
        if failed["plugin"] == nil { pluginEdits = [:] }
        if failed["credentials"] == nil && failed["credential_id"] == nil && failed["credential_name"] == nil { load() }
        else { values = (try? reloadValues()) ?? values }
        return failed.isEmpty
    }
}

/// Owner round 3, item 1: how a finished Test Connection is shown.
enum TestOutcome {
    /// How long the "Connection OK" tick stays.
    static let okSeconds: Double = 3
    static let popoverWidth: CGFloat = 420

    /// Every step ran and none failed or warned, and the verdict has nothing to say.
    @MainActor static func passed(_ test: ConnectionTest) -> Bool {
        guard test.startError == nil, let report = test.report, !report.cancelled,
              report.verdict.headline == nil else { return false }
        return report.steps.allSatisfy { $0.status == "ok" || $0.status == "skipped" }
    }
}

/// The last opened property dialog's state, for the UI driver only.
@MainActor enum PropertyEditorDriver {
    static var state: [String: String] = [:]
}
