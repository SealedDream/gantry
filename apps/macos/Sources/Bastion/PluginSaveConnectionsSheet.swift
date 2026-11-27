import SwiftUI
import BastionCore

/// The core-worded sheet for a plugin's `library.propose` (plugin API 1.6): Save as Connection.
/// One row per proposed guest: include, name, protocol, host. Above: the destination folder
/// (existing or new) and an optional saved credential, linked by id. A row whose host and
/// protocol are already in the folder is marked and left out. The core checks every row again
/// and saves normal connections (`Library.pluginProposeSave`); the plugin learns only the count.
struct PluginSaveConnectionsSheet: View {
    let request: PluginViewModel.LibraryRequest
    /// saved count (nil: cancelled), credential linked.
    let answer: (Int?, Bool) -> Void
    @Environment(LibraryModel.self) private var model
    @Environment(CredentialsModel.self) private var credentials

    struct RowState: Identifiable {
        let id: Int
        var include = true
        var name: String
        var proto: String
        var host: String
        let reported: Bool
        let osHint: String?
    }

    @State private var rows: [RowState]
    /// "" is the library's top level.
    @State private var folderId = ""
    @State private var newFolder = false
    @State private var newFolderName = ""
    @State private var credentialId: String?
    @State private var failure: String?

    /// The UI driver's last open sheet, so a script can answer it.
    @MainActor static var current: ((String, String?) -> Void)?

    init(request: PluginViewModel.LibraryRequest, answer: @escaping (Int?, Bool) -> Void) {
        self.request = request
        self.answer = answer
        _rows = State(initialValue: request.items.enumerated().map { i, p in
            RowState(id: i, name: p.label, proto: p.proto, host: p.host ?? "", reported: p.reported && p.host != nil, osHint: p.osHint)
        })
    }

    private var folders: [(FolderView, Int)] {
        func walk(_ f: FolderView, _ depth: Int) -> [(FolderView, Int)] {
            [(f, depth)] + f.folders.flatMap { walk($0, depth + 1) }
        }
        return model.tree.map { $0.folders.flatMap { walk($0, 0) } } ?? []
    }

    private func rowsJson(_ list: [RowState]) -> String {
        let a = list.map { ["name": $0.name, "host": $0.host, "protocol": $0.proto] }
        return (try? JSONSerialization.data(withJSONObject: a)).flatMap { String(data: $0, encoding: .utf8) } ?? "[]"
    }

    /// Duplicate flags for every row, from the core (same host and protocol in the folder).
    private var duplicates: [Bool] {
        if newFolder { return model.library.flatMap { try? $0.pluginProposeDuplicates(folderId: UUID().uuidString, rowsJson: rowsJson(rows)) } ?? [] }
        return model.library.flatMap { try? $0.pluginProposeDuplicates(folderId: folderId, rowsJson: rowsJson(rows)) } ?? []
    }

    private var chosen: [RowState] {
        let d = duplicates
        // A row without an address is left out (its mark says so); it never blocks the others.
        return rows.filter { r in r.include && !r.host.trimmingCharacters(in: .whitespaces).isEmpty && !(r.id < d.count && d[r.id]) }
    }

    var body: some View {
        let dup = duplicates
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text(request.items.count == 1 ? "Save as Connection" : "Save \(request.items.count) Connections").font(DS.Font.headline)
            Grid(alignment: .leading, horizontalSpacing: DS.Space.s, verticalSpacing: DS.Space.xs) {
                GridRow {
                    Text("Plugin").foregroundStyle(.secondary)
                    Text("\(request.plugin) · \(request.entryName)").lineLimit(1).truncationMode(.middle)
                }
                GridRow {
                    Text("Folder").foregroundStyle(.secondary)
                    HStack(spacing: DS.Space.xs) {
                        Picker("Folder", selection: $folderId) {
                            Text("Top level").tag("")
                            ForEach(folders, id: \.0.id) { f, depth in
                                Text(String(repeating: "  ", count: depth) + f.name).tag(f.id)
                            }
                        }
                        .labelsHidden().frame(maxWidth: 260)
                        .accessibilityIdentifier("plugin-save-folder")
                        Toggle("New folder", isOn: $newFolder).accessibilityIdentifier("plugin-save-new-folder")
                        if newFolder {
                            TextField("Name", text: $newFolderName).frame(maxWidth: 160)
                                .accessibilityIdentifier("plugin-save-new-folder-name")
                        }
                    }
                }
                GridRow {
                    Text("Credential").foregroundStyle(.secondary)
                    if credentials.vault != nil {
                        Picker("Credential", selection: $credentialId) {
                            CredentialPickerRows(groups: CredentialPickerGroup.build(credentials.tree), inherit: "None (ask when connecting)")
                        }
                        .labelsHidden().frame(maxWidth: 260)
                        .accessibilityIdentifier("plugin-save-credential")
                    } else {
                        Text("Ask when connecting").foregroundStyle(.secondary)
                    }
                }
            }
            Divider()
            ScrollView {
                Grid(alignment: .leading, horizontalSpacing: DS.Space.s, verticalSpacing: DS.Space.xs) {
                    GridRow {
                        Text("")
                        Text("Name").foregroundStyle(.secondary)
                        Text("Protocol").foregroundStyle(.secondary)
                        Text("Host").foregroundStyle(.secondary)
                    }
                    ForEach($rows) { $r in
                        let isDup = r.id < dup.count && dup[r.id]
                        GridRow {
                            Toggle("Include \(r.name)", isOn: $r.include).labelsHidden().disabled(isDup)
                                .accessibilityIdentifier("plugin-save-include-\(r.id)")
                            TextField("Name", text: $r.name).frame(minWidth: 140)
                                .accessibilityIdentifier("plugin-save-name-\(r.id)")
                            Picker("Protocol", selection: $r.proto) {
                                Text("SSH").tag("ssh")
                                Text("RDP").tag("rdp")
                                Text("VNC").tag("vnc")
                            }
                            .labelsHidden().fixedSize()
                            .accessibilityIdentifier("plugin-save-protocol-\(r.id)")
                            HStack(spacing: DS.Space.xxs) {
                                TextField("Host or IP", text: $r.host).font(.system(.body, design: .monospaced)).frame(minWidth: 150)
                                    .accessibilityIdentifier("plugin-save-host-\(r.id)")
                                if isDup {
                                    Text("Already in folder").font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1).fixedSize()
                                        .accessibilityIdentifier("plugin-save-duplicate-\(r.id)")
                                } else if r.reported {
                                    Image(systemName: "checkmark.seal").foregroundStyle(.secondary).help("\(request.entryName) reported this address")
                                } else if r.host.isEmpty {
                                    Image(systemName: "exclamationmark.triangle").foregroundStyle(.orange).help("No address known: type one")
                                }
                            }
                        }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(minHeight: 60, maxHeight: 320)
            if let failure {
                Text(failure).foregroundStyle(.red).font(DS.Font.caption).lineLimit(3).fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("plugin-save-error")
            }
            HStack {
                Text("Nothing secret is copied from the plugin.").foregroundStyle(.secondary).font(DS.Font.caption).lineLimit(1)
                Spacer()
                Button("Cancel", role: .cancel) { answer(nil, false) }.keyboardShortcut(.cancelAction)
                Button(chosen.count == 1 ? "Save 1 Connection" : "Save \(chosen.count) Connections") { save() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(chosen.isEmpty || (newFolder && newFolderName.trimmingCharacters(in: .whitespaces).isEmpty))
                    .accessibilityIdentifier("plugin-save-save")
            }
        }
        .padding(DS.Space.m)
        .frame(minWidth: 620, idealWidth: 680)
        .accessibilityIdentifier("plugin-save-sheet")
        .onAppear { Self.current = { folderName, credential in scripted(folderName, credential) } }
        .onDisappear { Self.current = nil }
    }

    private func save() {
        let list = chosen
        guard !list.isEmpty else { answer(0, credentialId != nil); return }
        var result: String?
        var thrown: String?
        let folder = folderId, name = newFolder ? newFolderName : "", cred = credentialId ?? ""
        model.mutate { lib in
            do { result = try lib.pluginProposeSave(folderId: folder, newFolder: name, rowsJson: rowsJson(list), credentialId: cred) } catch { thrown = error.userMessage }
        }
        if let thrown { failure = thrown; return }
        let ids = (result?.data(using: .utf8)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }?["ids"] as? [Any]
        answer(ids?.count ?? 0, credentialId != nil)
    }

    /// UI driver: pick a folder by name ("" or "-": top level), optionally a credential by name, and save.
    private func scripted(_ folderName: String, _ credentialName: String?) {
        if folderName.isEmpty || folderName == "-" {
            folderId = ""
        } else if let f = folders.first(where: { $0.0.name == folderName }) {
            folderId = f.0.id
        } else {
            newFolder = true
            newFolderName = folderName
        }
        if let credentialName { credentialId = credentials.tree.first { $0.name == credentialName }?.id }
        DispatchQueue.main.async { save() }
    }
}
