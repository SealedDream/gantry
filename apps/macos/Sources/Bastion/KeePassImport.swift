import SwiftUI
import BastionCore

/// B8: import a KeePass `.kdbx` into the encrypted credential vault. The core decrypts the file in
/// memory (`keepassImportPreview`, `keepassImport`); the preview lists titles, usernames and target
/// folders only. The master password lives in this sheet's state until it closes; no secret is
/// logged or written outside the vault.
struct KeePassImportSheet: View {
    struct Request: Identifiable {
        let id = UUID()
        let url: URL
    }

    enum Rule: String, CaseIterable, Identifiable {
        case skip, replace, keepBoth = "keep-both"
        var id: String { rawValue }
        var title: String {
            switch self {
            case .skip: "Skip"
            case .replace: "Replace"
            case .keepBoth: "Keep both"
            }
        }
    }

    let request: Request
    @Environment(CredentialsModel.self) private var credentials
    @Environment(SessionsModel.self) private var sessions
    private var dismiss = PanelDismiss()
    @State private var password = ""
    @State private var keyFile: URL?
    @State private var rows: [KeePassImportRow]?
    @State private var rule = Rule.skip
    @State private var busy = false
    @State private var error: String?
    @State private var result: String?

    private var hasKey: Bool { !password.isEmpty || keyFile != nil }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Import \(request.url.lastPathComponent)").font(DS.Font.bodyStrong).lineLimit(1).truncationMode(.middle)
            if let result {
                Text(result).fixedSize(horizontal: false, vertical: true)
            } else if let rows {
                previewList(rows)
            } else {
                keyForm
            }
            if let error { Text(error).font(DS.Font.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            buttons
        }
        .padding(DS.Space.m)
        .panelFrame(width: DS.Size.dialogWidth + 160)
        .onDisappear { password = "" }
    }

    private var keyForm: some View {
        Form {
            SecureField("Master password", text: $password)
                .accessibilityIdentifier("keepass-import-password")
            LabeledContent("Key file") {
                HStack {
                    Text(keyFile?.lastPathComponent ?? "None").foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    Button("Choose…") { keyFile = LibraryIO.chooseKeePassKeyFile() ?? keyFile }
                }
            }
        }
    }

    private func previewList(_ rows: [KeePassImportRow]) -> some View {
        let new = rows.filter { $0.status == "new" }.count
        let dup = rows.filter { $0.status == "duplicate" }.count
        let none = rows.filter { $0.status == "no-password" }.count
        return VStack(alignment: .leading, spacing: DS.Space.xs) {
            Text("\(new) new, \(dup) already in the vault, \(none) without a password")
                .font(DS.Font.caption).foregroundStyle(.secondary)
            List(Array(rows.enumerated()), id: \.offset) { _, r in
                HStack {
                    VStack(alignment: .leading) {
                        Text(r.title).lineLimit(1)
                        Text([r.username, r.folder].filter { !$0.isEmpty }.joined(separator: " · "))
                            .font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }
                    Spacer()
                    Text(statusLabel(r.status)).font(DS.Font.caption).foregroundStyle(.secondary)
                }
            }
            .frame(minHeight: 160, idealHeight: 240)
            Picker("Already in the vault", selection: $rule) {
                ForEach(Rule.allCases) { Text($0.title).tag($0) }
            }
            .help("Skip keeps the saved credential. Replace overwrites its username and password. Keep both adds a second one.")
            .disabled(dup == 0)
        }
    }

    private func statusLabel(_ status: String) -> String {
        switch status {
        case "new": "New"
        case "duplicate": "Duplicate"
        default: "No password"
        }
    }

    private var buttons: some View {
        HStack {
            if busy { ProgressView().controlSize(.small) }
            Spacer()
            if result != nil {
                Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
            } else {
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction)
                if rows == nil {
                    Button("Preview", action: preview).keyboardShortcut(.defaultAction).disabled(!hasKey || busy)
                } else {
                    Button("Import", action: runImport).keyboardShortcut(.defaultAction)
                        .disabled(busy || rows?.contains { $0.status != "no-password" } != true)
                }
            }
        }
    }

    private func vault() async -> CredentialVault? {
        if let v = credentials.vaultForSave() { return v }
        await credentials.openInBackground(sessions: sessions)
        return credentials.vault
    }

    private func preview() {
        let (path, pw, key) = (request.url.path, password, keyFile?.path)
        run { v in
            let r = try await Task.detached { try v.keepassImportPreview(path: path, password: pw, keyfilePath: key) }.value
            rows = r
        }
    }

    private func runImport() {
        let (path, pw, key, dup) = (request.url.path, password, keyFile?.path, rule.rawValue)
        run { v in
            let r = try await Task.detached { try v.keepassImport(path: path, password: pw, keyfilePath: key, duplicates: dup) }.value
            credentials.reload()
            password = ""
            var parts = ["Added \(r.added)"]
            if r.replaced > 0 { parts.append("replaced \(r.replaced)") }
            if r.skippedDuplicates > 0 { parts.append("skipped \(r.skippedDuplicates) already saved") }
            if r.skippedNoPassword > 0 { parts.append("left out \(r.skippedNoPassword) without a password") }
            result = parts.joined(separator: ", ") + ". They are in Credentials › “KeePass \(request.url.deletingPathExtension().lastPathComponent)”."
        }
    }

    private func run(_ work: @escaping (CredentialVault) async throws -> Void) {
        busy = true
        error = nil
        Task {
            defer { busy = false }
            guard let v = await vault() else {
                error = "The credential vault is locked."
                return
            }
            do { try await work(v) } catch { self.error = "\(error)" }
        }
    }
}
