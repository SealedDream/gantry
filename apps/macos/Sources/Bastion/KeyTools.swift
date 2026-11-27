import SwiftUI
import AppKit
import BastionCore

/// Key manager (core `keymanager`): generate ed25519, inspect and convert OpenSSH / PEM / PuTTY
/// keys. Same rules as Native Windows: files are written 0600 with a `.pub` beside, never over
/// an existing file; private key text is never shown or logged.
enum KeyToolMode: String, Identifiable { case generate, inspect, convert; var id: String { rawValue } }

/// UI tests only: open the sheet with these fields and press its action once.
struct KeyToolRequest {
    let id = UUID()
    let mode: KeyToolMode
    let source: String
    let target: String
    let comment: String
}

/// What `keys_*` return. `private_openssh` is decoded only for writing it out.
struct KeyInfo: Decodable {
    let algorithm: String
    let fingerprint: String
    let comment: String
    let public_openssh: String
    let format: String
    let hardware: Bool
    let private_openssh: String?

    static func decode(_ json: String) throws -> KeyInfo { try JSONDecoder().decode(KeyInfo.self, from: Data(json.utf8)) }
}

enum KeyFiles {
    static var sshDir: String { (NSHomeDirectory() as NSString).appendingPathComponent(".ssh") }

    /// Writes the private key 0600 and `<path>.pub`; refuses to replace either.
    static func write(_ key: KeyInfo, to path: String) throws {
        guard let priv = key.private_openssh else { throw KeyToolError("The key manager returned no private key.") }
        let fm = FileManager.default
        if fm.fileExists(atPath: path) || fm.fileExists(atPath: path + ".pub") { throw KeyToolError("That file exists. Gantry never overwrites a key.") }
        try fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        guard fm.createFile(atPath: path, contents: Data(priv.utf8), attributes: [.posixPermissions: 0o600]) else { throw KeyToolError("Could not write \(path).") }
        guard fm.createFile(atPath: path + ".pub", contents: Data((key.public_openssh + "\n").utf8), attributes: [.posixPermissions: 0o644]) else {
            throw KeyToolError("Could not write \(path).pub.")
        }
    }
}

struct KeyToolError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

struct KeyToolSheet: View {
    let mode: KeyToolMode
    var request: KeyToolRequest?
    @Environment(\.dismiss) private var dismiss
    @State private var source = ""
    @State private var target = ""
    @State private var comment = ""
    @State private var passphrase = ""
    @State private var newPassphrase = ""
    @State private var result: KeyInfo?
    @State private var problem: String?

    private var title: String {
        switch mode { case .generate: "Generate SSH Key"; case .inspect: "Inspect SSH Key"; case .convert: "Convert SSH Key" }
    }
    private var action: String {
        switch mode { case .generate: "Generate"; case .inspect: "Inspect"; case .convert: "Convert" }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text(title).font(DS.Font.bodyStrong)
            Form {
                if mode != .generate {
                    LabeledContent("Key file") {
                        HStack {
                            TextField("Key file", text: $source).labelsHidden().accessibilityLabel("Key file")
                            Button("Choose…", action: chooseSource)
                        }
                    }
                    SecureField("Passphrase", text: $passphrase).help("Only for an encrypted key")
                }
                if mode != .inspect {
                    TextField("Save as", text: $target)
                    TextField("Comment", text: $comment).help(mode == .convert ? "Empty keeps the key's own" : "")
                    SecureField(mode == .convert ? "New passphrase" : "Passphrase", text: $newPassphrase).help("Empty = unencrypted")
                }
            }
            .formStyle(.columns)
            if let r = result {
                VStack(alignment: .leading, spacing: DS.Space.xs) {
                    Text("\(r.algorithm) \(r.fingerprint)").font(DS.Font.caption.monospaced()).textSelection(.enabled)
                    Text("\(r.format)\(r.hardware ? " · hardware" : "")\(r.comment.isEmpty ? "" : " · \(r.comment)")")
                        .font(DS.Font.caption).foregroundStyle(.secondary)
                    HStack {
                        Text(r.public_openssh).font(DS.Font.caption.monospaced()).lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        Button("Copy") {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(r.public_openssh, forType: .string)
                        }.help("Copy public key")
                    }
                }
            }
            if let problem { Text(problem).font(DS.Font.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Spacer()
                Button(result == nil || mode == .inspect ? "Cancel" : "Done", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction).dsSecondaryButton()
                if result == nil || mode == .inspect {
                    Button(action) { perform() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
                }
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth + 160)
        .onAppear {
            target = (KeyFiles.sshDir as NSString).appendingPathComponent(mode == .convert ? "id_converted" : "id_ed25519_bastion")
            if mode == .generate { comment = "\(NSUserName())@\(ProcessInfo.processInfo.hostName)" }
            if let r = request {
                source = r.source; comment = r.comment
                if !r.target.isEmpty { target = r.target }
                AgentKeysModel.shared.driverKeyToolResult = perform()
            }
        }
    }

    private func chooseSource() {
        let panel = NSOpenPanel()
        panel.directoryURL = URL(fileURLWithPath: KeyFiles.sshDir)
        panel.showsHiddenFiles = true
        if panel.runModal() == .OK, let url = panel.url { source = url.path }
    }

    private func opt(_ s: String) -> String? { s.isEmpty ? nil : s }

    /// Runs the action; returns a log line for UI tests (never key material).
    @discardableResult
    private func perform() -> String {
        problem = nil
        defer { passphrase = ""; newPassphrase = "" }
        do {
            let key = try runAction()
            result = key
            return "ok \(key.algorithm) \(key.fingerprint) \(key.format) comment=\(key.comment)"
        } catch {
            problem = errorText(error)
            return "problem \(errorText(error))"
        }
    }

    private func runAction() throws -> KeyInfo {
            switch mode {
            case .generate:
                let path = (target.trimmingCharacters(in: .whitespaces) as NSString).expandingTildeInPath
                guard !path.isEmpty else { throw KeyToolError("Enter a file name.") }
                let key = try KeyInfo.decode(keysGenerate(comment: comment.trimmingCharacters(in: .whitespaces), passphrase: opt(newPassphrase)))
                try KeyFiles.write(key, to: path)
                return key
            case .inspect:
                return try KeyInfo.decode(keysInspect(keyText: try readSource(), passphrase: opt(passphrase)))
            case .convert:
                let path = (target.trimmingCharacters(in: .whitespaces) as NSString).expandingTildeInPath
                guard !path.isEmpty else { throw KeyToolError("Enter a file name.") }
                let key = try KeyInfo.decode(keysConvert(keyText: try readSource(), passphrase: opt(passphrase), newPassphrase: opt(newPassphrase),
                                                         comment: comment.trimmingCharacters(in: .whitespaces)))
                try KeyFiles.write(key, to: path)
                return key
            }
    }

    private func readSource() throws -> String {
        let path = (source.trimmingCharacters(in: .whitespaces) as NSString).expandingTildeInPath
        guard !path.isEmpty, FileManager.default.fileExists(atPath: path) else { throw KeyToolError("Choose an existing private key file.") }
        return try String(contentsOfFile: path, encoding: .utf8)
    }
}
