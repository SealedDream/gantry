import AppKit
import SwiftUI
import UniformTypeIdentifiers
import BastionCore

/// Library import and export, all parsed and written by the core (`Library.importFile`,
/// `exportPreview`, `exportTo`): CSV, `.rdp`, PuTTY `.reg`, Royal JSON, RDCMan `.rdg`,
/// mRemoteNG `.xml` and Bastion exports come in as a new top-level folder; the export is the secret-free
/// `bastion-export` v1 file, previewed and confirmed first. Files are chosen in native panels.
@MainActor
enum LibraryIO {
    /// UI test runs (`panel-path`): the next panel returns this file without showing.
    static var scriptedPanelURL: URL?

    static let importExtensions = ["csv", "rdp", "reg", "json", "rdg", "xml"]

    static func chooseImportFile() -> URL? {
        if let url = scriptedPanelURL { scriptedPanelURL = nil; return url }
        let panel = NSOpenPanel()
        panel.title = "Import Connections"
        panel.message = "CSV, .rdp, PuTTY .reg, Royal JSON, RDCMan .rdg, mRemoteNG .xml or a Gantry export. Passwords are not imported."
        panel.allowedContentTypes = importExtensions.compactMap { UTType(filenameExtension: $0) }
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseKeePassFile() -> URL? {
        if let url = scriptedPanelURL { scriptedPanelURL = nil; return url }
        let panel = NSOpenPanel()
        panel.title = "Import KeePass File"
        panel.message = "Passwords go into the encrypted vault. The file is not changed."
        panel.allowedContentTypes = [UTType(filenameExtension: "kdbx")].compactMap { $0 }
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseKeePassKeyFile() -> URL? {
        if let url = scriptedPanelURL { scriptedPanelURL = nil; return url }
        let panel = NSOpenPanel()
        panel.title = "KeePass Key File"
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseExportFile() -> URL? {
        if let url = scriptedPanelURL { scriptedPanelURL = nil; return url }
        let panel = NSSavePanel()
        panel.title = "Export Library"
        panel.nameFieldStringValue = "Gantry Export.json"
        panel.allowedContentTypes = [.json]
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseSshConfigFile() -> URL? {
        if let url = scriptedPanelURL { scriptedPanelURL = nil; return url }
        let panel = NSSavePanel()
        panel.title = "Export to ssh_config"
        panel.message = "SSH connections only. No passwords or keys are written."
        panel.nameFieldStringValue = "bastion_ssh_config"
        panel.allowsOtherFileTypes = true
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Write `ids` (everything when nil) as an OpenSSH ssh_config file and describe the result.
    static func exportSshConfig(model: LibraryModel, ids: [String]?, folderId: String) -> ImportReport? {
        guard let library = model.library, let url = chooseSshConfigFile() else { return nil }
        do {
            let r = try library.exportSshConfig(path: url.path, ids: ids)
            let skipped = r.skipped.isEmpty ? "" : "\n\nLeft out:\n" + r.skipped.prefix(10).joined(separator: "\n")
                + (r.skipped.count > 10 ? "\n…and \(r.skipped.count - 10) more" : "")
            return ImportReport(folderId: folderId, title: "Exported \(r.exported) host\(r.exported == 1 ? "" : "s")",
                                message: "To \(url.lastPathComponent). Include it from ~/.ssh/config with “Include \(url.path)”.\(skipped)")
        } catch {
            model.error = "Export to ssh_config failed: \(error)"
            return nil
        }
    }

    static func chooseAnsibleInventoryFile() -> URL? {
        if let url = scriptedPanelURL { scriptedPanelURL = nil; return url }
        let panel = NSSavePanel()
        panel.title = "Export Ansible Inventory"
        panel.message = "SSH connections only, as INI. Name the file .yml or .yaml for YAML. No passwords or keys are written."
        panel.nameFieldStringValue = "inventory.ini"
        panel.allowsOtherFileTypes = true
        return panel.runModal() == .OK ? panel.url : nil
    }

    /// Write `ids` (everything when nil) as an Ansible inventory (core `ansible_inventory`, shared
    /// with the Tauri app). YAML when the file is named .yml/.yaml, INI otherwise.
    static func exportAnsibleInventory(model: LibraryModel, ids: [String]?, folderId: String) -> ImportReport? {
        guard let library = model.library, let url = chooseAnsibleInventoryFile() else { return nil }
        let yaml = ["yml", "yaml"].contains(url.pathExtension.lowercased())
        do {
            let r = try library.exportAnsibleInventory(path: url.path, ids: ids, yaml: yaml)
            let skipped = r.skipped.isEmpty ? "" : "\n\nLeft out:\n" + r.skipped.prefix(10).joined(separator: "\n")
                + (r.skipped.count > 10 ? "\n…and \(r.skipped.count - 10) more" : "")
            return ImportReport(folderId: folderId, title: "Exported \(r.exported) host\(r.exported == 1 ? "" : "s") to Ansible",
                                message: "To \(url.lastPathComponent) (\(yaml ? "YAML" : "INI")). Use it with “ansible -i \(url.path) all -m ping”.\(skipped)")
        } catch {
            model.error = "Export Ansible inventory failed: \(error)"
            return nil
        }
    }

    /// Import a chosen file, save the library and describe the result (errors go to `model.error`).
    static func importConnections(model: LibraryModel) -> ImportReport? {
        guard let url = chooseImportFile() else { return nil }
        var report: ImportReport?
        model.mutate { lib in
            let r = try lib.importFile(path: url.path)
            let skipped = r.skipped.isEmpty ? "" : "\n\nNot imported:\n" + r.skipped.prefix(10).joined(separator: "\n")
                + (r.skipped.count > 10 ? "\n…and \(r.skipped.count - 10) more" : "")
            report = ImportReport(folderId: r.folder, title: "Imported \(r.connections) connection\(r.connections == 1 ? "" : "s")",
                                  message: "From \(url.lastPathComponent) (\(r.format)) into “Imported \(url.deletingPathExtension().lastPathComponent)”.\(skipped)")
        }
        return report
    }
}

struct ImportReport: Identifiable {
    let id = UUID()
    let folderId: String
    let title: String
    let message: String
}

/// The import result: how many connections came in, from what, and what was left out.
struct ImportReportSheet: View {
    let report: ImportReport
    private var dismiss = PanelDismiss()

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text(report.title).font(DS.Font.bodyStrong)
            Text(report.message).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
            HStack {
                Spacer()
                Button("OK") { dismiss() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
            }
        }
        .padding(DS.Space.m)
        .panelFrame(width: DS.Size.dialogWidth + 80)
    }
}

/// What an export will contain, from the core's preview, before anything is written. Exporting
/// configuration needs confirmation (`policy::Action::ExportConfiguration`); this sheet is it.
struct ExportSheet: View {
    let request: Request
    @Environment(LibraryModel.self) private var model
    private var dismiss = PanelDismiss()
    @State private var preview: ExportPreviewView?
    @State private var error: String?

    struct Request: Identifiable {
        let id = UUID()
        /// Nodes to export; `nil` is the whole library.
        let ids: [String]?
        let scope: String
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Export \(request.scope)").font(DS.Font.bodyStrong)
            if let p = preview {
                Grid(alignment: .leading, horizontalSpacing: DS.Space.m, verticalSpacing: DS.Space.xs) {
                    GridRow { Text("Connections").foregroundStyle(.secondary); Text("\(p.connections)").monospacedDigit() }
                    GridRow { Text("Folders").foregroundStyle(.secondary); Text("\(p.folders)").monospacedDigit() }
                    GridRow { Text("Credential references").foregroundStyle(.secondary); Text("\(p.credentialRefs)").monospacedDigit() }
                }
                Text(p.strippedFields.isEmpty
                     ? "No passwords or keys are written. Credential references stay as ids; the vault is not exported."
                     : "Removed before writing: \(p.strippedFields.joined(separator: ", ")). No passwords or keys are written.")
                    .font(DS.Font.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if let error { Text(error).font(DS.Font.caption).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Export…", action: export).keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(preview == nil)
            }
        }
        .padding(DS.Space.m)
        .panelFrame(width: DS.Size.dialogWidth + 80)
        .onAppear(perform: load)
    }

    private func load() {
        do { preview = try model.library?.exportPreview(ids: request.ids) } catch { self.error = "\(error)" }
    }

    private func export() {
        guard let url = LibraryIO.chooseExportFile(), let library = model.library else { return }
        do {
            try library.exportTo(path: url.path, ids: request.ids)
            dismiss()
        } catch {
            self.error = "Export failed: \(error)"
        }
    }
}
