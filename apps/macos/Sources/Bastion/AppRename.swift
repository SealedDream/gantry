import CryptoKit
import Foundation

/// The product rename (Bastion -> Gantry, owner 2026-11-23). On the first launch of Gantry the
/// old `~/Library/Application Support/Bastion` folder (library, vault, settings, known_hosts,
/// device key, plugins) is copied to `.../Gantry` once. The copy goes to a temporary folder, is
/// verified file by file (size and SHA-256), and only then takes the new name. The old folder is
/// never changed or removed, so nothing is lost if anything fails; the next launch tries again.
enum AppRename {
    static let newName = "Gantry"
    static let oldName = "Bastion"
    static let marker = "migrated-from-bastion.json"

    enum Outcome: Equatable { case notNeeded, migrated(files: Int), failed(String), hasOwnLibrary }

    /// A Gantry library of its own: document keys, an old-layout library.json, or Documents/Gantry/Personal.gantry.
    static func hasOwnLibrary(gantryData: URL, documents: URL, ext: String = "gantry") -> Bool {
        let fm = FileManager.default
        guard !fm.fileExists(atPath: gantryData.appendingPathComponent(marker).path) else { return false }
        return fm.fileExists(atPath: gantryData.appendingPathComponent("document-keys").path)
            || fm.fileExists(atPath: gantryData.appendingPathComponent("library.json").path)
            || fm.fileExists(atPath: documents.appendingPathComponent(newName).appendingPathComponent("Personal.\(ext)").path)
    }

    /// Run once per process before the data folder is first used. Migrates when no marker says it was done,
    /// also over a Gantry folder that has no library of its own (a failed first start, a test seed): that folder
    /// is renamed aside to `Gantry.before-migration-*`, never deleted, and only after the copy verified.
    static func migrateDataFolder(in parent: URL, documents: URL) -> Outcome {
        let fm = FileManager.default
        let old = parent.appendingPathComponent(oldName, isDirectory: true)
        let new = parent.appendingPathComponent(newName, isDirectory: true)
        guard !fm.fileExists(atPath: new.appendingPathComponent(marker).path), isDirectory(old) else { return .notNeeded }
        if hasOwnLibrary(gantryData: new, documents: documents) {
            NSLog("Gantry: a Gantry library exists; Bastion data left as it is")
            return .hasOwnLibrary
        }
        let staging = parent.appendingPathComponent("\(newName).migrating-\(UUID().uuidString)", isDirectory: true)
        do {
            let files = try copyTree(from: old, to: staging)
            try verify(source: old, copy: staging, files: files)
            if fm.fileExists(atPath: new.path) {
                // A settings-only Gantry folder keeps its own files over the copy (newer settings win; the
                // library and its keys come from Bastion, since this folder has none of its own).
                let own = try copyTree(from: new, to: staging, overwrite: true)
                try verify(source: new, copy: staging, files: own)
            }
            let aside = fm.fileExists(atPath: new.path) ? parent.appendingPathComponent("\(newName).before-migration-\(UUID().uuidString)", isDirectory: true) : nil
            var note: [String: Any] = ["from": old.path, "files": files.count, "at": ISO8601DateFormatter().string(from: Date())]
            if let aside { note["earlierGantryFolder"] = aside.path }
            try JSONSerialization.data(withJSONObject: note, options: [.sortedKeys]).write(to: staging.appendingPathComponent(marker))
            if let aside { try fm.moveItem(at: new, to: aside) }
            do { try fm.moveItem(at: staging, to: new) } catch {
                if let aside { try? fm.moveItem(at: aside, to: new) }
                throw error
            }
            NSLog("Gantry: copied %d files from %@ to %@; the old folder is kept%@", files.count, old.path, new.path, aside.map { "; the earlier Gantry folder is kept as \($0.path)" } ?? "")
            return .migrated(files: files.count)
        } catch {
            try? fm.removeItem(at: staging)
            NSLog("Gantry: data folder not migrated, %@ is unchanged: %@", old.path, "\(error)")
            return .failed("\(error)")
        }
    }

    /// The Personal document: `~/Documents/Gantry/Personal.gantry`, or the existing pre-rename
    /// `~/Documents/Bastion/Personal.bastion` where it is (documents are the user's files and are not moved).
    /// A pre-rename Personal.bastion is used where it is only when `dataDir` was migrated from the Bastion folder
    /// (marker present): its device key came with that copy. Otherwise its key is not here, so the new path is used.
    static func personalDocument(documents: URL, dataDir: URL, ext: String, legacyExt: String) -> URL {
        let current = documents.appendingPathComponent(newName, isDirectory: true).appendingPathComponent("Personal.\(ext)")
        let legacy = documents.appendingPathComponent(oldName, isDirectory: true).appendingPathComponent("Personal.\(legacyExt)")
        let fm = FileManager.default
        let migrated = fm.fileExists(atPath: dataDir.appendingPathComponent(marker).path)
        return migrated && !fm.fileExists(atPath: current.path) && fm.fileExists(atPath: legacy.path) ? legacy : current
    }

    private static func isDirectory(_ url: URL) -> Bool {
        var dir: ObjCBool = false
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &dir) && dir.boolValue
    }

    /// Copies directories, regular files and symlinks; skips sockets and other special files
    /// (the IPC socket is recreated at launch). Returns the regular files' relative paths.
    private static func copyTree(from src: URL, to dst: URL, overwrite: Bool = false) throws -> [String] {
        let fm = FileManager.default
        if !(overwrite && isDirectory(dst)) {
            try fm.createDirectory(at: dst, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        var files: [String] = []
        for name in try fm.contentsOfDirectory(atPath: src.path) {
            let from = src.appendingPathComponent(name), to = dst.appendingPathComponent(name)
            let attrs = try fm.attributesOfItem(atPath: from.path)
            switch attrs[.type] as? FileAttributeType {
            case .typeDirectory?:
                files += try copyTree(from: from, to: to, overwrite: overwrite).map { "\(name)/\($0)" }
            case .typeRegular?, .typeSymbolicLink?:
                if overwrite, (try? fm.attributesOfItem(atPath: to.path)) != nil { try fm.removeItem(at: to) }
                try fm.copyItem(at: from, to: to)  // keeps permissions (0600 key files stay 0600)
                if attrs[.type] as? FileAttributeType == .typeRegular { files.append(name) }
            default:
                continue
            }
        }
        return files
    }

    private static func verify(source: URL, copy: URL, files: [String]) throws {
        for rel in files {
            let a = try Data(contentsOf: source.appendingPathComponent(rel), options: .mappedIfSafe)
            let b = try Data(contentsOf: copy.appendingPathComponent(rel), options: .mappedIfSafe)
            guard a.count == b.count, SHA256.hash(data: a) == SHA256.hash(data: b) else {
                throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: rel])
            }
        }
    }
}
