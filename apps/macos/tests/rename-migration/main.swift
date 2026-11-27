// Native Mac: Bastion -> Gantry data folder migration (AppRename.swift). Exit 0 = all passed.
import CryptoKit
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) { print((ok ? "PASS " : "FAIL ") + what); if !ok { failures += 1 } }
let fm = FileManager.default
func fresh() -> URL {
    let d = fm.temporaryDirectory.appendingPathComponent("gantry-rename-\(UUID().uuidString)")
    try! fm.createDirectory(at: d, withIntermediateDirectories: true)
    return d
}
func write(_ url: URL, _ data: Data, mode: Int = 0o644) {
    try! fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try! data.write(to: url)
    try! fm.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
}
func snapshot(_ root: URL) -> [String: String] {
    var out: [String: String] = [:]
    let root = root.resolvingSymlinksInPath()
    for case let u as URL in fm.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey])! where (try? u.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true {
        if u.lastPathComponent == AppRename.marker { continue }
        let rel = String(u.resolvingSymlinksInPath().path.dropFirst(root.path.count))
        out[rel] = SHA256.hash(data: try! Data(contentsOf: u)).description
    }
    return out
}

// 1. A real old-name data set: library, vault, settings, known_hosts, device key (0600), plugins.
let noDocs = fresh()
let parent = fresh()
let old = parent.appendingPathComponent("Bastion")
write(old.appendingPathComponent("library.json"), Data("{\"folders\":[]}".utf8))
write(old.appendingPathComponent("credentials.vault"), Data((0..<70000).map { UInt8(truncatingIfNeeded: $0 * 7) }))
write(old.appendingPathComponent("settings.json"), Data("{}".utf8))
write(old.appendingPathComponent("known_hosts"), Data("web.example ssh-ed25519 AAAA\n".utf8))
write(old.appendingPathComponent("device-key"), Data("00ff".utf8), mode: 0o600)
write(old.appendingPathComponent("plugins/dev.bastion.postgres/installed.json"), Data("{}".utf8))
let before = snapshot(old)
check(AppRename.migrateDataFolder(in: parent, documents: noDocs) == .migrated(files: 6), "first launch migrates all 6 files")
let gantry = parent.appendingPathComponent("Gantry")
check(snapshot(gantry) == before, "every file arrives byte for byte")
let mode = (try? fm.attributesOfItem(atPath: gantry.appendingPathComponent("device-key").path)[.posixPermissions] as? Int) ?? 0
check(mode == 0o600, "device key stays 0600")
check(fm.fileExists(atPath: gantry.appendingPathComponent(AppRename.marker).path), "marker written")
check(snapshot(old) == before, "old folder kept unchanged")
check(((try? fm.contentsOfDirectory(atPath: parent.path)) ?? []).filter { $0.contains("migrating") }.isEmpty, "no staging folder left")

// 2. Second launch does nothing and keeps new edits.
write(gantry.appendingPathComponent("library.json"), Data("{\"changed\":true}".utf8))
check(AppRename.migrateDataFolder(in: parent, documents: noDocs) == .notNeeded, "second launch does nothing")
check((try? String(contentsOf: gantry.appendingPathComponent("library.json"), encoding: .utf8))?.contains("changed") == true, "new data untouched")

// 3. Fresh install.
let empty = fresh()
check(AppRename.migrateDataFolder(in: empty, documents: noDocs) == .notNeeded && !fm.fileExists(atPath: empty.appendingPathComponent("Gantry").path), "fresh install untouched")

// 4. A failed copy (unreadable file) leaves no Gantry folder and the old data; the next launch succeeds.
let failing = fresh()
let oldF = failing.appendingPathComponent("Bastion")
write(oldF.appendingPathComponent("library.json"), Data("x".utf8))
write(oldF.appendingPathComponent("locked.bin"), Data("y".utf8), mode: 0)
if case .failed = AppRename.migrateDataFolder(in: failing, documents: noDocs) { check(true, "unreadable file fails the copy") } else { check(false, "unreadable file fails the copy") }
check(!fm.fileExists(atPath: failing.appendingPathComponent("Gantry").path), "failed copy leaves no Gantry folder")
check(((try? fm.contentsOfDirectory(atPath: failing.path)) ?? []).filter { $0.contains("migrating") }.isEmpty, "failed copy leaves no staging folder")
try! fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: oldF.appendingPathComponent("locked.bin").path)
check(AppRename.migrateDataFolder(in: failing, documents: noDocs) == .migrated(files: 2), "next launch retries and succeeds")

// 5. Personal document path.
let docs = fresh()
let data = docs.appendingPathComponent("data", isDirectory: true)
try! fm.createDirectory(at: data, withIntermediateDirectories: true)
check(AppRename.personalDocument(documents: docs, dataDir: data, ext: "gantry", legacyExt: "bastion").path.hasSuffix("Gantry/Personal.gantry"), "new install uses Gantry/Personal.gantry")
write(docs.appendingPathComponent("Bastion/Personal.bastion"), Data("doc".utf8))
check(AppRename.personalDocument(documents: docs, dataDir: data, ext: "gantry", legacyExt: "bastion").path.hasSuffix("Gantry/Personal.gantry"), "old Personal.bastion not used without the migration marker")
write(data.appendingPathComponent(AppRename.marker), Data("{}".utf8))
check(AppRename.personalDocument(documents: docs, dataDir: data, ext: "gantry", legacyExt: "bastion").path.hasSuffix("Bastion/Personal.bastion"), "existing Personal.bastion used in place after a migration")

for d in [parent, empty, failing, docs] { try? fm.removeItem(at: d) }

// 6. The three cases of an existing profile (coordinator 2026-11-23).
func profile(seed: Bool, ownLibrary: Bool) -> URL {
    let root = fresh()
    write(root.appendingPathComponent("support/Bastion/document-keys/doc.key"), Data("key".utf8))
    write(root.appendingPathComponent("docs/Bastion/Personal.bastion"), Data("doc".utf8))
    if seed { write(root.appendingPathComponent("support/Gantry/seed.txt"), Data("s".utf8)) }
    if ownLibrary {
        write(root.appendingPathComponent("support/Gantry/document-keys/own.key"), Data("own".utf8))
        write(root.appendingPathComponent("docs/Gantry/Personal.gantry"), Data("own".utf8))
    }
    return root
}
func at(_ r: URL, _ p: String) -> URL { r.appendingPathComponent(p) }
let pa = profile(seed: true, ownLibrary: false)
check(AppRename.migrateDataFolder(in: at(pa, "support"), documents: at(pa, "docs")) == .migrated(files: 1), "case a: Bastion data + empty Gantry folder migrates")
check((try? Data(contentsOf: at(pa, "support/Gantry/document-keys/doc.key"))) == Data("key".utf8) && fm.fileExists(atPath: at(pa, "support/Gantry/\(AppRename.marker)").path), "case a: document key copied, marker written")
check(((try? fm.contentsOfDirectory(atPath: at(pa, "support").path)) ?? []).contains { $0.hasPrefix("Gantry.before-migration-") && fm.fileExists(atPath: at(pa, "support/\($0)/seed.txt").path) }, "case a: the earlier Gantry folder is kept aside")
check((try? Data(contentsOf: at(pa, "support/Gantry/seed.txt"))) == Data("s".utf8), "case a: the settings-only Gantry folder keeps its own files")
check(AppRename.personalDocument(documents: at(pa, "docs"), dataDir: at(pa, "support/Gantry"), ext: "gantry", legacyExt: "bastion").path.hasSuffix("Bastion/Personal.bastion"), "case a: the old Personal.bastion opens with its key")
let pb = profile(seed: false, ownLibrary: true)
check(AppRename.migrateDataFolder(in: at(pb, "support"), documents: at(pb, "docs")) == .hasOwnLibrary, "case b: own Gantry library is kept")
check(!fm.fileExists(atPath: at(pb, "support/Gantry/\(AppRename.marker)").path), "case b: nothing migrated")
check(AppRename.personalDocument(documents: at(pb, "docs"), dataDir: at(pb, "support/Gantry"), ext: "gantry", legacyExt: "bastion").path.hasSuffix("Gantry/Personal.gantry"), "case b: its own Personal.gantry opens")
let pc = fresh()
check(AppRename.migrateDataFolder(in: at(pc, "support"), documents: at(pc, "docs")) == .notNeeded, "case c: no Bastion data, nothing to migrate")
check(AppRename.personalDocument(documents: at(pc, "docs"), dataDir: at(pc, "support/Gantry"), ext: "gantry", legacyExt: "bastion").path.hasSuffix("Gantry/Personal.gantry"), "case c: new Personal.gantry")
for d in [pa, pb, pc, noDocs] { try? fm.removeItem(at: d) }
print(failures == 0 ? "ALL PASSED" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
