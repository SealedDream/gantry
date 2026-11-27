import Foundation

// Native Mac: session log listing, filter and export (SessionLogFiles.swift, LOG-CORE-02).

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS \(what)" : "FAIL \(what)")
    if !ok { failures += 1 }
}

let fm = FileManager.default
let root = fm.temporaryDirectory.appendingPathComponent("session-logs-test-\(UUID().uuidString)")
let a = root.appendingPathComponent("Customers/acme-web-01")
let b = root.appendingPathComponent("Customers/Lab/db-01")
try! fm.createDirectory(at: a, withIntermediateDirectories: true)
try! fm.createDirectory(at: b, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: root) }

func put(_ dir: URL, _ name: String, _ text: String, age: TimeInterval) {
    let url = dir.appendingPathComponent(name)
    try! (SessionLogFiles.magic + "\n" + text).write(to: url, atomically: true, encoding: .utf8)
    try! fm.setAttributes([.modificationDate: Date().addingTimeInterval(-age)], ofItemAtPath: url.path)
}
put(a, "2026-11-19_10-00-00_root.log", "uptime\n", age: 3600)
put(a, "2026-11-19_10-00-00_root.log.1", "older part\n", age: 7200)
put(a, "2026-11-20_09-00-00_root.log", "systemctl status nginx\n", age: 60)
put(a, "notes.txt", "not a log\n", age: 10)
put(b, "2026-11-20_08-00-00_admin.log", "psql -c 'select 1'\n", age: 600)

let all = SessionLogFiles.list([a: "acme-web-01", b: "db-01", root.appendingPathComponent("missing"): "gone"])
check(all.count == 4, "lists .log and rotated .log.N, skips other files and missing folders (\(all.count))")
check(all.first?.name == "2026-11-20_09-00-00_root.log", "newest first")
check(all.last?.name == "2026-11-19_10-00-00_root.log.1", "oldest last")
check(all.first { $0.name.hasPrefix("2026-11-20_08") }?.connection == "db-01", "file carries its connection")

check(SessionLogFiles.isLogName("x.log.12") && !SessionLogFiles.isLogName("x.log.bak") && !SessionLogFiles.isLogName("x.txt"), "log names")
check(SessionLogFiles.filter(all, query: "", content: false).count == 4, "empty filter keeps all")
check(SessionLogFiles.filter(all, query: "DB-01", content: false).count == 1, "filter by connection, any case")
check(SessionLogFiles.filter(all, query: "2026-11-19", content: false).count == 2, "filter by file name")
check(SessionLogFiles.filter(all, query: "nginx", content: false).isEmpty, "text not searched unless asked")
check(SessionLogFiles.filter(all, query: "nginx", content: true).count == 1, "text search")

let out = root.appendingPathComponent("export")
try! fm.createDirectory(at: out, withIntermediateDirectories: true)
let first = try! SessionLogFiles.export([all[0]], to: out)
let second = try! SessionLogFiles.export([all[0]], to: out)
check(first[0].lastPathComponent == all[0].name, "export keeps the name")
check(second[0].lastPathComponent == "2026-11-20_09-00-00_root 2.log", "export never overwrites (\(second[0].lastPathComponent))")
let perms = (try? fm.attributesOfItem(atPath: second[0].path)[.posixPermissions] as? Int) ?? 0
check(perms == 0o600, "exported copy is owner-only")
check((try? String(contentsOf: second[0], encoding: .utf8)) == (try? String(contentsOf: all[0].url, encoding: .utf8)), "copy matches the log")

check(SessionLogFiles.purgeRoots(settingFolder: "") == [""], "purge: default root only")
check(SessionLogFiles.purgeRoots(settingFolder: "  /Volumes/logs ") == ["", "/Volumes/logs"], "purge: settings folder too")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
