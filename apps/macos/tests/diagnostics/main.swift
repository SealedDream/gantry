import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}

let fm = FileManager.default
let dir = fm.temporaryDirectory.appendingPathComponent("diag-test-\(UUID().uuidString)")
try! fm.createDirectory(at: dir, withIntermediateDirectories: true)
defer { try? fm.removeItem(at: dir) }

// Synthetic test values that must not reach the zip.
let host = "db-secret-host.example", user = "alice-test", pass = "Hunter2-test-pw", home = "/Users/alice-test"

let settingsJSON = #"{"theme":"dark","log-folder":"\#(home)/logs","proxy":"\#(host)","password":"\#(pass)","scrollback":5000,"telnet":false,"list":["\#(user)"],"empty":""}"#
let red = DiagnosticsBundle.redactSettings(Data(settingsJSON.utf8))
check(!red.contains(host) && !red.contains(pass) && !red.contains(user) && !red.contains(home), "settings: text values removed")
check(red.contains("\"scrollback\" : 5000") && red.contains("\"telnet\" : false") && red.contains("\"theme\" : \"(set)\""), "settings: numbers, booleans and keys kept")
check(DiagnosticsBundle.redactSettings(Data("not json".utf8)) == "{}\n", "settings: bad JSON gives {}")

check(DiagnosticsBundle.scrub("crash in \(home)/Library/x by ALICE-TEST", home: home, user: user) == "crash in ~/Library/x by (user)", "logs: home and account name replaced")

var counts = DiagnosticsCounts(folders: 3, connections: 5, byProtocol: ["ssh": 4, "rdp": 1])
let summary = DiagnosticsBundle.summary(version: "1.2", build: "34", os: "Version 27.0", counts: counts, created: Date(timeIntervalSince1970: 0))
check(summary.contains("App version: 1.2 (34)") && summary.contains("Connections: 5") && summary.contains("  rdp: 1\n  ssh: 4"), "summary: version and counts")
counts.byProtocol = [:]

// App log: lines with level, cap and one older file.
let log = dir.appendingPathComponent("bastion.log")
AppLog.url = log
AppLog.info("Launched")
AppLog.warn("two\nlines")
let logText = try! String(contentsOf: log, encoding: .utf8)
check(logText.contains(" INFO Launched\n") && logText.contains(" WARN two lines\n"), "app log: levels, one line per entry")
for _ in 0..<(AppLog.maxBytes / 60 + 10) { AppLog.error(String(repeating: "x", count: 60)) }
let size = (try! fm.attributesOfItem(atPath: log.path))[.size] as! Int
check(size <= AppLog.maxBytes && fm.fileExists(atPath: log.path + ".1"), "app log: capped, one older file kept")
AppLog.url = nil

// Crash report: newest Bastion one.
let reports = dir.appendingPathComponent("reports")
try! fm.createDirectory(at: reports, withIntermediateDirectories: true)
for (name, age) in [("Bastion-old.ips", 100.0), ("Bastion-new.ips", 10.0), ("Other-newest.ips", 1.0)] {
    let u = reports.appendingPathComponent(name)
    try! "report \(name) path \(home)/x".write(to: u, atomically: true, encoding: .utf8)
    try! fm.setAttributes([.modificationDate: Date().addingTimeInterval(-age)], ofItemAtPath: u.path)
}
let crash = DiagnosticsBundle.latestCrash(in: reports)
check(crash?.lastPathComponent == "Bastion-new.ips", "newest Bastion crash report")
check(DiagnosticsBundle.latestCrash(in: dir.appendingPathComponent("none")) == nil, "no reports folder")

// Whole zip: the expected files, none of the test values.
let settings = dir.appendingPathComponent("settings.json")
try! settingsJSON.write(to: settings, atomically: true, encoding: .utf8)
let applog = dir.appendingPathComponent("app.log")
try! "2026-11-15T00:00:00Z INFO opened \(home)/Library\n".write(to: applog, atomically: true, encoding: .utf8)
let zip = dir.appendingPathComponent("out.zip")
try! DiagnosticsBundle.write(.init(summary: summary, settings: settings, logs: [applog], crash: crash, home: home, user: user), to: zip)
let out = dir.appendingPathComponent("unzipped")
let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/ditto"); p.arguments = ["-x", "-k", zip.path, out.path]
try! p.run(); p.waitUntilExit()
let folder = out.appendingPathComponent("Gantry diagnostics")
let names = ((try? fm.contentsOfDirectory(atPath: folder.path)) ?? []).sorted()
check(names == ["app.log", "last-crash.ips", "settings.json", "summary.txt"], "zip holds the expected files (\(names))")
let all = names.compactMap { try? String(contentsOf: folder.appendingPathComponent($0), encoding: .utf8) }.joined()
check(!all.isEmpty && ![host, user, pass, home].contains { all.localizedCaseInsensitiveContains($0) }, "zip has no host, user, password or home path")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
