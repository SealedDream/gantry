import Foundation
// The mode and route each connection type opens in (ConnectRoute.swift). Run by connect-route-test.sh.
var failures = 0
func check(_ ok: Bool, _ what: String) { print("\(ok ? "PASS" : "FAIL") \(what)"); if !ok { failures += 1 } }

let modes: [(String, ConnectMode)] = [
    ("ssh", .terminal), ("rdp", .terminal), ("vnc", .terminal), ("web", .terminal), ("local", .terminal),
    ("sftp", .files), ("scp", .files), ("ftps", .files),
    ("services", .system), ("processes", .system), ("eventlog", .system),
]
for (p, m) in modes { check(ConnectRoute.mode(forProtocol: p) == m, "\(p) opens as \(m)") }

// A normal connect: every type, with and without the Mosh transport set.
for (p, m) in modes {
    let plain = ConnectRoute.of(protocol: p, mode: m, usesMosh: false)
    let mosh = ConnectRoute.of(protocol: p, mode: m, usesMosh: true)
    let want: ConnectRoute = p == "local" ? .local : .queue(m)
    check(plain == want, "\(p) without Mosh routes to \(want)")
    check(mosh == (p == "ssh" ? .mosh : want), "\(p) with Mosh routes to \(p == "ssh" ? .mosh : want)")
}
// Mosh is only for an SSH terminal: files, tunnel and system modes of an SSH connection stay on SSH.
for m in [ConnectMode.files, .tunnel, .system] {
    check(ConnectRoute.of(protocol: "ssh", mode: m, usesMosh: true) == .queue(m), "ssh \(m) with Mosh stays on SSH")
}
// Connect All's Open One by One asks the same question with the type's own mode: a Mosh SSH
// connection must route to Mosh (review of #855), never to the SSH sign-in sheet.
check(ConnectRoute.of(protocol: "ssh", mode: ConnectRoute.mode(forProtocol: "ssh"), usesMosh: true) == .mosh,
      "Open One by One: Mosh SSH opens with Mosh")
// Telnet and serial open their own terminal tab, never the SSH sign-in sheet (B7), with or without Mosh.
for mosh in [false, true] {
    check(ConnectRoute.of(protocol: "telnet", mode: .terminal, usesMosh: mosh) == .telnet, "telnet routes to Telnet")
    check(ConnectRoute.of(protocol: "serial", mode: .terminal, usesMosh: mosh) == .serial, "serial routes to Serial")
}
if failures > 0 { print("\(failures) failed"); exit(1) }
print("all passed")
