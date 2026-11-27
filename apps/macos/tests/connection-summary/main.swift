import Foundation
// UI-04 (Native Mac): the connection page's login line and the session status line.
var failures = 0
func check(_ got: String, _ want: String, _ what: String) {
    let ok = got == want
    print((ok ? "PASS " : "FAIL ") + what + (ok ? "" : ": got \"\(got)\""))
    if !ok { failures += 1 }
}
typealias S = ConnectionSummary
check(S.loginLine(.offer(user: "admin", source: "default", sourceName: "", autoUse: true)), "Signs in as admin · Saved for this connection", "own login")
check(S.loginLine(.offer(user: "admin", source: "inherited", sourceName: "Customer A", autoUse: true)), "Signs in as admin · From folder Customer A", "folder login")
check(S.loginLine(.offer(user: "root", source: "same-host", sourceName: "a-ssh", autoUse: false)), "Signs in as root · Offered from a-ssh", "offered from another connection")
check(S.loginLine(.none), "No login saved", "none")
check(S.loginLine(.locked(user: "admin")), "Signs in as admin · Credentials locked", "credentials locked")
check(S.loginLine(.locked(user: "")), "Credentials locked", "locked, no user")
check(S.loginLine(.inline(user: "ops")), "Signs in as ops · Saved for this connection", "inline")
check(S.security(protocolName: "ssh", loginKind: "ssh-key"), "SSH · key", "ssh key")
check(S.security(protocolName: "rdp", loginKind: "password"), "RDP · password", "rdp password")
check(S.security(protocolName: "vnc", loginKind: nil), "VNC", "unknown kind")
check(S.statusLine(name: "web1", address: "10.0.0.5:22", user: "admin", security: "SSH · key", state: nil, logging: true),
      "web1 (10.0.0.5:22) · admin · SSH · key · Logging", "status line")
check(S.statusLine(name: "dc", address: "dc.lab", user: nil, security: "RDP", state: "Reconnecting", logging: false),
      "dc (dc.lab) · RDP · Reconnecting", "status line, reconnecting")
check(S.lastResult(nil), "None yet", "no result")
check(S.lastResult("OK"), "OK", "ok result")
print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
