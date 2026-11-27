import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}
func object(_ json: String) -> [String: Any] {
    (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any] ?? [:]
}

// Synthetic ids (the core takes UUIDs).
let conn = "5c1b7e0a-3f4d-4c8e-9a21-0b6d7e8f9a10", folder = "7f1d2c3b-4a5e-4b6c-8d9e-1a2b3c4d5e6f"
func start(_ proto: String, host: String = "dc1", port: Int? = 3389, own: String? = nil, inherited: String? = nil) -> SessionActivityStart {
    SessionActivityStart(connectionId: conn, connectionName: "DC", folderPath: [.init(id: folder, name: "Ops")],
                         protocolName: proto, host: host, port: port, ownUsername: own, inheritedUsername: inherited)
}

check(SessionActivityStart.isAppRecorded("rdp") && SessionActivityStart.isAppRecorded("vnc") && SessionActivityStart.isAppRecorded("web"), "rdp, vnc and web are recorded by the app")
check(!SessionActivityStart.isAppRecorded("ssh") && !SessionActivityStart.isAppRecorded("sftp") && !SessionActivityStart.isAppRecorded("ftps"), "ssh, sftp and ftps are left to the core")

// The login source is never "unknown": the core refuses it (#1004).
check(SessionActivityStart.loginSource("rdp", ownUsername: "admin", inheritedUsername: nil) == "own", "rdp with own user: own")
check(SessionActivityStart.loginSource("rdp", ownUsername: nil, inheritedUsername: "ops") == "inherited", "rdp with folder user: inherited")
check(SessionActivityStart.loginSource("rdp", ownUsername: "  ", inheritedUsername: nil) == "typed", "rdp with blank user: typed")
check(SessionActivityStart.loginSource("vnc", ownUsername: "admin", inheritedUsername: nil) == "typed", "vnc: typed")
check(SessionActivityStart.loginSource("web", ownUsername: nil, inheritedUsername: nil) == "typed", "web without user: typed")

let rdp = object(start("rdp", own: "admin").json(startedAt: 5, appVersion: "1", deviceName: "mac"))
check(rdp["connectionId"] as? String == conn && rdp["protocol"] as? String == "rdp" && rdp["host"] as? String == "dc1" && rdp["port"] as? Int == 3389, "rdp start: id, protocol, host, port")
check((rdp["folderPath"] as? [[String: String]]) == [["id": folder, "name": "Ops"]], "folder path root first with ids and names")
check(rdp["username"] as? String == "admin" && rdp["loginSource"] as? String == "own" && rdp["app"] as? String == "native-mac", "username, login source, app")
check(rdp["startedAt"] as? Int == 5 && (rdp["route"] as? [String]) == [], "start time and empty route")
check(Set(rdp.keys) == ["connectionId", "connectionName", "folderPath", "protocol", "host", "port", "username", "route", "loginSource", "startedAt", "app", "appVersion", "deviceName"], "only the core's field names, no secret field")

let vnc = object(start("vnc", port: nil, own: "admin").json(startedAt: 5, appVersion: "1", deviceName: "mac"))
check(vnc["username"] == nil && vnc["port"] == nil, "vnc: no username, no port when unset")

let web = object(start("web", host: "https://intranet.example:8443/app?q=1", port: nil).json(startedAt: 5, appVersion: "1", deviceName: "mac"))
check(web["host"] as? String == "intranet.example" && web["port"] as? Int == 8443, "web: host name and port from the URL, no path or query")
let web443 = object(start("web", host: "https://intranet.example/", port: nil).json(startedAt: 5, appVersion: "1", deviceName: "mac"))
check(web443["host"] as? String == "intranet.example" && web443["port"] == nil, "web: default port left out")
let webUser = object(start("web", host: "https://bob:secret@intranet.example/", port: nil).json(startedAt: 5, appVersion: "1", deviceName: "mac"))
check(webUser["host"] as? String == "intranet.example" && !String(describing: webUser).contains("secret"), "web: credentials in the URL are not recorded")

let end = object(SessionActivityStart.endJSON(connectedAt: 10, endedAt: 20, reason: "remote_closed"))
check(end["connectedAt"] as? Int == 10 && end["endedAt"] as? Int == 20 && end["endReason"] as? String == "remote_closed", "end JSON")
let failed = object(SessionActivityStart.endJSON(connectedAt: nil, endedAt: 20, reason: "failed"))
check(failed["connectedAt"] == nil && failed["endReason"] as? String == "failed", "failed connect: never connected")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
