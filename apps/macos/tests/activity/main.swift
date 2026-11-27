import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}

// The shape `activity_query_json` returns (synthetic values).
let json = """
[{"sessionId":"s1","connectionId":"c1","connectionName":"web-01","folderPath":[],"protocol":"ssh","host":"10.0.0.5","port":22,
  "username":"admin","route":[],"loginSource":"own","startedAt":1700000000000,"app":"native-mac","appVersion":"1","deviceName":"d",
  "open":false,"connectedAt":1700000001000,"endedAt":1700000046000,"durationMs":45000,"endReason":"closed_by_user","reconnects":0,
  "transcriptPath":null,"transcriptSha256":null},
 {"sessionId":"s2","connectionId":"c2","connectionName":"=cmd, \\"x\\"","folderPath":[],"protocol":"rdp","host":"dc1",
  "username":null,"route":[],"loginSource":"typed","startedAt":1700000100000,"app":"native-mac","appVersion":"1","deviceName":"d",
  "open":false,"durationMs":null,"endReason":"auth_failed"},
 {"sessionId":"s3","connectionId":"c3","connectionName":"files","folderPath":[],"protocol":"sftp","host":"nas","port":null,
  "username":"bob","route":[],"loginSource":"key","startedAt":1700000200000,"app":"native-mac","appVersion":"1","deviceName":"d",
  "open":true,"endReason":null},
 {"sessionId":"s4","connectionId":"c4","connectionName":"x","folderPath":[],"protocol":"vnc","host":"h","username":null,"route":[],
  "loginSource":"own","startedAt":1,"app":"native-mac","appVersion":"1","deviceName":"d","open":false,"endReason":"something_new"}]
"""
let rows = try! ActivityExport.decode(json)
check(rows.count == 4, "decodes four sessions, unknown fields ignored")
check(rows[0].resultText == "Closed" && rows[0].isOk && rows[0].durationText == "45 s", "closed by user: OK, 45 s")
check(rows[0].target == "10.0.0.5:22" && rows[2].target == "nas", "host with and without port")
check(rows[1].resultText == "Sign-in failed" && rows[1].isFailed, "auth_failed is a failure")
check(rows[2].resultText == "Open" && rows[2].durationText == "—" && !rows[2].isFailed, "open session")
check(rows[3].resultText == "Unknown" && rows[3].isFailed, "unknown end reason")

check(ActivityRecord.duration(59_000) == "59 s", "seconds")
check(ActivityRecord.duration(720_000) == "12 min", "minutes")
check(ActivityRecord.duration(11_100_000) == "3 h 05 min", "hours")

check(rows[0].matches("WEB") && rows[0].matches("admin") && rows[0].matches("10.0.0") && rows[0].matches(" "), "free text matches name, user, host, blank")
check(rows[1].matches("sign-in") && !rows[0].matches("rdp"), "free text matches result and protocol only on its row")

var f = ActivityFilter()
check(f.coreJSON() == "{}", "no filter sends {}")
f.range = .week; f.protocolName = "rdp"; f.user = " admin "; f.result = .failed
let now = Date(timeIntervalSince1970: 1_700_000_000)
check(f.coreJSON(now: now) == #"{"from":1699395200000,"protocol":"rdp","result":"failed","user":"admin"}"#, "filter JSON: from, protocol, trimmed user, result")
f.result = .open
check(f.coreJSON(now: now).contains(#""result":"open""#), "open result")

var scoped = ActivityFilter()
scoped.scope = .connection(id: "c1", name: "web-01")
check(scoped.coreJSON() == #"{"connection":"c1"}"#, "connection History sends the connection id")
check(scoped.scope?.title == "History of web-01", "connection History title")
scoped.scope = .folder(id: "f1", name: "Customers"); scoped.protocolName = "ssh"
check(scoped.coreJSON() == #"{"folder":"f1","protocol":"ssh"}"#, "folder History sends the folder id with other filters")
check(scoped.scope?.title == "History of Customers and subfolders", "folder History title")

let csv = ActivityExport.csv(rows)
let lines = csv.components(separatedBy: "\r\n")
check(lines[0] == "Started,Connection,Protocol,Host,User,Duration,Result", "CSV header")
check(lines.count == 6 && lines[5].isEmpty, "CSV has header + 4 rows")
check(lines[1] == "2023-11-14T22:13:20Z,web-01,ssh,10.0.0.5:22,admin,45 s,Closed", "CSV row")
check(lines[2].contains(#""'=cmd, ""x""""#), "CSV quotes commas/quotes and defuses formulas")
let exported = try! JSONSerialization.jsonObject(with: Data(ActivityExport.json(rows).utf8)) as! [[String: String]]
check(exported.count == 4 && exported[0]["Result"] == "Closed" && exported[0].count == 7, "JSON export has the same rows and columns")
check(ActivityExport.csv([]) == "Started,Connection,Protocol,Host,User,Duration,Result\r\n", "empty export is header only")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
