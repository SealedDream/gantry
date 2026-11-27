import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}

let a = TaskGridRow(id: "1", host: "web-01", state: "done", exit: 0, stdout: " 10:00 up 3 days, load 0.1\n", millis: 420)
let b = TaskGridRow(id: "2", host: "web-02", state: "done", exit: 0, stdout: " 10:00 up 3 days, load 0.1\n", millis: 380)
let c = TaskGridRow(id: "3", host: "db-01", state: "done", exit: 2, stdout: "", stderr: "df: /x: No such file\n", millis: 1500)
let d = TaskGridRow(id: "4", host: "db-02", state: "running")
let e = TaskGridRow(id: "5", host: "old", state: "failed", error: "host key not trusted yet: connect once\nmore")

check(a.status == .ok && c.status == .failed && d.status == .running && e.status == .failed, "status from state and exit code")
check(TaskGridRow(id: "x", host: "x", state: "starting").status == .waiting, "starting is waiting")
check(a.summary == "10:00 up 3 days, load 0.1", "summary is the last non-empty line")
check(c.summary == "df: /x: No such file", "failed with only stderr: first stderr line")
check(e.summary == "host key not trusted yet: connect once", "error: its first line")

let g = TaskGrid.groups([a, c, b, d, TaskGridRow(id: "6", host: "db-03", state: "running")])
check(g.count == 4, "identical output folds into one group; running rows stay alone")
check(g[0].isGroup && g[0].rows.map(\.host) == ["web-01", "web-02"] && g[0].title == "2 hosts", "group keeps order and names")
check(!g[1].isGroup && g[1].title == "db-01", "single row titled by host")
var a3 = a; a3.exit = 1; a3.state = "done"
check(TaskGrid.groups([a, a3]).count == 2, "same output, other exit code: not grouped")

let diff = TaskGrid.diff("one\ntwo\nthree\n", "one\n2\nthree\nfour\n")
check(diff == [.same("one"), .left("two"), .right("2"), .same("three"), .right("four")], "line diff marks changes")
check(TaskGrid.diff("", "").isEmpty, "empty diff")
let big = (0..<2500).map(String.init).joined(separator: "\n")
check(TaskGrid.diff(big, big).count == 2500 + 500, "diff is bounded: lines past the cap shown as changed")

let all = TaskGrid.labelled([a, c])
check(all.hasPrefix("== web-01 (exit 0, 420 ms) ==\n 10:00 up"), "labelled copy header")
check(all.contains("== db-01 (exit 2, 1.5 s) ==\ndf: /x"), "labelled copy per host")
check(TaskGrid.duration(125_000) == "2 m 5 s", "minutes")

check(TaskGrid.isOvertime(d, runningFor: 31, limit: 30) && !TaskGrid.isOvertime(a, runningFor: 99, limit: 30), "overtime only while running")
check(TaskGrid.tally([a, b, c, d]) == "2 ok · 1 failed · 1 running", "tally")
var t = a; t.stdout = "x\n[output truncated by Bastion]"
check(t.isTruncated && !a.isTruncated, "truncated flag")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
