import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String) {
    print(ok ? "PASS" : "FAIL", what)
    if !ok { failures += 1 }
}

let lines = TranscriptText.split(Data("[10:00:01] \u{1B}[32mok\u{1B}[0m\r\n2026-11-15T10:00:02Z second line\nplain \u{1B}]0;title\u{07}three\n".utf8), firstNumber: 0)
check(lines.count == 3, "three lines")
check(lines[0].time == "10:00:01" && lines[0].text == "ok", "short time split, colours and CR removed")
check(lines[1].time == "2026-11-15T10:00:02Z" && lines[1].text == "second line", "ISO time split")
check(lines[2].time == nil && lines[2].text == "plain three", "OSC title removed, no time")
check(TranscriptText.hasTimes(lines) && !TranscriptText.hasTimes([lines[2]]), "time column detected")
check(lines[0].display(showTimes: true) == "10:00:01  ok" && lines[0].display(showTimes: false) == "ok", "show times toggle")

let hits = TranscriptText.find("LINE", in: lines)
check(hits == [1], "find is case-insensitive")
check(TranscriptText.find("  ", in: lines).isEmpty, "blank find has no hits")
check(TranscriptText.step([2, 5, 9], from: nil, forward: true) == 2 && TranscriptText.step([2, 5, 9], from: 5, forward: true) == 9, "find next")
check(TranscriptText.step([2, 5, 9], from: 9, forward: true) == 2 && TranscriptText.step([2, 5, 9], from: 2, forward: false) == 9, "find wraps")
check(TranscriptText.copyText(lines, selected: [0, 2], showTimes: false) == "ok\nplain three", "copy chosen lines")

let title = TranscriptText.title(connection: "web-01", started: Date(timeIntervalSince1970: 0))
check(title.hasPrefix("web-01 — "), "title is \"<connection> — <started>\"")

// Paging: a file read in tiny pages gives the same lines as one read, with multi-byte text across page edges.
let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("transcript-test-\(UUID().uuidString).log")
defer { try? FileManager.default.removeItem(at: tmp) }
var body = ""
for i in 0..<5000 { body += "[00:00:\(String(format: "%02d", i % 60))] line \(i) é✓\n" }
body += "last without newline"
try! body.write(to: tmp, atomically: true, encoding: .utf8)
var paged: [TranscriptLine] = []
var pages = 0
try! TranscriptText.read(tmp, pageBytes: 997) { paged += $0; pages += 1; return true }
check(paged.count == 5001 && pages > 50, "reads in pages (\(pages))")
check(paged.map(\.id) == Array(0..<5001), "line numbers continue across pages")
check(paged[4999].text == "line 4999 é✓" && paged[5000].text == "last without newline", "multi-byte text intact across pages, last line kept")
var stopped = 0
try! TranscriptText.read(tmp, pageBytes: 997) { stopped += $0.count; return false }
check(stopped < 5001, "stops when the viewer closes")
check((try? TranscriptText.read(URL(fileURLWithPath: "/nonexistent/x.log")) { _ in true }) == nil, "missing file is an error")

// Speed: a 60 MB log splits well under a second per page.
let big = Data(String(repeating: "[12:00:00] \u{1B}[1mroot@host\u{1B}[0m:~# tail -f /var/log/syslog something long\r\n", count: 13_000).utf8)
let t0 = Date()
_ = TranscriptText.split(big, firstNumber: 0)
let perPage = Date().timeIntervalSince(t0) * Double(TranscriptText.pageBytes) / Double(big.count)
print(String(format: "INFO split %.1f ms per 1 MB page", perPage * 1000))
check(perPage < 0.5, "a page splits in under 500 ms")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
