// Native Mac: a terminal's program title (OSC 0/2) made safe for a tab name (TabTitle.swift).
import Foundation
func check(_ ok: Bool, _ what: String) { if !ok { print("FAIL \(what)"); failures += 1 } else { print("ok \(what)") } }
var failures = 0

check(TabTitle.sanitized("mo@build-01: ~") == "mo@build-01: ~", "plain title kept")
check(TabTitle.sanitized(nil) == nil, "no title")
check(TabTitle.sanitized("") == nil, "empty title")
check(TabTitle.sanitized("   \t ") == nil, "blank title")
check(TabTitle.sanitized("a\u{1b}[31mb\u{07}c\u{0}d\u{7f}e\u{9b}f") == "a[31mbcdef", "control characters removed (C0, DEL, C1)")
check(TabTitle.sanitized("line1\nline2\r") == "line1line2", "newlines removed")
check(TabTitle.sanitized("a\u{202e}b\u{200b}c") == "abc", "bidi override and zero-width removed")
check(TabTitle.sanitized("  host  ") == "host", "trimmed")
let long = String(repeating: "x", count: 200)
check(TabTitle.sanitized(long)?.count == TabTitle.maxLength, "capped at \(TabTitle.maxLength)")
check(TabTitle.sanitized(long)?.hasSuffix("…") == true, "cap ends with an ellipsis")
check(TabTitle.sanitized(String(repeating: "é", count: 61))?.count == TabTitle.maxLength, "cap counts characters, not bytes")

check(TabTitle.display(name: "Local Shell", program: "ssh build-01", isSaved: false) == "\u{203A} ssh build-01", "unsaved follows the program, marked")
check(TabTitle.display(name: "Local Shell", program: nil, isSaved: false) == "Local Shell", "unsaved falls back on reset")
check(TabTitle.display(name: "Local Shell", program: "\u{1b}\u{07}", isSaved: false) == "Local Shell", "unsaved falls back when only control characters")
check(TabTitle.display(name: "prod-db", program: "vim", isSaved: true) == "prod-db", "saved connection keeps its name")
// SEC-7
check(TabTitle.marked("\u{1F514} Command finished") == "\u{203A} Command finished", "fake bell dropped, mark added")
check(TabTitle.marked("\u{203A}\u{203A} x") == "\u{203A} x", "no doubled mark")
check(TabTitle.marked("\u{25CF}") == nil, "symbol only gives no name")
check(TabTitle.programNotice(source: "web1", title: "Bastion", body: "Vault locked") == ("web1 \u{00B7} terminal", "Bastion: Vault locked"), "notice heading is the source")
check(TabTitle.programNotice(source: "web1", title: "", body: "done") == ("web1 \u{00B7} terminal", "done"), "body only")

if failures > 0 { print("\(failures) failure(s)"); exit(1) }
print("tab-title: all passed")
