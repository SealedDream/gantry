// PLUG-06c: the SQL code editor's logic (SqlEditorLogic.swift). The tokenizer is faked here: a
// line holding "/*" opens a comment state, "*/" closes it (the real one is tested in the core).
import Foundation
var failures = 0
func check(_ ok: Bool, _ what: String) { if !ok { failures += 1; print("FAIL \(what)") } else { print("ok \(what)") } }
typealias L = SqlEditorLogic

// Roles
check(L.role("keyword") == .keyword && L.role("string") == .string && L.role("comment") == .comment, "kinds map to roles")
check(L.role("identifier") == .plain && L.role("operator") == .plain && L.role("new-kind") == .plain, "other and unknown kinds are plain")
check(L.role("error") == .error && L.role("parameter") == .parameter, "error and parameter")

// Lines
let text = "SELECT 1;\nFROM 😀 t\n\nx" as NSString
let starts = L.lineStarts(text)
check(starts == [0, 10, 20, 21], "line starts in UTF-16 (emoji is two units)")
check(L.line(of: 0, in: starts) == 0 && L.line(of: 9, in: starts) == 0 && L.line(of: 10, in: starts) == 1, "line of offset")
check(L.line(of: 20, in: starts) == 2 && L.line(of: 21, in: starts) == 3, "empty line and last line")
check(L.lineStarts("" as NSString) == [0], "empty text has one line")

// Fake tokenizer over lines
func fake(_ lines: [String]) -> (Int, String) -> String {
    { i, before in
        let l = lines[i]
        if l.contains("*/") { return "" }
        if l.contains("/*") { return "c1" }
        return before
    }
}
var lines = ["a", "b", "c", "d"]
var states = L.recolour(states: Array(repeating: "\u{1}", count: 4), first: 0, mustReach: 3, tokenize: fake(lines)).states
check(states == ["", "", "", ""], "first colouring")
lines[0] = "/* a"
var r = L.recolour(states: states, first: 0, mustReach: 0, tokenize: fake(lines))
check(r.states == ["c1", "c1", "c1", "c1"] && r.last == 3, "opening a comment re-colours to the end")
lines[2] = "*/"
r = L.recolour(states: r.states, first: 2, mustReach: 2, tokenize: fake(lines))
check(r.states == ["c1", "c1", "", ""] && r.last == 3, "closing it re-colours the lines after")
lines[1] = "bb"
r = L.recolour(states: r.states, first: 1, mustReach: 1, tokenize: fake(lines))
check(r.last == 1, "an edit that keeps the end state stops at its own line")

// Splice
check(L.splice(["a", "b", "c"], first: 1, lastNew: 2, delta: 1, placeholder: "?") == ["a", "?", "?", "c"], "a line inserted")
check(L.splice(["a", "b", "c", "d"], first: 1, lastNew: 1, delta: -2, placeholder: "?") == ["a", "?"], "two lines joined away")
check(L.splice(["a", "b"], first: 1, lastNew: 1, delta: 0, placeholder: "?") == ["a", "?"], "one line edited")

// Completion
let a = L.applyCompletion("SELECT us FROM t", start: 7, length: 2, insert: "users")
check(a.text == "SELECT users FROM t" && a.caret == 12, "completion replaces the prefix")
let e = L.applyCompletion("😀 se", start: 3, length: 2, insert: "select")
check(e.text == "😀 select" && e.caret == 9, "completion after a four-byte character")
check(L.applyCompletion("ab", start: 5, length: 9, insert: "x").text == "abx", "out-of-range replace is clamped")
check(L.move(0, by: -1, count: 3) == 0 && L.move(2, by: 1, count: 3) == 2 && L.move(1, by: 1, count: 3) == 2, "selection stays in the list")
check(L.move(4, by: 1, count: 0) == 0, "empty list")
check(L.needsNewAsk(previousStart: nil, start: 3) && !L.needsNewAsk(previousStart: 3, start: 3) && L.needsNewAsk(previousStart: 3, start: 9), "re-ask only for a new word")
check(L.triggersCompletion("a") && L.triggersCompletion("_") && L.triggersCompletion(".") && L.triggersCompletion("7"), "typing a word character asks")
check(!L.triggersCompletion(" ") && !L.triggersCompletion(";") && !L.triggersCompletion("ab") && !L.triggersCompletion("\n"), "space, punctuation, paste and return do not")

// Run
check(L.runText("SELECT 1;\nSELECT 2;", selection: NSRange(location: 10, length: 9)) == "SELECT 2;", "run the selection")
check(L.runText("SELECT 1;", selection: NSRange(location: 3, length: 0)) == "SELECT 1;", "run all without a selection")
check(L.runText("ab", selection: NSRange(location: 1, length: 9)) == "ab", "a stale selection runs all")

// Comment toggle
var t = L.toggleComment("SELECT 1;\nSELECT 2;", selection: NSRange(location: 2, length: 0))
check(t.text == "-- SELECT 1;\nSELECT 2;", "comment the caret line")
t = L.toggleComment(t.text, selection: NSRange(location: 0, length: 0))
check(t.text == "SELECT 1;\nSELECT 2;", "uncomment it")
t = L.toggleComment("a\n\nb\nc", selection: NSRange(location: 0, length: 4))
check(t.text == "-- a\n\n-- b\nc", "comment several lines, skip empty, stop at the selection")
t = L.toggleComment("  -- a\n--b", selection: NSRange(location: 0, length: 9))
check(t.text == "  a\nb", "uncomment keeps indentation")
t = L.toggleComment("a\nb", selection: NSRange(location: 0, length: 2))
check(t.text == "-- a\nb", "a selection ending at a line start leaves that line")

print(failures == 0 ? "PASS sql-editor-logic" : "FAIL sql-editor-logic \(failures)")
if failures != 0 { fflush(stdout); exit(1) }
