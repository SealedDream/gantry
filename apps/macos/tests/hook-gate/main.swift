import Foundation

var failures = 0
func check(_ ok: Bool, _ name: String) {
    print("\(ok ? "PASS" : "FAIL") \(name)")
    if !ok { failures += 1 }
}

func v(_ state: String, _ exit: Int32?, out: String = "", err: String = "", error: String? = nil) -> HookGateVerdict {
    HookGate.verdict(task: "Gate", connection: "web-1", state: state, exit: exit, stdout: out, stderr: err, error: error)
}

check(v("done", 0) == .proceed, "done with exit 0 connects")
if case .stop(let t) = v("done", 1, err: "no VPN\n") {
    check(t.contains("exited with 1") && t.hasSuffix("no VPN") && t.contains("web-1"), "exit 1 stops and quotes stderr")
} else { check(false, "exit 1 stops") }
if case .stop(let t) = v("done", 2, out: "stdout only") { check(t.hasSuffix("stdout only"), "falls back to stdout") } else { check(false, "exit 2 stops") }
if case .stop(let t) = v("failed", nil, error: "program not found") { check(t.contains("failed") && t.hasSuffix("program not found"), "start failure stops with the error") } else { check(false, "failed stops") }
if case .stop(let t) = v("timed_out", nil) { check(t.contains("timed out"), "timeout stops") } else { check(false, "timeout stops") }
if case .stop(let t) = v("cancelled", nil) { check(t.contains("cancelled"), "cancel stops") } else { check(false, "cancel stops") }
if case .stop(let t) = v("done", 1, err: String(repeating: "x", count: 5000)) {
    check(t.count < HookGate.quotedOutputLimit + 200, "long output is cut to its tail")
} else { check(false, "long output stops") }
check(v("running", nil) != .proceed, "a run still going never counts as success")

let batch = HookBatch()
check(batch.claim(ownerId: "f", taskId: "t", when: "after_connect"), "first host of a Connect All runs the multi-host hook")
check(!batch.claim(ownerId: "f", taskId: "t", when: "after_connect"), "second host does not run it again")
check(batch.claim(ownerId: "f", taskId: "t", when: "before_connect"), "another moment is its own hook")
check(batch.claim(ownerId: "g", taskId: "t", when: "after_connect"), "another folder is its own hook")

print(failures == 0 ? "ALL PASS" : "\(failures) FAILED")
exit(failures == 0 ? 0 : 1)
