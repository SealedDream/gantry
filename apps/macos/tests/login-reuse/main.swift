import Foundation
// SEC-03 (Native Mac): RememberedLoginStore asks the rule on every read, with the minutes given
// at that read, counts from the last successful sign-in and forgets an expired login.
// The rule here mirrors core `remembered_login_usable` (its own tests are in core/tests/policy_tests.rs).
var failures = 0
func check(_ ok: Bool, _ what: String) { print((ok ? "PASS " : "FAIL ") + what); if !ok { failures += 1 } }
func rule(_ at: UInt64, _ now: UInt64, _ m: UInt32) -> Bool { m == 0 || (now >= at && now - at < UInt64(m) * 60) }

var clock: UInt64 = 1_000
var calls: [UInt32] = []
var s = RememberedLoginStore<String>(usable: { calls.append($2); return rule($0, $1, $2) }, now: { clock })

check(s.login(for: "a", minutes: 5) == nil, "nothing remembered: nil, rule not asked")
check(calls.isEmpty, "rule not asked without an entry")
s.remember("pw", for: "a")
clock += 299
check(s.login(for: "a", minutes: 5) == "pw", "4 min 59 s under 5: reused")
check(calls == [5], "minutes passed to the rule as given")
clock += 1
check(s.login(for: "a", minutes: 5) == nil, "5 min 0 s: not reused")
check(s.login(for: "a", minutes: 0) == nil, "expired login was forgotten, not kept for a later 0")
s.remember("pw", for: "b"); clock += 10_000
check(s.login(for: "b", minutes: 0) == "pw", "0 = until Lock or quit")
check(s.login(for: "b", minutes: 1) == nil, "a lower limit set later applies at once")
s.remember("pw", for: "c"); clock += 200; s.remember("pw", for: "c"); clock += 200
check(s.login(for: "c", minutes: 5) == "pw", "a successful sign-in restarts the time")
s.remember("pw", for: "d"); clock -= 50
check(s.login(for: "d", minutes: 5) == nil, "clock went back under a limit: not reused")
s.remember("x", for: "e"); s.remember("y", for: "f"); s.forget("e")
check(s.login(for: "e", minutes: 0) == nil && s.login(for: "f", minutes: 0) == "y", "forget drops one")
s.forgetAll()
check(s.login(for: "f", minutes: 0) == nil, "forgetAll (Lock) drops all")
let a = monotonicSeconds(); let b = monotonicSeconds()
check(b >= a && a > 0, "monotonic clock moves forward")
print(failures == 0 ? "login-reuse: 0 FAIL" : "login-reuse: \(failures) FAIL")
exit(failures == 0 ? 0 : 1)
