import Foundation
// MAC-TEST-VAULT-SCREEN-LOCK: a release build (no test hooks) listens for the real screen lock in
// every environment; only a test-hooks build running a UI-driver script skips it.
var failures = 0
func check(_ ok: Bool, _ name: String) { print((ok ? "PASS " : "FAIL ") + name); if !ok { failures += 1 } }
let driver = ["BASTION_UI_SCRIPT": "/tmp/s.txt"]
let envs: [[String: String]] = [[:], driver, ["BASTION_UI_QUIET": "1"], driver.merging(["BASTION_UI_DOCUMENT_GATE": "1"]) { a, _ in a }]
for env in envs {
    check(ScreenLockGate.observesRealScreenLock(testHooksBuild: false, environment: env), "release build locks on screen lock, env=\(env.keys.sorted())")
}
check(ScreenLockGate.observesRealScreenLock(testHooksBuild: true, environment: [:]), "test-hooks build without driver script still locks")
check(ScreenLockGate.observesRealScreenLock(testHooksBuild: true, environment: ["BASTION_UI_QUIET": "1"]), "test-hooks build, quiet only, still locks")
check(!ScreenLockGate.observesRealScreenLock(testHooksBuild: true, environment: driver), "test-hooks build in driver run skips the real notification")
if failures > 0 { print("\(failures) FAILED"); exit(1) }
print("ALL PASS")
