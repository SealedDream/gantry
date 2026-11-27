import Foundation

/// MAC-TEST-VAULT-SCREEN-LOCK: whether the app subscribes to the real, system-wide screen-lock
/// notification (`com.apple.screenIsLocked`). A UI-driver run on a core built with the test hooks
/// skips it, so the Mac's own screen lock (5 idle minutes) cannot lock the test vault mid-suite;
/// the driver's simulated `session-lock` and the idle timers still work. Every other build listens
/// exactly as before: the run-time environment alone can never turn the lock off.
enum ScreenLockGate {
    /// Pure decision, tested in `tests/mac-screen-lock-gate`.
    static func observesRealScreenLock(testHooksBuild: Bool, environment: [String: String]) -> Bool {
        !(testHooksBuild && environment["BASTION_UI_SCRIPT"] != nil)
    }
}
