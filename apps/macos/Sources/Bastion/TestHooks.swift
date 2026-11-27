import Foundation

/// Test hooks (the UI driver, `Snapshot`, test-only environment variables) exist only in a test
/// build: `swift build -c release -Xswiftc -DBASTION_TEST_HOOKS` (`uitests/build-app.sh`). Any
/// other build, owner builds and bundles included, has none of that code and ignores the
/// variables, whatever the environment says.
enum TestHooks {
    #if BASTION_TEST_HOOKS
    static let compiled = true
    #else
    static let compiled = false
    #endif

    /// A test-only environment variable; always `nil` outside a test build.
    static func env(_ name: String) -> String? {
        compiled ? ProcessInfo.processInfo.environment[name] : nil
    }

    /// `BASTION_LIBRARY=<file>`: a throwaway library (`.json`) or Personal document (`.bastion`) for
    /// tests. The name exists only in a test build, so an owner build always opens the user's own
    /// library and Personal document behind the unlock (LIBRARY-ENV-GATE).
    static var libraryOverride: String? {
        #if BASTION_TEST_HOOKS
        return env("BASTION_LIBRARY")
        #else
        return nil
        #endif
    }

    /// A UI-driver run (`BASTION_UI_SCRIPT` in a test build).
    static let isScripted = env("BASTION_UI_SCRIPT") != nil
}
