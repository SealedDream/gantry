// Unit test for AutosaveKeys: which saved window frames and split layouts are removed at launch.
import Foundation
var failures = 0
func check(_ ok: Bool, _ what: String) { print(ok ? "PASS" : "FAIL", what); if !ok { failures += 1 } }
let w = AutosaveKeys.windowPrefix, s = AutosaveKeys.splitPrefix
let keys = [
    w + "SwiftUI.WindowGroup<Old1>-AppWindow-1", s + "SwiftUI.WindowGroup<Old2>-AppWindow-1",
    w + "main-AppWindow-1", s + "main-AppWindow-1, SidebarNavigationSplitView", s + "credentials",
    "NSTableView Columns v3 folder", "library.width",
]
check(AutosaveKeys.staleKeys(in: keys) == [s + "SwiftUI.WindowGroup<Old2>-AppWindow-1", w + "SwiftUI.WindowGroup<Old1>-AppWindow-1"], "generated window and split keys are stale")
check(AutosaveKeys.staleKeys(in: [String]()).isEmpty, "no keys, nothing to remove")

// removeStale on a scratch domain: generated keys go, the others stay, and it persists.
let domain = "dev.bastion.test.autosave-keys.\(ProcessInfo.processInfo.processIdentifier)"
let app = domain as CFString, user = kCFPreferencesCurrentUser, host = kCFPreferencesAnyHost
for k in keys { CFPreferencesSetValue(k as CFString, "v" as CFString, app, user, host) }
CFPreferencesSynchronize(app, user, host)
check(AutosaveKeys.removeStale(domain: domain) == 2, "two keys removed")
CFPreferencesSynchronize(app, user, host)
let left = Set((CFPreferencesCopyKeyList(app, user, host) as? [String]) ?? [])
check(left == Set(keys.dropFirst(2)), "only the stale keys are gone")
check(AutosaveKeys.removeStale(domain: domain) == 0, "a second launch removes nothing")
for k in left { CFPreferencesSetValue(k as CFString, nil, app, user, host) }
CFPreferencesSynchronize(app, user, host)
try? FileManager.default.removeItem(atPath: NSHomeDirectory() + "/Library/Preferences/\(domain).plist")
if failures > 0 { fatalError("\(failures) failed") }
