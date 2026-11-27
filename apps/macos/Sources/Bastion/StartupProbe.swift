import AppKit
import Darwin

/// `BASTION_STARTUP_PROBE=1`: print the time from process start (the kernel's start time, so
/// dyld and static init count) to the main window's first frame on screen, then quit. Used to
/// measure the startup budget (cold ≤1.0 s, warm ≤0.5 s); without the variable it does nothing.
enum StartupProbe {
    static var isEnabled: Bool { ProcessInfo.processInfo.environment["BASTION_STARTUP_PROBE"] == "1" }

    /// Call from the main window's onAppear. After the first frame is on screen, opens the
    /// launch gate so the toolbar and menu bar content build; with the probe on, reports both
    /// times and quits.
    @MainActor static func windowAppeared() {
        DispatchQueue.main.async {
            CATransaction.flush()
            report("first-window")
            LaunchGate.shared.open()
            guard isEnabled else { return }
            DispatchQueue.main.async {
                CATransaction.flush()
                report("chrome-ready")
                QuitConfirm.terminateWithoutAsking()
            }
        }
    }

    static func report(_ label: String) {
        guard isEnabled else { return }
        let ms = (Date().timeIntervalSince1970 - processStart()) * 1000
        FileHandle.standardError.write(String(format: "STARTUP %@ %.0f ms\n", label, ms).data(using: .utf8)!)
    }

    /// Process start time in seconds since 1970, from `kinfo_proc`.
    private static func processStart() -> TimeInterval {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0 else { return Date().timeIntervalSince1970 }
        let t = info.kp_proc.p_un.__p_starttime
        return TimeInterval(t.tv_sec) + TimeInterval(t.tv_usec) / 1_000_000
    }
}

/// Closed until the main window's first frame is on screen. The toolbar waits for it: building
/// it (the SwiftUI→AppKit toolbar bridge) was most of the launch time. The menu bar does not:
/// a Commands struct never re-read the gate, so its items and key equivalents stayed missing.
@MainActor
final class LaunchGate: ObservableObject {
    static let shared = LaunchGate()
    @Published private(set) var isOpen = false
    func open() { if !isOpen { isOpen = true } }
}
