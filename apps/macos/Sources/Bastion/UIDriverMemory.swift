#if BASTION_TEST_HOOKS
import AppKit
import Darwin

/// Memory run steps (MAC-MEMORY). Every sample is one `MEM` line:
/// `MEM <label> age=<s> footprint=<MB> rss=<MB> fds=<n> threads=<n> tabs=<n>`.
/// `footprint` is phys_footprint, the figure macOS charges the app for (compressed and swapped
/// pages included); `rss` is the resident size `ps` shows, which falls when pages are compressed.
extension Driver {
    func memoryStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "mem-sample":
            memSample(arg.isEmpty ? "sample" : arg)
        case "mem-at":
            // `mem-at <seconds> <label>`: sample once the process is that many seconds old.
            let p = arg.split(separator: " ", maxSplits: 1).map(String.init)
            guard let at = p.first.flatMap(Double.init) else { write("FAIL mem-at \(arg)"); return true }
            while ProcessMemory.ageSeconds() < at { await settle(0.1) }
            memSample(p.count > 1 ? p[1] : "at-\(Int(at))s")
        case "mem-soak":
            await memSoak(arg)
        default:
            return false
        }
        return true
    }

    private func memSample(_ label: String) {
        let s = ProcessMemory.sample()
        let tabs = UIDriver.services?.sessions.tabs.count ?? -1
        write(String(format: "MEM %@ age=%.1f footprint=%.2f rss=%.2f fds=%d threads=%d tabs=%d",
                     label as NSString, ProcessMemory.ageSeconds(), s.footprintMB, s.residentMB, s.fds, s.threads, tabs))
    }

    /// `mem-soak <minutes> <tabs>`: until the minutes are up, open that many local shell tabs,
    /// sample, close them all, let the shells end, sample. Cycles are numbered from 1.
    private func memSoak(_ arg: String) async {
        let p = arg.split(separator: " ").compactMap { Double($0) }
        guard p.count == 2, let sv = UIDriver.services else { return write("FAIL mem-soak \(arg)") }
        let (minutes, tabs) = (p[0], Int(p[1]))
        let end = CFAbsoluteTimeGetCurrent() + minutes * 60
        var cycle = 0
        while CFAbsoluteTimeGetCurrent() < end {
            cycle += 1
            for _ in 0..<tabs { sv.sessions.openLocal(); await settle(0.3) }
            await settle(MemoryRun.openSettle)
            memSample("open-\(cycle)")
            sv.sessions.tabs.forEach(sv.sessions.close)
            await settle(MemoryRun.closeSettle)
            memSample("closed-\(cycle)")
            // The baseline for descriptors and threads (owner ruling 2026-11-17): after cycle 1, once
            // the shells have ended, so one-time set-up of the first shell is not counted.
            if cycle == 1 { await settle(MemoryRun.baselineSettle); memSample("settled-1") }
        }
        write("MEM-SOAK cycles=\(cycle) minutes=\(minutes) tabs=\(tabs)")
    }
}

enum MemoryRun {
    /// Seconds after the last tab opens before the sample: the shells start and print a prompt.
    static let openSettle = 2.0
    /// Seconds after closing every tab before the sample: the shell processes exit and their
    /// reader threads and descriptors close.
    static let closeSettle = 3.0
    /// Seconds after cycle 1 before the descriptor and thread baseline, as before the `end` sample.
    static let baselineSettle = 10.0
}

/// This process's memory, descriptors and threads, read the way `footprint` and `ps` read them.
enum ProcessMemory {
    struct Sample { let footprintMB: Double; let residentMB: Double; let fds: Int; let threads: Int }

    static func sample() -> Sample {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
        }
        let mb = 1_048_576.0
        let footprint = kr == KERN_SUCCESS ? Double(info.phys_footprint) / mb : -1
        let resident = kr == KERN_SUCCESS ? Double(info.resident_size) / mb : -1
        return Sample(footprintMB: footprint, residentMB: resident, fds: fileDescriptors(), threads: threads())
    }

    static func fileDescriptors() -> Int {
        let bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, nil, 0)
        return bytes > 0 ? Int(bytes) / MemoryLayout<proc_fdinfo>.size : -1
    }

    static func threads() -> Int {
        var info = proc_taskinfo()
        let size = Int32(MemoryLayout<proc_taskinfo>.size)
        return proc_pidinfo(getpid(), PROC_PIDTASKINFO, 0, &info, size) == size ? Int(info.pti_threadnum) : -1
    }

    /// Seconds since this process started (the kernel's start time, not the driver's).
    static func ageSeconds() -> Double {
        var kp = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.size
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        guard sysctl(&mib, 4, &kp, &size, nil, 0) == 0 else { return -1 }
        let start = kp.kp_proc.p_un.__p_starttime
        let started = Double(start.tv_sec) + Double(start.tv_usec) / 1e6
        return Date().timeIntervalSince1970 - started
    }
}
#endif
