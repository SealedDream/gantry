import Darwin
import Foundation
import BastionCore

/// Owner round 2, item 14: closing asks only when something runs. A live SSH pane always asks; a
/// local shell asks only while a program runs in it. The core does not report a terminal's process
/// yet, so the Mac reads it from the process table: every local shell is a child of this app, and a
/// shell with a child of its own is running a command. With several local shells open the check
/// cannot tell which one is busy, so a busy one anywhere makes every local close ask (never the
/// reverse: a busy shell is never closed without asking).
@MainActor
enum LocalShellActivity {
    /// Terminals that run a local shell (weak: a closed terminal drops out).
    private static let local = NSHashTable<AnyObject>.weakObjects()

    static func markLocal(_ terminal: Terminal) { local.add(terminal) }
    static func isLocal(_ terminal: Terminal) -> Bool { local.contains(terminal) }

    /// Whether any child of this app has a child process (a command running in a local shell).
    nonisolated static func anyShellBusy() -> Bool {
        childPids(of: getpid()).contains { !childPids(of: $0).isEmpty }
    }

    /// Direct children of `pid`; empty when the table cannot be read.
    nonisolated static func childPids(of pid: pid_t) -> [pid_t] {
        let capacity = 256
        var buffer = [pid_t](repeating: 0, count: capacity)
        let bytes = proc_listchildpids(pid, &buffer, Int32(capacity * MemoryLayout<pid_t>.size))
        guard bytes > 0 else { return [] }
        // The call returns a count of pids on current macOS (bytes on some older releases).
        let count = min(Int(bytes), capacity)
        return buffer.prefix(count).filter { $0 > 0 }
    }
}
