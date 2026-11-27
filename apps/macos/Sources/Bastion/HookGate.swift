import Foundation

/// What the before-connect gate decides once a hook's task has finished (B5 packet: "a failing
/// BeforeConnect hook cancels the connect and shows the task output"). Pure, so it is tested
/// without the app (`tests/hook-gate-test.sh`).
enum HookGateVerdict: Equatable {
    case proceed
    case stop(String)
}

enum HookGate {
    /// The longest output tail the refusal message quotes; the full output stays in the task's tab.
    static let quotedOutputLimit = 400

    /// `state` and `exit` are the core's `TaskRunView` (`done` with exit 0 is the only success,
    /// the same rule the core's audit record uses).
    static func verdict(task: String, connection: String, state: String, exit: Int32?,
                        stdout: String, stderr: String, error: String?) -> HookGateVerdict {
        if state == "done", exit == 0 { return .proceed }
        let why: String
        switch state {
        case "cancelled": return .stop("Not connected to \(connection): “\(task)” was cancelled before connect.")
        case "timed_out": why = "timed out"
        default: why = exit.map { "exited with \($0)" } ?? "failed"
        }
        var text = "Not connected to \(connection): before-connect task “\(task)” \(why)."
        let output = [error ?? "", stderr, stdout].map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.first { !$0.isEmpty }
        if let output { text += "\n\n" + String(output.suffix(quotedOutputLimit)) }
        return .stop(text)
    }
}

/// One Connect All run: a multi-host hook set on a folder runs once for the run, not once per
/// host that connects. A connect outside a bulk run has no batch, so its hooks always run.
final class HookBatch {
    private var fired: Set<String> = []

    /// True the first time this hook (folder, task, moment) asks to run in this batch.
    func claim(ownerId: String, taskId: String, when: String) -> Bool {
        fired.insert("\(ownerId)|\(taskId)|\(when)").inserted
    }
}
