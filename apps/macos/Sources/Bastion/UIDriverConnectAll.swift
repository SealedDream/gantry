#if BASTION_TEST_HOOKS
import AppKit

/// UI driver steps for Connect All (B4). The recorder takes Connect All's connect requests instead
/// of the queue, so the suite needs no reachable host and nothing is signed in to.
/// `bulk-record [off]` start (stop) recording · `bulk-sheet` wait for Connect All's alert
/// `bulk-plan = <summary text>` the last plan's summary ("Opening 2. 1 needs a login: x.")
/// `bulk-requests = <name>:<direct|ask>, …` the requests recorded since the last check, in order:
///   `mosh` a direct request that opens with Mosh; `ask` is a request that must sign in through the sheet with automatic sign-in off; `none` for no request
/// `bulk-sessions = <n>` live sessions now (Disconnect All, Reconnect All)
extension Driver {
    @MainActor enum BulkRecord { static var requests: [ConnectRequest] = [] }

    func bulkStep(_ cmd: String, _ arg: String) async {
        let expected = arg.hasPrefix("= ") ? String(arg.dropFirst(2)) : nil
        switch cmd {
        case "bulk-record":
            BulkRecord.requests = []
            commands.bulkRecorder = arg == "off" ? nil : { BulkRecord.requests += $0 }
            write("BULK-RECORD \(arg == "off" ? "off" : "on")")
        case "bulk-sheet":
            for _ in 0..<50 where window?.attachedSheet == nil { await settle(0.1) }
            await settle(0.3)
            write("\(window?.attachedSheet == nil ? "FAIL " : "")BULK-SHEET \(window?.attachedSheet.map(sheetText) ?? "none")")
        case "bulk-plan":
            for _ in 0..<30 where commands.lastBulkSummary == nil { await settle(0.1) }
            let got = commands.lastBulkSummary?.text ?? "none"
            commands.lastBulkSummary = nil
            write("\(expected == nil || expected == got ? "" : "FAIL ")BULK-PLAN \(got)")
        case "bulk-requests":
            await settle(0.3)
            let got = BulkRecord.requests.map { r in
                // A request from the one-by-one list must never sign in on its own.
                let ask = r.askLogin && !r.autoConnect
                let direct = commands.route(r.connection, r.mode, library: commands.model.library) == .mosh ? "mosh" : "direct"
                return "\(r.connection.name):\(ask ? "ask" : r.askLogin || !r.autoConnect ? "BROKEN" : direct)"
            }.joined(separator: ", ")
            BulkRecord.requests = []
            let shown = got.isEmpty ? "none" : got
            write("\(expected == nil || expected == shown ? "" : "FAIL ")BULK-REQUESTS \(shown)")
        case "bulk-sessions":
            await settle(0.5)
            let live = UIDriver.services?.sessions.tabs.filter { !$0.ended }.count ?? -1
            write("\(expected == nil || expected == "\(live)" ? "" : "FAIL ")BULK-SESSIONS \(live)")
        default:
            write("FAIL unknown step \(cmd)")
        }
    }
}
#endif
