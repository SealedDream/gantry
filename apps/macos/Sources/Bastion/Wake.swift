import AppKit
import SwiftUI
import BastionCore

/// A connect waiting for its host to wake (core `wol`, "Wake before connect" on).
struct WakeRequest: Identifiable {
    let id = UUID()
    let request: ConnectRequest
    let plan: WolPlanView
}

extension Commands {
    /// Context menu › Wake: send the magic packet now; the result shows as a short alert.
    func wake(_ c: ConnectionView) {
        guard let library = model.library else { return }
        do {
            try library.wake(id: c.id)
            wakeNotice = "Sent a Wake-on-LAN packet to \(c.name)."
        } catch {
            sessions.error = "\(c.name): \(errorText(error))"
        }
    }

    /// Before a connect sheet: the host's wake plan when it should be woken first, else nil.
    func wakePlanBeforeConnect(_ r: ConnectRequest) -> WolPlanView? {
        guard !r.woken, let library = r.library ?? model.library,
              let plan = try? library.wolPlan(id: r.connection.id), plan.beforeConnect else { return nil }
        return plan
    }

    /// The wake sheet finished: connect now (also after a timeout, the host may still answer),
    /// or drop the request when the user cancelled.
    func wakeFinished(_ w: WakeRequest, connect: Bool) {
        waking = nil
        Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(350))
            if connect {
                var r = w.request
                r.woken = true
                enqueueFront(r)
            } else {
                resumeQueue()
            }
        }
    }
}

/// "Waking <host>…" with Cancel, while the core sends the packet and waits for the host's port.
struct WakeSheet: View {
    @Environment(Commands.self) private var commands
    let wake: WakeRequest
    @State private var cancel = WakeCancel()
    @State private var started = Date()
    @State private var outcome: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Waking \(wake.request.connection.name)…").font(DS.Font.bodyStrong)
            Text("Sent Wake-on-LAN to \(wake.plan.mac) via \(wake.plan.broadcast):\(wake.plan.port). Waiting up to \(wake.plan.waitSecs) seconds for \(wake.plan.host):\(wake.plan.checkPort) to answer.")
                .font(DS.Font.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            TimelineView(.periodic(from: started, by: 1)) { ctx in
                ProgressView(value: min(Double(wake.plan.waitSecs), ctx.date.timeIntervalSince(started)), total: Double(max(wake.plan.waitSecs, 1)))
            }
            if let outcome { Text(outcome).font(DS.Font.caption).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Connect Now") { finish(connect: true) }
                Button("Cancel") { finish(connect: false) }.keyboardShortcut(.cancelAction).dsSecondaryButton()
            }
        }
        .padding(DS.Space.m)
        .frame(width: 420)
        .task { await run() }
    }

    private func run() async {
        guard let library = wake.request.library ?? commands.model.library else { return finish(connect: true) }
        let id = wake.request.connection.id, cancel = cancel
        let result = await Task.detached { () -> Result<WakeResult, Error> in
            Result { try library.wakeBeforeConnect(id: id, cancel: cancel) }
        }.value
        switch result {
        case .success(.cancelled): return
        case .success: finish(connect: true)
        case .failure(let error):
            // The packet could not be sent (bad MAC, no network): say so, let the user decide.
            outcome = errorText(error)
        }
    }

    private func finish(connect: Bool) {
        cancel.cancel()
        guard commands.waking?.id == wake.id else { return }
        commands.wakeFinished(wake, connect: connect)
    }
}
