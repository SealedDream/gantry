import SwiftUI
import BastionCore

/// A before-connect hook task the connect is waiting for (B5).
struct HookGateState: Identifiable {
    let id = UUID()
    let task: String
    let run: TaskRun
}

/// "Running <task>…" with Cancel, at the foot of the main window while a connect waits for its
/// before-connect tasks. Cancel stops the task, and so the connect (`HookGate`).
struct HookGateBar: View {
    let gates: [HookGateState]

    var body: some View {
        VStack(spacing: 4) {
            ForEach(gates) { gate in
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Running \(gate.task)…").lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 8)
                    Button("Cancel") { gate.run.cancel() }
                        .accessibilityIdentifier("hook-gate-cancel")
                }
                .accessibilityElement(children: .contain)
                .accessibilityIdentifier("hook-gate")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .frame(maxWidth: 420)
        .background(.bar, in: RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(.separator))
        .padding(12)
    }
}
