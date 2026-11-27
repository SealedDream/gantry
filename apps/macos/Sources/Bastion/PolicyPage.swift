import SwiftUI
import BastionCore

/// Settings › Managed Policy: what the administrator's policy file (core `managed_policy_path`,
/// loaded and enforced by the core) sets, read-only. A broken file blocks every connect; the page
/// says why and where the file is.
struct PolicyPage: View {
    private let policy = policyState()

    var body: some View {
        Form {
            Section {
                if let error = policy.error {
                    Label(error, systemImage: "exclamationmark.octagon.fill").foregroundStyle(.red)
                } else if let source = policy.source {
                    LabeledContent("In force") { Text(source).textSelection(.enabled).truncationMode(.middle) }
                } else {
                    Text("No managed policy is installed; Gantry's defaults apply.").foregroundStyle(.secondary)
                }
                LabeledContent("Policy file location") { Text(policy.managedPath).textSelection(.enabled).truncationMode(.middle) }
            } footer: {
                Text("An administrator installs this file (owned by root, not writable by others). Every setting can only tighten Gantry's defaults; nothing here can be changed from the app.")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
            }
            // Without a policy every row would only repeat the defaults: show the table when one is in force.
            if policy.source != nil || policy.error != nil {
                rules
            }
        }
        .formStyle(.grouped)
    }

    @ViewBuilder private var rules: some View {
        Section("Protocols") {
            LabeledContent("Disabled", value: list(policy.deniedProtocols))
            LabeledContent("Unencrypted protocols allowed", value: policy.forbidLegacy ? "Forbidden" : list(policy.allowedLegacy))
            LabeledContent("RDP requires NLA", value: yesNo(policy.requireRdpNla))
        }
        Section("Credentials and sessions") {
            LabeledContent("Lock credentials after inactivity", value: policy.inactivityLockSecs.map { "\($0 / 60) min" } ?? "Never")
            LabeledContent("Lock credentials when the Mac locks", value: yesNo(policy.lockCredentialsOnOsLock))
            LabeledContent("Credentials shared across customers", value: policy.allowCrossCustomerCredentials ? "Allowed" : "Refused")
            LabeledContent("Session recording", value: policy.allowSessionRecording ? "Allowed" : "Not allowed")
            LabeledContent("Remote clipboard writes (OSC 52)", value: policy.forbidOsc52Write ? "Refused" : "Per connection")
            LabeledContent("Confirm commands on this many hosts", value: "\(policy.bulkConfirmThreshold)")
        }
    }

    private func list(_ items: [String]) -> String {
        items.isEmpty ? "None" : items.map { $0.uppercased() }.joined(separator: ", ")
    }

    private func yesNo(_ b: Bool) -> String { b ? "Yes" : "No" }
}
