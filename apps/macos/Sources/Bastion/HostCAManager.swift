import SwiftUI
import BastionCore

/// SSH host certificate authorities (core `hostcert`): each is a `@cert-authority` line in the
/// app's known_hosts. A server whose host certificate one of them signed, for a host its patterns
/// match, connects without a host-key prompt. Public keys only; nothing secret is stored.
struct HostCAManagerView: View {
    @Environment(SessionsModel.self) private var sessions
    private var dismiss = PanelDismiss()
    @State private var cas: [HostCaView] = []
    @State private var selection: String?
    @State private var patterns = ""
    @State private var publicKey = ""
    @State private var problem: String?

    var body: some View {
        VStack(spacing: 0) {
            Text("Host Certificate Authorities").font(DS.Font.bodyStrong)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if cas.isEmpty {
                Text("No CAs trusted. Servers prove themselves with their host key, checked against known hosts.")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 80)
            } else {
                Table(cas, selection: $selection) {
                    TableColumn("Hosts") { (ca: HostCaView) in Text(ca.patterns).font(DS.Font.style(.body, design: .monospaced)) }
                    TableColumn("CA key") { (ca: HostCaView) in
                        Text("\(ca.algorithm) \(ca.fingerprint)\(ca.comment.isEmpty ? "" : " (\(ca.comment))")").foregroundStyle(.secondary)
                    }
                }
                .frame(minHeight: 120)
            }
            Divider()
            Form {
                TextField("Hosts", text: $patterns, prompt: Text("*.example.com,[10.0.0.5]:2222"))
                // Keys are long: the field gets the row's full width, its label above it.
                VStack(alignment: .leading, spacing: DS.Space.xs) {
                    Text("CA public key")
                    TextField("CA public key", text: $publicKey, prompt: Text("ssh-ed25519 AAAA… ca"))
                        .labelsHidden()
                        .font(DS.Font.style(.body, design: .monospaced))
                        .frame(maxWidth: .infinity)
                }
                Text("Only add a CA you got from its owner over a channel you trust: it can vouch for every host its patterns match.")
                    .font(DS.Font.caption).foregroundStyle(.secondary)
                if let problem { Text(problem).font(DS.Font.caption).foregroundStyle(.red) }
            }
            .formStyle(.grouped)
            .scrollDisabled(true)
            .fixedSize(horizontal: false, vertical: true)
            Divider()
            HStack {
                Button("Remove") { remove() }.disabled(selection == nil)
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Add CA") { add() }.keyboardShortcut(.defaultAction).dsPrimaryButton()
                    .disabled(patterns.trimmingCharacters(in: .whitespaces).isEmpty || publicKey.trimmingCharacters(in: .whitespaces).isEmpty)
            }
            .padding(DS.Space.m)
        }
        .frame(minWidth: 0, idealWidth: DS.Size.managerWidth + 220, maxWidth: DS.Size.managerWidth + 220)
        .onAppear(perform: reload)
    }

    private func reload() { cas = sessions.manager?.hostCas() ?? [] }

    private func add() {
        do {
            _ = try sessions.manager?.addHostCa(patterns: patterns, publicKey: publicKey)
            patterns = ""
            publicKey = ""
            problem = nil
            reload()
        } catch FfiError.Failed(let message, _) {
            problem = message
        } catch {
            problem = "\(error)"
        }
    }

    private func remove() {
        guard let ca = cas.first(where: { $0.id == selection }) else { return }
        do {
            try sessions.manager?.removeHostCa(patterns: ca.patterns, fingerprint: ca.fingerprint)
            selection = nil
            reload()
        } catch {
            problem = "\(error)"
        }
    }
}

extension HostCaView: Identifiable {
    public var id: String { "\(patterns) \(fingerprint)" }
}
