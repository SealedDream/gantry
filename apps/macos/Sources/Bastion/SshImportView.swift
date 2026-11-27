import SwiftUI
import BastionCore

/// Preview of `~/.ssh` before import: source file, customer group, flags and warnings.
/// Nothing in the config is executed; the user picks which hosts to import.
struct SshImportView: View {
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var root = ""
    @State private var scan: SshScan?
    @State private var chosen = Set<String>()
    /// Ticked forward rows, in tick order (the first to tick a local port claims it).
    @State private var forwardKeys: [String] = []
    @State private var forwards: [SshForwardRow] = []

    private var groups: [(String, [SshHostView])] {
        Dictionary(grouping: scan?.hosts ?? [], by: \.group).sorted { $0.key < $1.key }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Scanning \(root)").font(DS.Font.caption).foregroundStyle(.secondary)
                Spacer()
                Button("Rescan") { rescan() }
            }
            List {
                ForEach(groups, id: \.0) { group, hosts in
                    Section(group) {
                        ForEach(hosts, id: \.identity) { h in
                            Toggle(isOn: Binding(get: { chosen.contains(h.identity) },
                                                 set: { if $0 { chosen.insert(h.identity) } else { chosen.remove(h.identity) } })) {
                                VStack(alignment: .leading) {
                                    Text(h.alias)
                                    Text("\(h.user.map { "\($0)@" } ?? "")\(h.hostname)\(h.port.map { ":\($0)" } ?? "") · \(h.sourceFile)")
                                        .font(DS.Font.caption).foregroundStyle(.secondary)
                                    if !h.placeholders.isEmpty {
                                        Text("Needs your values: \(h.placeholders.map { "<\($0)>" }.joined(separator: ", "))")
                                            .font(DS.Font.caption).foregroundStyle(.orange)
                                    }
                                    if !h.flags.isEmpty {
                                        Text(h.flags.joined(separator: ", ")).font(DS.Font.caption).foregroundStyle(.orange)
                                    }
                                }
                            }
                            ForEach(forwards.filter { $0.hostIdentity == h.identity && !$0.key.isEmpty }, id: \.key) { f in
                                forwardRow(f, hostChosen: chosen.contains(h.identity))
                            }
                        }
                    }
                }
                if let more = forwards.first(where: { $0.key.isEmpty }) {
                    Section("Tunnels") { Text("\(more.description). \(more.blocked)").font(DS.Font.caption).foregroundStyle(.secondary) }
                }
                if let w = scan?.warnings, !w.isEmpty {
                    Section("Warnings") { ForEach(w, id: \.self) { Text($0).font(DS.Font.caption) } }
                }
            }
        }
        .padding()
        .frame(width: 560, height: 480)
        .onAppear(perform: rescan)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
            ToolbarItem(placement: .confirmationAction) {
                Button(importTitle) {
                    do {
                        if let wf = model.workflow, let lib = model.library {
                            _ = try wf.importHosts(library: lib, identities: Array(chosen))
                            let keys = tickedForwards
                            if !keys.isEmpty {
                                let made = Int(try wf.importForwards(library: lib, keys: keys))
                                if made < keys.count {
                                    model.error = "\(keys.count - made) ticked tunnel\(keys.count - made == 1 ? " was" : "s were") not created: the config changed or the port is now taken. Import again to see them."
                                }
                            }
                        }
                    } catch {
                        model.error = "\(error)"
                    }
                    model.reload()
                    dismiss()
                }
                .disabled(chosen.isEmpty)
            }
        }
    }

    /// Uses the workflow's directory and discovery switches (SSH Config Sources).
    private func rescan() {
        root = model.workflow?.sshDir() ?? ""
        scan = model.workflow?.scan()
        chosen = Set(scan?.hosts.map(\.identity) ?? [])
        forwardKeys = []
        refreshForwards()
    }

    /// Ticked rows whose host is also ticked and that are still importable.
    private var tickedForwards: [String] {
        forwardKeys.filter { k in forwards.first { $0.key == k }.map { chosen.contains($0.hostIdentity) && $0.blocked.isEmpty } ?? false }
    }

    private var importTitle: String {
        let t = tickedForwards.count
        let hosts = "\(chosen.count) \(chosen.count == 1 ? "host" : "hosts")"
        return t == 0 ? "Import \(hosts)" : "Import \(hosts), \(t) \(t == 1 ? "tunnel" : "tunnels")"
    }

    private func refreshForwards() {
        guard let wf = model.workflow, let lib = model.library else { forwards = []; return }
        forwards = wf.forwardPreview(library: lib, chosen: forwardKeys)
    }

    /// One forward under its host: unticked by default, never ticked silently.
    @ViewBuilder private func forwardRow(_ f: SshForwardRow, hostChosen: Bool) -> some View {
        let on = forwardKeys.contains(f.key)
        Toggle(isOn: Binding(get: { on && f.blocked.isEmpty },
                             set: { v in
                                 if v { forwardKeys.append(f.key) } else { forwardKeys.removeAll { $0 == f.key } }
                                 refreshForwards()
                             })) {
            VStack(alignment: .leading, spacing: 2) {
                Text(f.description)
                if !f.blocked.isEmpty {
                    Text(f.blocked).font(DS.Font.caption).foregroundStyle(.secondary)
                } else {
                    if !f.warning.isEmpty {
                        Label(f.warning, systemImage: "exclamationmark.triangle").font(DS.Font.caption).foregroundStyle(.orange)
                    }
                }
                if !f.line.isEmpty {
                    Text("Config: \(f.line)").font(DS.Font.caption.monospaced()).foregroundStyle(.tertiary)
                }
            }
            .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.leading, 24)
        .disabled(!f.blocked.isEmpty || !hostChosen)
        // Two lines per row (owner, 2026-11-14): title and Config line; the explanation is the tooltip.
        .help(f.blocked.isEmpty ? "\(f.explain) If it cannot open, the terminal stays connected and the Tunnel Manager shows why." : f.blocked)
        .accessibilityHint(f.blocked.isEmpty ? f.explain : f.blocked)
        .accessibilityIdentifier("sshImport.forward.\(f.key)")
    }
}
