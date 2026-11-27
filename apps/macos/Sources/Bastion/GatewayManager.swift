import SwiftUI
import BastionCore

/// Shared SSH gateways (core `gateway`): a connection, folder or type default picks one in its
/// properties and is then reached through it as the first hop. Gateways hold no secrets; the
/// login for a gateway is asked for at connect time like any jump host. Deleting a gateway in use
/// is refused by the core, which names the places that use it.
struct GatewayManagerView: View {
    @Environment(LibraryModel.self) private var model
    private var dismiss = PanelDismiss()
    @State private var gateways: [GatewayView] = []
    @State private var selection: String?
    @State private var editing: GatewayEdit?
    @State private var deleting: GatewayView?
    @State private var problem: String?

    @State private var filter = ""

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("Gateways").font(DS.Font.bodyStrong)
                Spacer()
                ListFilterField(text: $filter)
            }
            .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if gateways.isEmpty {
                EmptyState(symbol: "point.3.connected.trianglepath.dotted", title: "No gateways",
                           message: "Add a jump host once and choose it in any SSH connection's properties.") {
                    Button("Add Gateway…") { editing = .add }.keyboardShortcut(.defaultAction).dsPrimaryButton()
                }
            } else {
                table
            }
            if let problem {
                Text(problem).font(DS.Font.caption).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal, DS.Space.m).padding(.top, DS.Space.xs)
            }
            Divider()
            bottomBar
        }
        .frame(minWidth: 0, idealWidth: DS.Size.managerWidth + 120, maxWidth: DS.Size.managerWidth + 120, minHeight: 0, idealHeight: DS.Size.managerHeight, maxHeight: DS.Size.managerHeight)
        .onAppear(perform: reload)
        .sheet(item: $editing, onDismiss: reload) { edit in GatewayEditSheet(edit: edit, select: { selection = $0 }) }
        .confirmationDialog("Delete “\(deleting?.name ?? "")”?", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } })) {
            Button("Delete Gateway", role: .destructive) { deleting.map(remove); deleting = nil }
        } message: {
            Text("Only a gateway that nothing uses can be deleted.")
        }
    }

    private var table: some View {
        Table(gateways.filter { ListFilterField.matches(filter, [$0.name, $0.host, $0.username ?? "", $0.notes]) }, selection: $selection) {
            TableColumn("Name") { g in Text(g.name).lineLimit(1) }
            TableColumn("Address") { g in Text(verbatim: "\(g.username.map { "\($0)@" } ?? "")\(g.host):\(g.port ?? 22)").lineLimit(1).foregroundStyle(.secondary) }
            TableColumn("Used By") { g in
                Text(g.usedBy.isEmpty ? "Not used" : g.usedBy.joined(separator: ", "))
                    .lineLimit(1).foregroundStyle(.secondary).help(g.usedBy.joined(separator: "\n"))
            }
        }
        .contextMenu(forSelectionType: String.self) { ids in
            if let g = gateways.first(where: { $0.id == ids.first }) {
                Button("Edit…") { editing = .edit(g) }
                Divider()
                Button("Delete…", role: .destructive) { deleting = g }
            }
        } primaryAction: { ids in
            if let g = gateways.first(where: { $0.id == ids.first }) { editing = .edit(g) }
        }
        .onDeleteCommand { deleting = selected }
    }

    private var selected: GatewayView? { gateways.first { $0.id == selection } }

    private var bottomBar: some View {
        HStack(spacing: DS.Space.xs) {
            if !gateways.isEmpty {
                Button("Add Gateway…") { editing = .add }
            }
            Spacer()
            Group {
                Button("Edit", systemImage: "pencil") { selected.map { editing = .edit($0) } }
                    .iconTip("Edit the selected gateway")
                Button("Delete", systemImage: "trash") { deleting = selected }
                    .iconTip("Delete the selected gateway")
            }
            .labelStyle(.iconHitTarget)
            .buttonStyle(.borderless)
            .disabled(selected == nil)
            Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
        }
        .padding(DS.Space.s)
    }

    private func reload() {
        gateways = (try? model.library?.gateways()) ?? []
    }

    private func remove(_ g: GatewayView) {
        guard let library = model.library else { return }
        do {
            try library.removeGateway(id: g.id)
            try library.save()
            model.reload()
            problem = nil
            selection = nil
        } catch {
            problem = errorText(error)
        }
        reload()
    }
}

enum GatewayEdit: Identifiable {
    case add
    case edit(GatewayView)
    var id: String { if case .edit(let g) = self { g.id } else { "add" } }
}

/// Add or edit one gateway. Validation is the core's; its message shows under the fields.
struct GatewayEditSheet: View {
    let edit: GatewayEdit
    var select: (String) -> Void = { _ in }
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var host = ""
    @State private var port = ""
    @State private var username = ""
    @State private var notes = ""
    @State private var problem: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text(isAdd ? "Add Gateway" : "Edit Gateway").font(DS.Font.bodyStrong)
            Form {
                TextField("Name", text: $name)
                TextField("Host", text: $host, prompt: Text("jump.example.net"))
                TextField("Port", text: $port, prompt: Text("22"))
                TextField("User name", text: $username, prompt: Text("Same as the connection"))
                TextField("Notes", text: $notes, axis: .vertical).lineLimit(2...4)
            }
            .formStyle(.columns)
            Text(problem ?? "The login for the gateway is asked for when connecting; nothing secret is stored here.")
                .font(DS.Font.caption).foregroundStyle(problem == nil ? .secondary : Color.red)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button(isAdd ? "Add" : "Save", action: save).keyboardShortcut(.defaultAction).dsPrimaryButton()
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth + 60)
        .onAppear {
            if case .edit(let g) = edit {
                (name, host, port, username, notes) = (g.name, g.host, g.port.map(String.init) ?? "", g.username ?? "", g.notes)
            }
        }
    }

    private var isAdd: Bool { if case .add = edit { true } else { false } }

    private func save() {
        guard let library = model.library else { return }
        let trimmedPort = port.trimmingCharacters(in: .whitespaces)
        guard trimmedPort.isEmpty || UInt16(trimmedPort) != nil else { problem = "Port must be a number from 1 to 65535."; return }
        let input = GatewayInputView(name: name, host: host, port: UInt16(trimmedPort), username: username.isEmpty ? nil : username, notes: notes)
        do {
            switch edit {
            case .add: select(try library.addGateway(gateway: input))
            case .edit(let g): try library.updateGateway(id: g.id, gateway: input)
            }
            try library.save()
            model.reload()
            dismiss()
        } catch {
            problem = errorText(error)
        }
    }
}

extension GatewayView: Identifiable {}
