import SwiftUI
import BastionCore

/// Connection templates (B9): Save as Template…, New from Template…, and the Templates list.
/// Templates live outside the tree in the core, so nothing here can connect to one.
struct TemplateSaveRequest: Identifiable {
    let id: String
    let name: String
}

/// Save as Template…: a name, then a copy of the connection (login reference only, never a password).
struct SaveTemplateSheet: View {
    let request: TemplateSaveRequest
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Save as Template").font(DS.Font.bodyStrong)
            TextField("Name", text: $name)
                .help("Use $Token$ in the template's fields; New from Template asks for each one.")
            if let error { Text(error).font(DS.Font.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Save", action: save).keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(name.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth)
        .onAppear { name = request.name }
    }

    private func save() {
        guard let library = model.library else { return }
        do {
            _ = try library.saveAsTemplate(connectionId: request.id, name: name)
            model.mutate { _ in }
            dismiss()
        } catch {
            self.error = "\(error)"
        }
    }
}

/// New from Template…: pick a template, give each token once, create the connection.
struct NewFromTemplateSheet: View {
    let parent: String?
    @Environment(LibraryModel.self) private var model
    @Environment(Commands.self) private var commands
    @Environment(\.dismiss) private var dismiss
    @State private var templates: [TemplateView] = []
    @State private var selected: String?
    @State private var values: [String: String] = [:]
    @State private var error: String?
    @State private var managing = false

    private var template: TemplateView? { templates.first { $0.id == selected } }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("New from Template").font(DS.Font.bodyStrong)
            if templates.isEmpty {
                Text("No templates. Right-click a connection › Save as Template…")
                    .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } else {
                Picker("Template", selection: $selected) {
                    ForEach(templates, id: \.id) { Text($0.name).tag(Optional($0.id)) }
                }
                if let template {
                    Text("\(template.protocol.uppercased()) · \(template.host)")
                        .font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        .help(template.host)
                    Form {
                        ForEach(template.tokens, id: \.self) { token in
                            TextField(token, text: binding(token))
                        }
                    }
                    .formStyle(.columns)
                }
            }
            if let error { Text(error).font(DS.Font.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Button("Templates…") { managing = true }.help("Edit, rename or delete templates")
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Create", action: create).keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(!complete)
            }
        }
        .padding(DS.Space.m)
        .frame(width: DS.Size.dialogWidth)
        .onAppear {
            templates = model.library?.templates() ?? []
            selected = templates.first?.id
        }
        .onChange(of: selected) { values = [:]; error = nil }
        .sheet(isPresented: $managing, onDismiss: {
            templates = model.library?.templates() ?? []
            if !templates.contains(where: { $0.id == selected }) { selected = templates.first?.id }
        }) { TemplatesSheet() }
    }

    private var complete: Bool {
        guard let template else { return false }
        return template.tokens.allSatisfy { !(values[$0] ?? "").isEmpty }
    }

    private func binding(_ token: String) -> Binding<String> {
        Binding(get: { values[token] ?? "" }, set: { values[token] = $0 })
    }

    private func create() {
        guard let library = model.library, let template else { return }
        do {
            let id = try library.newFromTemplate(templateId: template.id, values: values, parent: parent)
            model.mutate { _ in }
            if let parent { commands.tree.setExpanded(parent, true) }
            commands.selectNode?(id)
            dismiss()
        } catch {
            self.error = "\(error)"
        }
    }
}

/// The Templates list: edit the token fields, rename, delete.
struct TemplatesSheet: View {
    @Environment(LibraryModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var templates: [TemplateView] = []
    @State private var selected: String?
    @State private var draft = Draft()
    @State private var error: String?
    @State private var confirmingDelete = false

    struct Draft: Equatable {
        var name = "", host = "", port = "", username = "", notes = ""
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text("Templates").font(DS.Font.bodyStrong)
            HStack(alignment: .top, spacing: DS.Space.s) {
                List(templates, id: \.id, selection: $selected) { t in
                    Text(t.name).lineLimit(1).help(t.name).tag(Optional(t.id))
                }
                .frame(width: 160, height: 220)
                if selected != nil {
                    Form {
                        TextField("Name", text: $draft.name)
                        TextField("Host", text: $draft.host).help("Computer name or URL. $Token$ allowed.")
                        TextField("Port", text: $draft.port).help("Number or $Token$. Empty: protocol default.")
                        TextField("Username", text: $draft.username)
                        TextField("Notes", text: $draft.notes)
                    }
                    .formStyle(.columns)
                    .frame(minWidth: 220)
                } else {
                    Text(templates.isEmpty ? "No templates." : "Select a template.").foregroundStyle(.secondary)
                        .frame(minWidth: 220, alignment: .leading)
                }
            }
            if let error { Text(error).font(DS.Font.caption).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Button("Delete…", role: .destructive) { confirmingDelete = true }.disabled(selected == nil)
                Spacer()
                Button("Done", role: .cancel) { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Save", action: save).keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(selected == nil)
            }
        }
        .padding(DS.Space.m)
        .onAppear(perform: reload)
        .onChange(of: selected) { load() }
        .confirmationDialog("Delete this template?", isPresented: $confirmingDelete) {
            Button("Delete", role: .destructive, action: delete)
        }
    }

    private func reload() {
        templates = model.library?.templates() ?? []
        if selected == nil || !templates.contains(where: { $0.id == selected }) { selected = templates.first?.id }
        load()
    }

    private func load() {
        error = nil
        guard let t = templates.first(where: { $0.id == selected }) else { draft = Draft(); return }
        draft = Draft(name: t.name, host: t.host, port: t.port ?? "", username: t.username ?? "", notes: t.notes)
    }

    private func save() {
        guard let library = model.library, let id = selected else { return }
        do {
            try library.updateTemplate(id: id, name: draft.name, host: draft.host,
                                       port: draft.port.isEmpty ? nil : draft.port,
                                       username: draft.username.isEmpty ? nil : draft.username, notes: draft.notes)
            model.mutate { _ in }
            reload()
        } catch {
            self.error = "\(error)"
        }
    }

    private func delete() {
        guard let id = selected else { return }
        model.mutate { try $0.deleteTemplate(id: id) }
        selected = nil
        reload()
    }
}

/// Move to… and the B9 template sheets, kept out of `ContentView`'s modifier chain: one more
/// modifier there was more than the compiler could type-check in reasonable time.
struct TreeItemSheets: ViewModifier {
    @Bindable var commands: Commands

    func body(content: Content) -> some View {
        content
            .sheet(item: $commands.moving) { MoveSheet(nodeId: $0.id) }
            .sheet(item: $commands.savingTemplate) { SaveTemplateSheet(request: $0) }
            .sheet(item: $commands.newFromTemplate) { NewFromTemplateSheet(parent: $0.id) }
            .sheet(isPresented: $commands.showingTemplates) { TemplatesSheet() }
    }
}
