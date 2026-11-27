import AppKit
import SwiftUI
import BastionCore

/// Bulk edit (packet B3-BULK-EDIT): set one property on several selected connections. The core
/// lists the properties they all share (`properties_for_selection`) and applies the change to all
/// of them or to none (`apply_to_selection`).
@MainActor
enum BulkEdit {
    /// Show the sheet on `window` for `ids` (two or more connections).
    static func present(ids: [String], model: LibraryModel, on window: NSWindow) {
        let sheet = NSWindow(contentRect: .zero, styleMask: [.titled], backing: .buffered, defer: true)
        let close = { [weak window, weak sheet] in
            guard let window, let sheet else { return }
            window.endSheet(sheet)
        }
        sheet.contentViewController = NSHostingController(rootView: BulkEditSheet(ids: ids, model: model, close: close).uiZoomRoot())
        window.beginSheet(sheet, completionHandler: nil)
    }
}

struct BulkEditSheet: View {
    let ids: [String]
    let model: LibraryModel
    let close: () -> Void

    @State private var props: [SelectionPropertyView] = []
    @State private var key = ""
    @State private var text = ""
    @State private var error: String?
    @State private var addTags = ""
    @State private var removeTags = ""

    /// Width of the sheet: room for the longest property label and a value field.
    private static let width: CGFloat = 440
    /// Picker tag for "inherit from the folder or type".
    private static let inherit = ""

    private var selected: SelectionPropertyView? { props.first { $0.def.key == key } }
    /// Tags are added or removed, never replaced: other tags on each connection stay.
    private var isTags: Bool { key == "tags" }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Edit \(ids.count) Connections").font(DS.Font.headline)
            if props.isEmpty && error == nil {
                Text("These connections share no property that can be edited together.").foregroundStyle(.secondary)
            } else {
                Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 10, verticalSpacing: 10) {
                    GridRow {
                        Text("Property")
                        Picker("Property", selection: $key) {
                            ForEach(props, id: \.def.key) { Text($0.def.label).tag($0.def.key) }
                        }
                        .labelsHidden()
                    }
                    GridRow {
                        Text("Now")
                        Text(currentText).foregroundStyle(.secondary)
                    }
                    if isTags {
                        GridRow {
                            Text("Add")
                            TagField(text: $addTags, suggestions: Tags.all(in: model.tree))
                        }
                        GridRow {
                            Text("Remove")
                            TagField(text: $removeTags, suggestions: Tags.all(in: model.tree))
                        }
                    } else {
                        GridRow {
                            Text("New value")
                            editor
                        }
                    }
                }
                if let help = selected?.def.help, !help.isEmpty {
                    Text(help).font(DS.Font.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
            }
            if let error {
                Text(error).foregroundStyle(.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel", action: close).keyboardShortcut(.cancelAction)
                Button("Apply to \(ids.count)", action: apply).keyboardShortcut(.defaultAction).disabled(selected == nil)
            }
        }
        .padding(20)
        .frame(width: Self.width)
        .onAppear(perform: load)
        .onChange(of: key) { _, _ in text = selected?.mixed == true ? "" : selected?.value ?? "" }
    }

    private var currentText: String {
        guard let p = selected else { return "" }
        if p.mixed { return "Mixed" }
        return p.value ?? "Inherited"
    }

    @ViewBuilder private var editor: some View {
        if let def = selected?.def, def.kind == "choice" || def.kind == "toggle" {
            Picker(def.label, selection: $text) {
                Text("Inherit").tag(Self.inherit)
                if def.kind == "toggle" {
                    Text("On").tag("true")
                    Text("Off").tag("false")
                } else {
                    ForEach(def.options, id: \.id) { Text($0.label).tag($0.id) }
                }
            }
            .labelsHidden()
        } else {
            TextField("Empty: inherit", text: $text).textFieldStyle(.roundedBorder)
        }
    }

    private func load() {
        guard let library = model.library else { error = "No library is open."; return }
        do {
            props = try library.propertiesForSelection(ids: ids)
            key = props.first?.def.key ?? ""
        } catch {
            self.error = "\(error)"
        }
    }

    private func apply() {
        guard let key = selected?.def.key else { return }
        if isTags { return applyTags() }
        let value: String? = text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : text
        var failure: String?
        model.mutate { library in
            do { _ = try library.applyToSelection(ids: ids, key: key, value: value) } catch { failure = "\(error)" }
        }
        if let failure { error = failure } else { close() }
    }

    private func applyTags() {
        let add = Tags.split(addTags), remove = Tags.split(removeTags)
        guard !add.isEmpty || !remove.isEmpty else { return close() }
        var failure: String?
        model.mutate { library in
            do { _ = try library.editTagsOnSelection(ids: ids, add: add, remove: remove) } catch { failure = "\(error)" }
        }
        if let failure { error = failure } else { close() }
    }
}
