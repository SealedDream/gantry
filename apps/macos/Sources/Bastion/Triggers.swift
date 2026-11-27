import AppKit
import SwiftUI
import UniformTypeIdentifiers
import UserNotifications
import BastionCore

/// Applies the user's triggers (core `triggers`, `triggers.json` beside the library) to every open
/// terminal and turns the core's trigger events into notifications. The core does the matching,
/// highlighting and per-trigger cooldown; this only polls for events.
@MainActor
final class TriggerRuntime {
    static let shared = TriggerRuntime()

    let library: TriggerLibrary?
    private(set) var loadError: String?
    private final class WeakTerminal { weak var terminal: Terminal?; init(_ t: Terminal) { terminal = t } }
    private var terminals: [WeakTerminal] = []
    private var timer: Timer?
    static let pollInterval: TimeInterval = 1

    private init() {
        let path = LibraryModel.dataDir.appendingPathComponent("triggers.json").path
        do { library = try TriggerLibrary.open(path: path) } catch {
            library = nil
            loadError = errorText(error)
            NSLog("Gantry triggers: %@", errorText(error))
        }
    }

    func attach(_ terminal: Terminal) {
        guard let library else { return }
        do { try terminal.setTriggers(library: library) } catch { NSLog("Gantry triggers: %@", errorText(error)); return }
        terminals.removeAll { $0.terminal == nil }
        terminals.append(WeakTerminal(terminal))
        startTimer()
    }

    /// After an edit: recompile the rules on every open terminal. Returns the first error.
    @discardableResult func reapply() -> String? {
        terminals.removeAll { $0.terminal == nil }
        var first: String?
        for w in terminals {
            do { try w.terminal?.setTriggers(library: library) } catch { first = first ?? errorText(error) }
        }
        return first
    }

    private func startTimer() {
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { _ in
            MainActor.assumeIsolated { TriggerRuntime.shared.poll() }
        }
    }

    private func poll() {
        terminals.removeAll { $0.terminal == nil }
        if terminals.isEmpty { timer?.invalidate(); timer = nil; return }
        for w in terminals {
            guard let t = w.terminal else { continue }
            for e in t.takeTriggerEvents() { notify(e) }
        }
    }

    private func notify(_ e: TriggerEventView) {
        DesktopNotice.post(title: e.name.isEmpty ? "Trigger" : e.name, body: e.line)
    }
}

extension TriggerView: Identifiable {}

/// View › Triggers…: the list, add/edit/delete, import and export.
struct TriggerManagerView: View {
    private var dismiss = PanelDismiss()
    @State private var triggers: [TriggerView] = []
    @State private var selection: String?
    @State private var editing: TriggerView?
    @State private var problem: String?

    private var runtime: TriggerRuntime { .shared }
    private var selected: TriggerView? { triggers.first { $0.id == selection } }

    var body: some View {
        VStack(spacing: 0) {
            Text("Triggers").font(DS.Font.bodyStrong)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            if triggers.isEmpty {
                EmptyState(symbol: "text.magnifyingglass", title: "No triggers",
                           message: "Highlight terminal output that matches a pattern, or get a notification when it appears.") {
                    Button("Add Trigger…") { editing = Self.blank }.keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(runtime.library == nil)
                }
            } else {
                Table(triggers, selection: $selection) {
                    TableColumn("On") { t in
                        Toggle("Enabled", isOn: Binding(get: { t.enabled }, set: { v in problem = save(with(t) { $0.enabled = v }) }))
                            .labelsHidden().toggleStyle(.checkbox)
                    }
                    .width(28)
                    TableColumn("Name") { t in Text(t.name).lineLimit(1) }
                    TableColumn("Pattern") { t in Text(verbatim: t.pattern).font(DS.Font.caption.monospaced()).lineLimit(1) }
                    TableColumn("Action") { t in Text(Self.actions(t)).font(DS.Font.caption).foregroundStyle(.secondary) }
                }
                .contextMenu(forSelectionType: String.self) { ids in
                    if let t = triggers.first(where: { $0.id == ids.first }) {
                        Button("Edit…") { editing = t }
                        Divider()
                        Button("Delete", role: .destructive) { remove(t) }
                    }
                } primaryAction: { ids in editing = triggers.first { $0.id == ids.first } }
                .onDeleteCommand { selected.map(remove) }
            }
            if let message = problem ?? runtime.loadError {
                Text(message).font(DS.Font.caption).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading).padding(.horizontal, DS.Space.m).padding(.top, DS.Space.xs)
            }
            Divider()
            HStack(spacing: DS.Space.xs) {
                Group {
                    Button("Add Trigger", systemImage: "plus") { editing = Self.blank }.help("Add Trigger…")
                    Button("Delete", systemImage: "minus") { selected.map(remove) }.disabled(selected == nil).help("Delete")
                    Button("Edit", systemImage: "pencil") { editing = selected }.disabled(selected == nil).help("Edit…")
                }
                .labelStyle(.iconHitTarget).buttonStyle(.borderless)
                .disabled(runtime.library == nil)
                IconMenuButton(symbol: "ellipsis", help: "More: Import, Export", items: [
                    IconMenuItem(title: "Import…", enabled: runtime.library != nil, action: importFile),
                    IconMenuItem(title: "Export…", enabled: !triggers.isEmpty, action: exportFile),
                ], identifier: "triggers-more")
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
            }
            .padding(DS.Space.s)
        }
        .panelFrame(width: DS.Size.managerWidth + 220, height: DS.Size.managerHeight)
        .onAppear(perform: reload)
        .sheet(item: $editing) { t in TriggerEditSheet(trigger: t) { save($0) } }
    }

    static let defaultHighlight: UInt32 = 0xd9b72b
    static let blank = TriggerView(id: "", name: "", pattern: "", caseInsensitive: true, enabled: true,
                                   highlight: true, fg: nil, bg: defaultHighlight, bold: true, notify: false)

    static func actions(_ t: TriggerView) -> String {
        [t.highlight ? "Highlight" : nil, t.notify ? "Notify" : nil].compactMap { $0 }.joined(separator: " · ")
    }

    private func with(_ t: TriggerView, _ change: (inout TriggerView) -> Void) -> TriggerView {
        var copy = t
        change(&copy)
        return copy
    }

    private func reload() {
        guard let library = runtime.library else { return }
        do { triggers = try library.list() } catch { problem = errorText(error) }
    }

    /// Returns the error text, nil on success (the edit sheet stays open on an error).
    private func save(_ t: TriggerView) -> String? {
        guard let library = runtime.library else { return "Triggers are unavailable." }
        do {
            selection = try library.save(trigger: t)
            reload()
            return runtime.reapply()
        } catch {
            return errorText(error)
        }
    }

    private func remove(_ t: TriggerView) {
        guard let library = runtime.library else { return }
        do { try library.remove(id: t.id); problem = runtime.reapply() } catch { problem = errorText(error) }
        reload()
    }

    private func importFile() {
        guard let library = runtime.library else { return }
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            let json = try String(contentsOf: url, encoding: .utf8)
            _ = try library.importJson(json: json)
            reload()
            problem = runtime.reapply()
        } catch { problem = errorText(error) }
    }

    private func exportFile() {
        guard let library = runtime.library else { return }
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "triggers.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do { try library.exportJson().write(to: url, atomically: true, encoding: .utf8); problem = nil } catch { problem = errorText(error) }
    }
}

/// Add or edit one trigger. The core checks the pattern (bounded regex) when it is saved.
private struct TriggerEditSheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var trigger: TriggerView
    let save: (TriggerView) -> String?
    @State private var problem: String?

    init(trigger: TriggerView, save: @escaping (TriggerView) -> String?) {
        _trigger = State(initialValue: trigger)
        self.save = save
    }

    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            Text(trigger.id.isEmpty ? "New Trigger" : "Edit Trigger").font(DS.Font.bodyStrong)
            Form {
                TextField("Name", text: $trigger.name)
                TextField("Pattern", text: $trigger.pattern).font(DS.Font.body.monospaced())
                Toggle("Ignore case", isOn: $trigger.caseInsensitive)
                Toggle("Highlight matches", isOn: $trigger.highlight)
                if trigger.highlight {
                    colour("Text colour", \.fg)
                    colour("Background", \.bg)
                    Toggle("Bold", isOn: $trigger.bold)
                }
                Toggle("Notify when a new line matches", isOn: $trigger.notify)
                Toggle("Enabled", isOn: $trigger.enabled)
            }
            .formStyle(.grouped)
            Text("A regular expression, for example ERROR|FATAL. Matching is bounded, so a pattern can't slow the terminal down.")
                .font(DS.Font.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let problem { Text(problem).font(DS.Font.caption).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                Button("Save") {
                    problem = save(trigger)
                    if problem == nil { dismiss() }
                }
                .keyboardShortcut(.defaultAction).dsPrimaryButton()
                .disabled(trigger.pattern.trimmingCharacters(in: .whitespaces).isEmpty || (!trigger.highlight && !trigger.notify))
            }
        }
        .padding(DS.Space.m)
        .frame(width: 440)
    }

    /// Optional colour: off keeps the program's own colour.
    private func colour(_ label: String, _ key: WritableKeyPath<TriggerView, UInt32?>) -> some View {
        HStack {
            Toggle(label, isOn: Binding(get: { trigger[keyPath: key] != nil },
                                        set: { trigger[keyPath: key] = $0 ? (trigger[keyPath: key] ?? TriggerManagerView.defaultHighlight) : nil }))
            if let rgb = trigger[keyPath: key] {
                ColorPicker(label, selection: Binding(get: { Color(rgb: rgb) }, set: { trigger[keyPath: key] = $0.rgb }),
                            supportsOpacity: false)
                    .labelsHidden()
            }
        }
    }
}
