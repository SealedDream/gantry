import SwiftUI
import BastionCore

/// Settings › Keyboard: every command that can have a shortcut, grouped as in the menu bar, with
/// a filter (by name or by keys). Click a shortcut and press the new keys; Delete removes it,
/// Escape cancels. The core refuses system chords and reports one another command already has;
/// taking it from that command needs a confirmation.
struct KeyboardSettingsPage: View {
    @Environment(ShortcutsModel.self) private var shortcuts
    @State private var filter = ""

    var body: some View {
        Form {
            Section {
                HStack(spacing: DS.Space.xs) {
                    TextField("Filter", text: $filter, prompt: Text("Filter by command or keys"))
                        .textFieldStyle(.roundedBorder)
                        .labelsHidden()
                    Button("Restore Defaults") { shortcuts.resetAll() }
                        .disabled(shortcuts.items.allSatisfy(\.isDefault))
                }
                if let why = shortcuts.rejection {
                    Label(why, systemImage: "exclamationmark.triangle.fill")
                        .font(DS.Font.caption)
                        .foregroundStyle(.red)
                }
            }
            ShortcutSections(items: shortcuts.search(filter))
        }
        .formStyle(.grouped)
    }
}

/// Shortcut rows in one section, for Settings search.
struct ShortcutList: View {
    let items: [ShortcutView]

    var body: some View {
        ForEach(items, id: \.id) { ShortcutRow(item: $0) }
    }
}

/// Shortcut rows grouped by menu, for the Keyboard page.
struct ShortcutSections: View {
    let items: [ShortcutView]

    var body: some View {
        if items.isEmpty {
            Section { Text("No matching commands").foregroundStyle(.secondary) }
        }
        ForEach(groups, id: \.id) { group in
            Section(group.label) {
                ForEach(items.filter { $0.group == group.id }, id: \.id) { ShortcutRow(item: $0) }
            }
        }
    }

    private var groups: [(id: String, label: String)] {
        var seen = Set<String>()
        return items.compactMap { seen.insert($0.group).inserted ? ($0.group, $0.groupLabel) : nil }
    }
}

private struct ShortcutRow: View {
    let item: ShortcutView
    @Environment(ShortcutsModel.self) private var shortcuts
    @State private var pending: (chord: String, conflict: ShortcutConflict)?

    var body: some View {
        LabeledContent(item.label) {
            HStack(spacing: DS.Space.xxs) {
                if !item.isDefault {
                    Button("Restore Default", systemImage: "arrow.uturn.backward") { shortcuts.reset(item.id) }
                        .labelStyle(.iconHitTarget)
                        .buttonStyle(.borderless)
                        .help(item.defaultChord.map { "Restore \(Chords.display($0))" } ?? "Restore: no shortcut")
                }
                ShortcutRecorder(item: item, record: record)
            }
        }
        .confirmationDialog(conflictTitle, isPresented: Binding(get: { pending != nil }, set: { if !$0 { pending = nil } })) {
            Button("Use for \(item.label)") {
                if let p = pending { shortcuts.set(item.id, chord: p.chord, replace: true) }
                pending = nil
            }
            Button("Cancel", role: .cancel) { pending = nil }
        } message: {
            Text("\(pending?.conflict.label ?? "") will no longer have a shortcut.")
        }
    }

    private var conflictTitle: String {
        guard let p = pending else { return "" }
        return "\(Chords.display(p.chord)) is used by \(p.conflict.label)"
    }

    /// A new chord (nil removes the shortcut). The core refuses system chords and says why.
    private func record(_ chord: String?) {
        guard let chord else {
            shortcuts.set(item.id, chord: nil)
            return
        }
        if case .taken(let c) = shortcuts.record(item.id, chord: chord) { pending = (chord, c) }
    }
}

/// The current shortcut as a button; clicked, it waits for the next key press.
private struct ShortcutRecorder: View {
    let item: ShortcutView
    let record: (String?) -> Void
    @Environment(ShortcutsModel.self) private var shortcuts
    @State private var monitor: Any?

    private var recording: Bool { monitor != nil }

    var body: some View {
        Button(action: toggle) {
            Text(recording ? "Type shortcut…" : item.chord.map(Chords.display) ?? "None")
                .monospacedDigit()
                .foregroundStyle(recording ? Color.accentColor : item.chord == nil ? .secondary : .primary)
                .frame(minWidth: DS.Size.shortcutField)
        }
        .help(recording ? "Press the new keys; Delete removes the shortcut, Escape cancels" : "Click to change")
        .accessibilityLabel("\(item.label) shortcut")
        .accessibilityIdentifier("shortcut-\(item.id)")
        .accessibilityValue(item.chord.map(Chords.display) ?? "None")
        .onDisappear(perform: stop)
    }

    private func toggle() {
        if recording { return stop() }
        // Ahead of menu key equivalents, so ⌘-chords are recorded rather than run.
        shortcuts.isRecording = true
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            let plain = event.modifierFlags.intersection([.command, .control, .option, .shift]).isEmpty
            switch event.keyCode {
            case 53 where plain: stop()
            case 51 where plain:
                stop()
                record(nil)
            default:
                guard let chord = Chords.chord(from: event) else {
                    QuietLaunch.beep()
                    return nil
                }
                stop()
                record(chord)
            }
            return nil
        }
    }

    private func stop() {
        guard let monitor else { return }
        NSEvent.removeMonitor(monitor)
        self.monitor = nil
        shortcuts.isRecording = false
    }
}
