import AppKit
import SwiftUI
import BastionCore

/// Tasks results grid (design A): one row per host with a status dot, the last output line, exit
/// code and duration. Click a row to read its whole output in the terminal font and colours; hosts
/// with the same output fold into one row; pick two rows to compare them. Output stays in memory.
struct TaskResultsGrid: View {
    let rows: [TaskGridRow]
    /// Seconds a host may run before the grid offers "Open in Terminal" instead of waiting.
    var limit: TimeInterval = 30
    var openInTerminal: (String) -> Void
    var openAll: ([String]) -> Void

    @Environment(AppearanceSettings.self) private var appearance
    @Environment(ThemesModel.self) private var themes
    @Environment(\.colorScheme) private var colorScheme
    @State private var grouped = true
    @State private var expanded: Set<String> = []
    @State private var picked: Set<String> = []
    @State private var comparing: (GridGroup, GridGroup)?
    @State private var firstSeen: [String: Date] = [:]
    @State private var now = Date()
    private let tick = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var groups: [GridGroup] { grouped ? TaskGrid.groups(rows) : rows.map { GridGroup(rows: [$0]) } }

    var body: some View {
        VStack(spacing: 0) {
            toolbar
            Divider()
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(groups) { g in
                        row(g)
                        if expanded.contains(g.id) { detail(g) }
                        Divider()
                    }
                }
            }
        }
        .onReceive(tick) { now = $0 }
        .onChange(of: rows.filter { !$0.isFinished }.map(\.id), initial: true) { _, live in
            for id in live where firstSeen[id] == nil { firstSeen[id] = Date() }
        }
        .sheet(isPresented: Binding(get: { comparing != nil }, set: { if !$0 { comparing = nil } })) {
            if let (a, b) = comparing { TaskCompareSheet(left: a.first, right: b.first, font: font) }
        }
    }

    private var toolbar: some View {
        HStack(spacing: DS.Space.s) {
            Text(TaskGrid.tally(rows)).font(DS.Font.caption).foregroundStyle(.secondary)
            Spacer()
            Toggle("Group same output", isOn: $grouped).toggleStyle(.checkbox).font(DS.Font.caption)
            Button("Compare", systemImage: "rectangle.split.2x1") { compare() }.disabled(picked.count != 2)
                .quietIcon("Select two rows (⌘-click) to compare their output")
            IconMenuButton(symbol: "doc.on.doc", help: "Copy output", items: [
                IconMenuItem(title: "All, labelled") { copy(TaskGrid.labelled(rows)) },
                IconMenuItem(title: "Selected, labelled", enabled: !picked.isEmpty) {
                    copy(TaskGrid.labelled(rows.filter { r in picked.contains { $0.split(separator: ",").contains(Substring(r.id)) } }))
                },
            ])
            Button("Open All in Terminals", systemImage: "rectangle.stack") { openAll(rows.map(\.id)) }
                .quietIcon("Open all in terminals: one per host, input broadcast to all")
        }
        .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.xs)
    }

    private func row(_ g: GridGroup) -> some View {
        let r = g.first
        let over = !r.isFinished && TaskGrid.isOvertime(r, runningFor: now.timeIntervalSince(firstSeen[r.id] ?? now), limit: limit)
        return HStack(spacing: DS.Space.s) {
            Image(systemName: expanded.contains(g.id) ? "chevron.down" : "chevron.right").font(DS.Font.caption2).foregroundStyle(.tertiary).frame(width: 10)
            Circle().fill(dot(r.status)).frame(width: 8, height: 8).help(r.state)
            Text(g.title).lineLimit(1).frame(width: 150, alignment: .leading)
                .help(g.rows.map(\.host).joined(separator: ", "))
            if over {
                Text("Still running after \(Int(limit)) s, may be waiting for input").font(DS.Font.caption).foregroundStyle(.orange).lineLimit(1)
                Spacer(minLength: 0)
                Button("Open in Terminal") { openInTerminal(r.id) }.controlSize(.small)
            } else {
                Text(r.isFinished ? r.summary : r.status == .running ? "Running…" : "Waiting")
                    .font(font.size(11)).foregroundStyle(r.isFinished ? .primary : .secondary).lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 0)
            }
            if r.isTruncated { Text("truncated").font(DS.Font.caption).foregroundStyle(.orange) }
            Text(r.exit.map { "\($0)" } ?? "–").font(DS.Font.caption.monospacedDigit()).foregroundStyle(.secondary).frame(width: 28, alignment: .trailing)
                .help("Exit code")
            Text(r.isFinished ? TaskGrid.duration(r.millis) : "").font(DS.Font.caption.monospacedDigit()).foregroundStyle(.tertiary)
                .frame(width: 64, alignment: .trailing)
        }
        .padding(.horizontal, DS.Space.m).padding(.vertical, 5)
        .background(picked.contains(g.id) ? Color.accentColor.opacity(0.18) : .clear)
        .contentShape(Rectangle())
        .onTapGesture { toggle(g) }
        .contextMenu {
            Button("Copy Output") { copy(r.output) }
            if g.isGroup { Button("Copy Hosts") { copy(g.rows.map(\.host).joined(separator: "\n")) } }
            Divider()
            ForEach(g.rows) { h in Button("Open \(h.host) in Terminal") { openInTerminal(h.id) } }
        }
        .accessibilityElement(children: .combine)
        .accessibilityIdentifier("task-grid-row-\(r.host)")
    }

    private func detail(_ g: GridGroup) -> some View {
        let r = g.first
        return VStack(alignment: .leading, spacing: DS.Space.xs) {
            if g.isGroup { Text(g.rows.map(\.host).joined(separator: ", ")).font(DS.Font.caption).foregroundStyle(.secondary) }
            ScrollView {
                Text(r.output.isEmpty ? (r.isFinished ? "(no output)" : "Output appears when the host finishes.") : r.output)
                    .font(font.size(CGFloat(appearance.terminalFontSize) - 1)).foregroundStyle(palette.fg)
                    .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .topLeading).padding(DS.Space.s)
            }
            .frame(maxHeight: 260)
            .background(palette.bg, in: RoundedRectangle(cornerRadius: 4))
            HStack {
                Button("Copy") { copy(r.output) }
                Button("Open in Terminal") { openInTerminal(r.id) }
                Spacer()
            }
            .controlSize(.small)
        }
        .padding(.horizontal, DS.Space.m).padding(.bottom, DS.Space.s).padding(.leading, 18)
    }

    /// ⌘- or ⇧-click adds the row to the selection (for Compare and Copy); a plain click opens it.
    private func toggle(_ g: GridGroup) {
        let mods = NSEvent.modifierFlags
        if mods.contains(.command) || mods.contains(.shift) {
            if picked.contains(g.id) { picked.remove(g.id) } else { picked.insert(g.id) }
            return
        }
        if expanded.contains(g.id) { expanded.remove(g.id) } else { expanded.insert(g.id) }
        picked = [g.id]
    }

    private func compare() {
        let chosen = groups.filter { picked.contains($0.id) }
        guard chosen.count == 2 else { return }
        comparing = (chosen[0], chosen[1])
    }

    private func dot(_ s: GridStatus) -> Color {
        switch s {
        case .ok: .green
        case .running: .orange
        case .failed: .red
        case .waiting: .secondary
        }
    }

    private var font: TaskGridFont { TaskGridFont(family: appearance.terminalFont.family) }

    private var palette: (fg: Color, bg: Color) {
        let id = AppearanceSettings.terminalThemeId(appearance.terminalTheme, appIsDark: colorScheme == .dark)
        guard let t = themes.theme(id) else { return (.primary, Color(nsColor: .textBackgroundColor)) }
        return (Color(rgb: t.foreground), Color(rgb: t.background))
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

/// The terminal's font family, falling back to the system monospaced font.
struct TaskGridFont {
    let family: String
    func size(_ s: CGFloat) -> Font {
        NSFont(name: family, size: s) != nil ? .custom(family, fixedSize: s) : .system(size: s, design: .monospaced)
    }
}

/// Two hosts' output side by side, lines that differ highlighted.
struct TaskCompareSheet: View {
    let left: TaskGridRow
    let right: TaskGridRow
    let font: TaskGridFont
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let lines = TaskGrid.diff(left.output, right.output)
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Label(left.host, systemImage: "minus").foregroundStyle(.red)
                Label(right.host, systemImage: "plus").foregroundStyle(.green)
                Spacer()
                Text(lines.contains { if case .same = $0 { false } else { true } } ? "" : "Identical").foregroundStyle(.secondary)
            }
            .font(DS.Font.bodyStrong).padding(DS.Space.m)
            Divider()
            ScrollView([.vertical, .horizontal]) {
                LazyVStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { _, l in line(l) }
                }
                .padding(DS.Space.s)
            }
            Divider()
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton() }.padding(DS.Space.s)
        }
        .frame(minWidth: 640, idealWidth: 760, minHeight: 360, idealHeight: 480)
    }

    private func line(_ l: DiffLine) -> some View {
        let (mark, text, tint): (String, String, Color?) = switch l {
        case .same(let s): (" ", s, nil)
        case .left(let s): ("−", s, .red)
        case .right(let s): ("+", s, .green)
        }
        return Text("\(mark) \(text)").font(font.size(12)).frame(maxWidth: .infinity, alignment: .leading)
            .background(tint.map { $0.opacity(0.15) } ?? .clear)
    }
}
