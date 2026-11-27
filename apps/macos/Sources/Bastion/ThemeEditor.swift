import SwiftUI
import BastionCore

/// Terminal themes from the core (`termthemes`): the bundled set and the user's own in
/// `terminal-themes.json`. `revision` moves on every edit so open terminals re-apply colours.
@MainActor @Observable
final class ThemesModel {
    private(set) var items: [TerminalThemeView] = []
    private(set) var revision = 0
    var error: String?
    /// UI driver: the theme the open editor should select.
    var scriptedSelection: String?
    private let library: ThemeLibrary?

    init(dataDir: URL) {
        do {
            library = try ThemeLibrary.open(dataDir: dataDir.path)
        } catch {
            library = nil
            self.error = "Your terminal themes could not be read: \(errorText(error))"
        }
        reload()
    }

    func reload() {
        items = library?.list() ?? []
        revision += 1
    }

    func theme(_ id: String) -> TerminalThemeView? { items.first { $0.id == id } }

    func apply(_ id: String, to terminal: Terminal) { library?.apply(id: id, terminal: terminal) }

    @discardableResult
    func duplicate(_ id: String) -> TerminalThemeView? {
        do {
            let t = try library?.duplicate(id: id)
            reload()
            return t
        } catch { self.error = errorText(error); return nil }
    }

    @discardableResult
    func save(_ theme: TerminalThemeView) -> Bool {
        do { try library?.save(theme: theme); error = nil; reload(); return true } catch { self.error = errorText(error); return false }
    }

    func remove(_ id: String) {
        do { try library?.remove(id: id); reload() } catch { self.error = errorText(error) }
    }
}

/// Theme editor: pick any theme to preview it; duplicate to make an editable copy; edit names and
/// all 18 colours with live preview and a contrast check; use one as the app default.
struct ThemeEditorView: View {
    @Environment(ThemesModel.self) private var themes
    @Environment(SettingsModel.self) private var settings
    private var dismiss = PanelDismiss()
    @Environment(\.colorScheme) private var colorScheme
    @State private var selection: String?
    @State private var draft: TerminalThemeView?

    private var selected: TerminalThemeView? { themes.theme(selection ?? "") }

    var body: some View {
        VStack(spacing: 0) {
            Text("Terminal Themes").font(DS.Font.bodyStrong)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            Divider()
            HStack(spacing: 0) {
                List(selection: $selection) {
                    Section("Bundled") { ForEach(themes.items.filter(\.bundled), id: \.id) { row($0) } }
                    let mine = themes.items.filter { !$0.bundled }
                    if !mine.isEmpty { Section("My Themes") { ForEach(mine, id: \.id) { row($0) } } }
                }
                .listStyle(.sidebar)
                .frame(width: 210)
                Divider()
                detail.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            Divider()
            HStack(spacing: DS.Space.xs) {
                if let error = themes.error { Text(error).font(DS.Font.caption).foregroundStyle(.red).lineLimit(2) }
                Spacer()
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction).dsSecondaryButton()
            }
            .padding(DS.Space.s)
        }
        .panelFrame(width: 780, height: 560)
        .onAppear { selection = selection ?? AppearanceSettings.terminalThemeId(settings.value("terminal.theme"), appIsDark: colorScheme == .dark) }
        .onChange(of: selection) { _, id in draft = themes.theme(id ?? "").flatMap { $0.bundled ? nil : $0 } }
        .onChange(of: themes.scriptedSelection) { _, id in if let id { selection = id } }
    }

    private func row(_ t: TerminalThemeView) -> some View {
        HStack(spacing: DS.Space.xs) {
            ThemeSwatch(theme: t)
            Text(t.name).lineLimit(1)
            if settings.value("terminal.theme") == t.id { Spacer(); Image(systemName: "checkmark").foregroundStyle(.secondary).help("App default") }
        }
        .tag(t.id)
    }

    @ViewBuilder private var detail: some View {
        if let base = selected {
            let shown = draft ?? base
            ScrollView {
                VStack(alignment: .leading, spacing: DS.Space.s) {
                    HStack {
                        if draft != nil {
                            TextField("Name", text: Binding(get: { draft?.name ?? "" }, set: { draft?.name = $0 }))
                                .textFieldStyle(.roundedBorder).frame(maxWidth: 260)
                        } else {
                            Text(base.name).font(DS.Font.bodyStrong)
                        }
                        Spacer()
                        Button("Duplicate") { if let t = themes.duplicate(base.id) { selection = t.id } }
                            .help("Make an editable copy")
                        if !base.bundled {
                            Button("Delete", role: .destructive) { themes.remove(base.id); selection = "bastion-dark" }
                        }
                        Button("Use as Default") { settings.set("terminal.theme", base.id) }
                            .disabled(settings.value("terminal.theme") == base.id)
                    }
                    if base.bundled {
                        Text("\(base.source) · \(base.license). Duplicate it to change colours.")
                            .font(DS.Font.caption).foregroundStyle(.secondary)
                    }
                    ThemePreview(theme: shown)
                    contrastNote(shown)
                    if draft != nil { colourGrid }
                    if let d = draft {
                        HStack {
                            Spacer()
                            Button("Revert") { draft = base }.disabled(d == base)
                            Button("Save") { _ = themes.save(d) }.keyboardShortcut(.defaultAction).dsPrimaryButton().disabled(d == base)
                        }
                    }
                }
                .padding(DS.Space.m)
            }
        } else {
            Text("Choose a theme.").foregroundStyle(.secondary).padding(DS.Space.m)
        }
    }

    private func contrastNote(_ t: TerminalThemeView) -> some View {
        let ok = t.contrast >= 4.5
        return Label(String(format: "Text contrast %.1f:1%@", t.contrast, ok ? "" : " — below 4.5:1, hard to read for some people"),
                     systemImage: ok ? "checkmark.circle" : "exclamationmark.triangle")
            .font(DS.Font.caption)
            .foregroundStyle(ok ? AnyShapeStyle(.secondary) : AnyShapeStyle(.orange))
    }

    private static let ansiNames = ["Black", "Red", "Green", "Yellow", "Blue", "Magenta", "Cyan", "White"]

    private var colourGrid: some View {
        Grid(alignment: .leading, horizontalSpacing: DS.Space.s, verticalSpacing: DS.Space.xs) {
            GridRow {
                colour("Foreground", get: { $0.foreground }, set: { $0.foreground = $1 })
                colour("Background", get: { $0.background }, set: { $0.background = $1 })
            }
            ForEach(0..<8, id: \.self) { i in
                GridRow {
                    colour(Self.ansiNames[i], get: { $0.ansi[i] }, set: { $0.ansi[i] = $1 })
                    colour("Bright \(Self.ansiNames[i].lowercased())", get: { $0.ansi[i + 8] }, set: { $0.ansi[i + 8] = $1 })
                }
            }
        }
    }

    /// Two grid cells: the label, then its well, so wells line up in a column.
    @ViewBuilder
    private func colour(_ label: String, get: @escaping (TerminalThemeView) -> UInt32, set: @escaping (inout TerminalThemeView, UInt32) -> Void) -> some View {
        Text(label)
        ColorPicker(label, selection: Binding(
            get: { Color(rgb: draft.map(get) ?? 0) },
            set: { c in if var d = draft { set(&d, c.rgb); draft = d } }), supportsOpacity: false)
            .labelsHidden()
            .padding(.trailing, DS.Space.m)
    }
}

/// Four colour chips: background with foreground, red, green and blue on it.
struct ThemeSwatch: View {
    let theme: TerminalThemeView
    var body: some View {
        HStack(spacing: 1) {
            ForEach([theme.foreground, theme.ansi[1], theme.ansi[2], theme.ansi[4]], id: \.self) { Rectangle().fill(Color(rgb: $0)).frame(width: 4, height: 10) }
        }
        .padding(3)
        .background(RoundedRectangle(cornerRadius: 3).fill(Color(rgb: theme.background)))
    }
}

/// A short shell session in the theme's colours, monospaced like the terminal.
struct ThemePreview: View {
    let theme: TerminalThemeView
    var body: some View {
        let c = { (i: Int) in Color(rgb: theme.ansi[i]) }
        VStack(alignment: .leading, spacing: 2) {
            (Text("ops@web-01").foregroundColor(c(2)) + Text(":").foregroundColor(Color(rgb: theme.foreground)) + Text("~/deploy").foregroundColor(c(4)) + Text("$ ls -l").foregroundColor(Color(rgb: theme.foreground)))
            (Text("drwxr-xr-x  ").foregroundColor(Color(rgb: theme.foreground)) + Text("releases/").foregroundColor(c(12)) + Text("  ").foregroundColor(c(0)) + Text("run.sh").foregroundColor(c(10)))
            (Text("error: ").foregroundColor(c(1)) + Text("disk 91% full  ").foregroundColor(Color(rgb: theme.foreground)) + Text("warning: ").foregroundColor(c(3)) + Text("restart pending").foregroundColor(c(11)))
            (Text("magenta ").foregroundColor(c(5)) + Text("cyan ").foregroundColor(c(6)) + Text("white ").foregroundColor(c(7)) + Text("grey ").foregroundColor(c(8)) + Text("bright magenta ").foregroundColor(c(13)) + Text("bright cyan").foregroundColor(c(14)))
            HStack(spacing: 2) { ForEach(0..<16, id: \.self) { i in Rectangle().fill(c(i)).frame(width: 18, height: 12) } }
                .padding(.top, 4)
        }
        .font(DS.Font.size(12, design: .monospaced))
        .padding(DS.Space.s)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 4).fill(Color(rgb: theme.background)))
    }
}

extension Color {
    init(rgb: UInt32) {
        self.init(red: Double(rgb >> 16 & 0xff) / 255, green: Double(rgb >> 8 & 0xff) / 255, blue: Double(rgb & 0xff) / 255)
    }

    /// sRGB 0xRRGGBB (alpha dropped).
    var rgb: UInt32 {
        let ns = NSColor(self).usingColorSpace(.sRGB) ?? .black
        let v = { (x: CGFloat) in UInt32(max(0, min(255, (x * 255).rounded()))) }
        return v(ns.redComponent) << 16 | v(ns.greenComponent) << 8 | v(ns.blueComponent)
    }
}
