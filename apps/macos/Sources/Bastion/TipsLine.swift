import SwiftUI

/// ✕ on any tips line hides them all until the next launch.
@MainActor @Observable
final class TipsState {
    static let shared = TipsState()
    var dismissed = false
}

/// One faint, short tip at the foot of the library or inspector. It changes every few minutes
/// (one timeline tick, no other work), ✕ hides it for this run, and Settings → General →
/// Panel tips (`ui.tips`) turns it off.
struct TipsLine: View {
    enum Panel: String { case library, inspector }

    let panel: Panel
    @Environment(SettingsModel.self) private var settings
    @Environment(ShortcutsModel.self) private var shortcuts
    @State private var state = TipsState.shared
    @State private var hovering = false

    static let interval: TimeInterval = 180

    /// (text, shortcut id). A tip whose command has no key is skipped.
    static let tips: [Panel: [(String, String)]] = [
        .library: [("hides this panel", "toggle-library"), ("filters connections", "focus-search"),
                   ("opens the command palette", "palette"), ("opens a file panel on an SSH tab", "toggle-files-panel")],
        .inspector: [("hides this panel", "toggle-inspector"), ("opens a file panel on an SSH tab", "toggle-files-panel"),
                     ("opens the command palette", "palette")],
    ]

    var body: some View {
        if settings.value("ui.tips") == "true", !state.dismissed, !lines.isEmpty {
            TimelineView(.periodic(from: .now, by: Self.interval)) { context in
                HStack(spacing: DS.Space.xxs) {
                    Text("Tip: \(lines[Self.index(at: context.date, count: lines.count)])")
                        .lineLimit(1).truncationMode(.tail)
                    Spacer(minLength: 0)
                    Button { state.dismissed = true } label: { Image(systemName: "xmark").imageScale(.small).iconHitTarget() }
                        .buttonStyle(.borderless)
                        .opacity(hovering ? 1 : 0)
                        .help("Hide tips (turn off in Settings → General)")
                        .accessibilityLabel("Hide tips")
                }
                .font(DS.Font.caption2)
                .foregroundStyle(.tertiary)
            }
            .onHover { hovering = $0 }
            .uiProbe("tips-\(panel.rawValue)")
        }
    }

    /// "⌃⌘S hides this panel": tips use the current shortcuts.
    private var lines: [String] {
        (Self.tips[panel] ?? []).compactMap { text, id in
            let keys = shortcuts.display(id)
            return keys.isEmpty ? nil : "\(keys) \(text)"
        }
    }

    static func index(at date: Date, count: Int) -> Int {
        guard count > 0 else { return 0 }
        return Int(date.timeIntervalSince1970 / interval) % count
    }
}
