import AppKit
import BastionCore
import SwiftUI

/// Tab hover previews and the tab overview (B11, `docs/plans/B11-PREVIEWS.md`). Rules and the cache are in
/// `PreviewCache.swift`. Nothing here is written to disk, the pasteboard or a log.

/// The live desktop canvases, by their session object, so a preview reads the picture already on screen.
/// RDP sends only what changed since the last read, so a second reader would break the view: never poll it here.
@MainActor
enum PreviewFrames {
    private final class WeakCanvas {
        weak var canvas: RemoteDesktopCanvas?
        init(_ canvas: RemoteDesktopCanvas) { self.canvas = canvas }
    }
    private static var canvases: [ObjectIdentifier: WeakCanvas] = [:]

    static func register(_ canvas: RemoteDesktopCanvas, key: ObjectIdentifier) {
        canvases = canvases.filter { $0.value.canvas != nil }
        canvases[key] = WeakCanvas(canvas)
    }

    static func image(for key: ObjectIdentifier) -> CGImage? { canvases[key]?.canvas?.currentImage }
}

/// What a tab's preview shows.
enum PreviewContent {
    case image(CGImage)
    case text(String)
    case none
}

@MainActor @Observable
final class TabPreviews {
    static let shared = TabPreviews()

    /// Bumped once a second while something is shown, so open previews redraw.
    private(set) var tick = 0
    /// The tab overview (⇧⌘\) is open in the main window.
    var showingOverview = false {
        didSet {
            guard showingOverview != oldValue else { return }
            if showingOverview { begin() } else { end() }
        }
    }

    /// Set by the app: `tabs.previews`, credentials lock, and the connection's own Hide tab preview.
    @ObservationIgnored var previewsOn: () -> Bool = { true }
    @ObservationIgnored var credentialsLocked: () -> Bool = { false }
    @ObservationIgnored var hidesPreview: (String) -> Bool = { _ in false }

    @ObservationIgnored private let cache = PreviewCache<UUID, CGImage>()
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var shown = 0

    /// A preview or the overview appeared: refresh once a second until the last one goes.
    func begin() {
        shown += 1
        guard timer == nil else { return }
        timer = Timer.scheduledTimer(withTimeInterval: TabPreviewRules.refreshInterval, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { self?.tick &+= 1 }
        }
    }

    func end() {
        shown = max(0, shown - 1)
        guard shown == 0 else { return }
        timer?.invalidate()
        timer = nil
    }

    /// Lock or previews turned off: drop every image at once.
    func clear() { cache.clear() }

    /// Called once by the main window. A saved vault that is not open counts as locked.
    static func configure(model: LibraryModel, credentials: CredentialsModel, settings: SettingsModel) {
        let previews = TabPreviews.shared
        previews.previewsOn = { [weak settings] in settings?.value("tabs.previews") != "false" }
        previews.credentialsLocked = { [weak credentials] in
            guard let credentials else { return true }
            return credentials.vault == nil && FileManager.default.fileExists(atPath: CredentialsModel.vaultPath.path)
        }
        previews.hidesPreview = { [weak model] id in ((try? model?.library?.noPreview(connectionId: id)) ?? nil) ?? true }
    }

    func mayShowImage(_ tab: TerminalTab, sessions: SessionsModel) -> Bool {
        TabPreviewRules.mayShowImage(previewsOn: previewsOn(),
                                     locked: credentialsLocked() || sessions.isDocumentLocked(tab),
                                     connectionHidesPreview: tab.connectionId.map(hidesPreview) ?? false)
    }

    /// The tab's preview now; reads the session at most once a second.
    func content(for tab: TerminalTab, sessions: SessionsModel) -> PreviewContent {
        guard mayShowImage(tab, sessions: sessions) else {
            cache.remove(tab.id)
            return .none
        }
        switch tab.content {
        case .terminal:
            guard let terminal = tab.terminal else { return .none }
            return .text(Self.lastLines(terminal.screen(), count: 14))
        case .rdp(let session):
            return image(tab.id, key: ObjectIdentifier(session))
        case .vnc(let viewer):
            return image(tab.id, key: ObjectIdentifier(viewer))
        default:
            return .none
        }
    }

    /// Forget tabs that closed.
    func retain(_ tabs: [TerminalTab]) { cache.retain(Set(tabs.map(\.id))) }

    private func image(_ id: UUID, key: ObjectIdentifier) -> PreviewContent {
        let now = Date()
        if cache.needsRefresh(id, now: now), let full = PreviewFrames.image(for: key), let small = Self.downscale(full) {
            cache.store(small, for: id, now: now)
        }
        return cache.image(for: id).map(PreviewContent.image) ?? .none
    }

    static func downscale(_ image: CGImage) -> CGImage? {
        let size = TabPreviewRules.scaledSize(CGSize(width: image.width, height: image.height))
        guard size.width > 0, let ctx = CGContext(data: nil, width: Int(size.width), height: Int(size.height), bitsPerComponent: 8, bytesPerRow: 0,
                                                  space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipFirst.rawValue) else { return nil }
        ctx.interpolationQuality = .medium
        ctx.draw(image, in: CGRect(origin: .zero, size: size))
        return ctx.makeImage()
    }

    /// The last `count` rows of the screen that have text, as plain text.
    static func lastLines(_ screen: TermScreen, count: Int) -> String {
        let cols = max(Int(screen.cols), 1)
        var rows = stride(from: 0, to: screen.cells.count, by: cols).map { start in
            screen.cells[start..<min(start + cols, screen.cells.count)].map { $0.text.isEmpty ? " " : $0.text }.joined()
                .replacingOccurrences(of: "\\s+$", with: "", options: .regularExpression)
        }
        while rows.last?.isEmpty == true { rows.removeLast() }
        return rows.suffix(count).joined(separator: "\n")
    }
}

/// The picture in a preview popup or an overview tile.
struct TabPreviewBody: View {
    @Environment(SessionsModel.self) private var sessions
    let tab: TerminalTab
    private var previews: TabPreviews { .shared }

    var body: some View {
        let _ = previews.tick
        switch previews.content(for: tab, sessions: sessions) {
        case .image(let image):
            Image(decorative: image, scale: 1).resizable().aspectRatio(contentMode: .fit)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .text(let text):
            Text(text).font(DS.Font.size(7, design: .monospaced)).lineLimit(14)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomLeading).padding(4)
                .background(Color(nsColor: .textBackgroundColor))
        case .none:
            Image(systemName: tab.symbol).font(DS.Font.style(.largeTitle)).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

/// Title row shared by the popup and the overview tile.
private struct TabPreviewTitle: View {
    let tab: TerminalTab
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: tab.symbol)
            Text(tab.title).lineLimit(1).truncationMode(.middle)
            Spacer(minLength: 0)
            if tab.ended { Text("Ended").foregroundStyle(.secondary) }
        }
        .font(DS.Font.callout)
    }
}

/// The hover popup: decoration only, the tab's accessible name is unchanged.
struct TabPreviewCard: View {
    let tab: TerminalTab
    static let width: CGFloat = 320

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            TabPreviewTitle(tab: tab)
            TabPreviewBody(tab: tab)
                .frame(width: Self.width - 16, height: (Self.width - 16) * 10 / 16)
                .clipShape(RoundedRectangle(cornerRadius: 4))
        }
        .padding(8)
        .onAppear { TabPreviews.shared.begin() }
        .onDisappear { TabPreviews.shared.end() }
        .accessibilityHidden(true)
    }
}

/// Shows the preview after the pointer rests on a tab that is not selected.
private struct TabHoverPreview: ViewModifier {
    @Environment(SettingsModel.self) private var settings
    let tab: TerminalTab
    let isSelected: Bool
    @State private var showing = false
    @State private var pending: Task<Void, Never>?

    func body(content: Content) -> some View {
        content
            .onHover { inside in
                pending?.cancel()
                guard inside, !isSelected, settings.value("tabs.previews") != "false" else { showing = false; return }
                pending = Task { @MainActor in
                    try? await Task.sleep(for: .seconds(TabPreviewRules.hoverDelay))
                    if !Task.isCancelled { showing = true }
                }
            }
            .onChange(of: isSelected) { _, selected in if selected { pending?.cancel(); showing = false } }
            .popover(isPresented: $showing, arrowEdge: .bottom) { TabPreviewCard(tab: tab) }
    }
}

extension View {
    func tabHoverPreview(_ tab: TerminalTab, isSelected: Bool) -> some View {
        modifier(TabHoverPreview(tab: tab, isSelected: isSelected))
    }
}

/// Every open tab of the main window as a grid of tiles. Arrows move, Return opens, Esc closes, typing filters.
struct TabOverview: View {
    @Environment(SessionsModel.self) private var sessions
    @State private var index = 0
    @State private var filter = ""
    @FocusState private var focused: Bool
    private var previews: TabPreviews { .shared }

    private var tabs: [TerminalTab] {
        let all = sessions.mainTabs
        guard !filter.isEmpty else { return all }
        return all.filter { $0.title.localizedCaseInsensitiveContains(filter) }
    }

    var body: some View {
        GeometryReader { geo in
            let columns = TabPreviewRules.columns(forWidth: geo.size.width - 32)
            let shown = tabs
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text("Tab Overview").font(DS.Font.headline)
                    if !filter.isEmpty { Text("“\(filter)”").foregroundStyle(.secondary).lineLimit(1) }
                    Spacer()
                    Button("Done") { previews.showingOverview = false }.keyboardShortcut(.cancelAction).dsSecondaryButton()
                }
                if shown.isEmpty {
                    Text(sessions.mainTabs.isEmpty ? "No open sessions" : "No tab matches").foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else {
                    ScrollViewReader { proxy in
                        ScrollView {
                            LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: columns), spacing: 12) {
                                ForEach(Array(shown.enumerated()), id: \.element.id) { offset, tab in
                                    tile(tab, selected: offset == index).id(tab.id)
                                        .onTapGesture { open(tab) }
                                }
                            }
                        }
                        .onChange(of: index) { _, i in if shown.indices.contains(i) { proxy.scrollTo(shown[i].id) } }
                    }
                }
            }
            .padding(16)
            .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
            .background(Color(nsColor: .windowBackgroundColor))
            .focusable()
            .focusEffectDisabled()
            .focused($focused)
            .onKeyPress { press in key(press, columns: columns, count: shown.count) }
            .onAppear {
                focused = true
                index = shown.firstIndex { $0.id == sessions.selected } ?? 0
            }
            .accessibilityElement(children: .contain)
            .accessibilityLabel("Tab Overview")
        }
    }

    private func tile(_ tab: TerminalTab, selected: Bool) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            TabPreviewTitle(tab: tab)
            TabPreviewBody(tab: tab).aspectRatio(16 / 10, contentMode: .fit).clipShape(RoundedRectangle(cornerRadius: 4))
        }
        .padding(8)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(selected ? Color.accentColor : .clear, lineWidth: 2))
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? [.isButton, .isSelected] : .isButton)
        .accessibilityAction { open(tab) }
    }

    private func open(_ tab: TerminalTab) {
        sessions.selected = tab.id
        previews.showingOverview = false
    }

    private func key(_ press: KeyPress, columns: Int, count: Int) -> KeyPress.Result {
        switch press.key {
        case .leftArrow: index = TabPreviewRules.move(index, dx: -1, dy: 0, count: count, columns: columns)
        case .rightArrow: index = TabPreviewRules.move(index, dx: 1, dy: 0, count: count, columns: columns)
        case .upArrow: index = TabPreviewRules.move(index, dx: 0, dy: -1, count: count, columns: columns)
        case .downArrow: index = TabPreviewRules.move(index, dx: 0, dy: 1, count: count, columns: columns)
        case .return:
            let shown = tabs
            if shown.indices.contains(index) { open(shown[index]) }
        case .escape: previews.showingOverview = false
        case .delete:
            filter = String(filter.dropLast())
            index = 0
        default:
            guard press.modifiers.isDisjoint(with: [.command, .control]), !press.characters.isEmpty,
                  press.characters.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }) else { return .ignored }
            filter.append(press.characters)
            index = 0
        }
        return .handled
    }
}
