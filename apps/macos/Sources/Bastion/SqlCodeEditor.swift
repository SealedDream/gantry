import AppKit
import SwiftUI
import BastionCore

/// PLUG-06c (Native Mac): a plugin's `code-editor` component. An `NSTextView` coloured by the
/// core's tokenizer one line at a time (`highlightLine`, re-colouring down from an edit until a
/// line's end state is unchanged), with completions asked of the plugin and filtered by the core
/// (`completionContext`, `completionsRank`). Colours are system colours, so the editor follows the
/// app's light or dark appearance. Keys: ⌃Space completions, ↑↓ choose, ↩ or ⇥ insert, Esc close,
/// ⌘↩ run (the selection, else all), ⌘/ comment lines.
struct PluginCodeEditor: View {
    @ObservedObject var model: PluginViewModel
    let node: Int, language: String, initial: String, readOnly: Bool
    @StateObject private var editor = SqlEditorController()

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ZStack(alignment: .topLeading) {
                SqlTextViewHost(editor: editor)
                if editor.popupVisible {
                    SqlCompletionPopup(editor: editor)
                        .offset(x: editor.anchor.x, y: editor.anchor.y)
                }
            }
            .frame(minHeight: 120)
            .overlay(Rectangle().strokeBorder(Color(nsColor: .separatorColor)))
            if !readOnly {
                HStack(spacing: 8) {
                    Button("Run") { editor.run() }
                        .keyboardShortcut(.return, modifiers: .command)
                        .help("Run the selection, or all (⌘↩)")
                    Text("⌃Space completions · ⌘/ comment").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
            }
        }
        .onAppear {
            editor.configure(language: language, text: initial, readOnly: readOnly,
                             ask: { [weak model] text, offset in model?.askCompletions(node: node, text: text, offset: offset) ?? -1 },
                             run: { [weak model] text in model?.input(node: node, ["kind": "run", "value": text]) })
        }
        .onChange(of: initial) { _, new in editor.pluginText(new) }
        .onReceive(model.$completions) { all in
            if let c = all[node] { editor.receive(ask: c.ask, items: c.items) }
        }
    }
}

/// The completion list, under the caret. Rows are at least 24 pt for the pointer.
struct SqlCompletionPopup: View {
    @ObservedObject var editor: SqlEditorController
    static let width: CGFloat = 320
    static let rowHeight: CGFloat = 24
    static let maxRows = 8

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(spacing: 0) {
                    ForEach(Array(editor.shown.enumerated()), id: \.offset) { i, item in
                        HStack(spacing: 8) {
                            Text(item.label).font(.system(.body, design: .monospaced)).lineLimit(1)
                            Spacer(minLength: 8)
                            Text(item.detail).font(.caption).foregroundStyle(i == editor.selected ? Color.white.opacity(0.85) : .secondary).lineLimit(1)
                        }
                        .padding(.horizontal, 8)
                        .frame(height: Self.rowHeight)
                        .foregroundStyle(i == editor.selected ? Color.white : Color.primary)
                        .background(i == editor.selected ? Color.accentColor : Color.clear)
                        .contentShape(Rectangle())
                        .onTapGesture { editor.accept(i) }
                        .id(i)
                        .help(item.detail)
                    }
                }
            }
            .onChange(of: editor.selected) { _, i in proxy.scrollTo(i) }
        }
        .frame(width: Self.width, height: Self.rowHeight * CGFloat(min(editor.shown.count, Self.maxRows)))
        .background(Color(nsColor: .controlBackgroundColor))
        .overlay(Rectangle().strokeBorder(Color(nsColor: .separatorColor)))
        .shadow(color: .black.opacity(0.15), radius: 4, y: 2)
        .accessibilityIdentifier("plugin-completions")
    }
}

struct SqlTextViewHost: NSViewRepresentable {
    let editor: SqlEditorController
    func makeNSView(context: Context) -> NSScrollView { editor.scrollView }
    func updateNSView(_ nsView: NSScrollView, context: Context) {}
}

/// Passes ⌃Space, ⌘/ and ⌘↩ to the controller; arrows, ↩, ⇥ and Esc go through `doCommandBy`.
final class SqlTextView: NSTextView {
    weak var editor: SqlEditorController?
    static let spaceKey: UInt16 = 49

    override func keyDown(with event: NSEvent) {
        let mods = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        if mods == .control, event.keyCode == Self.spaceKey { editor?.requestCompletions(explicit: true); return }
        if mods == .command, event.charactersIgnoringModifiers == "/" { editor?.toggleComment(); return }
        super.keyDown(with: event)
    }

    /// ⌘↩ runs the query while the editor has focus. Views see key equivalents before the menu, so Session › Connect
    /// (default-action, ⌘↩) no longer takes it and re-selects the plugin tab instead of running (PLUG-PG-REDO-MAC-KEY).
    override func performKeyEquivalent(with event: NSEvent) -> Bool {
        let mods = event.modifierFlags.intersection(.deviceIndependentFlagsMask)
        if mods == .command, event.keyCode == Self.returnKey, window?.firstResponder === self, let editor {
            editor.run()
            return true
        }
        return super.performKeyEquivalent(with: event)
    }
    static let returnKey: UInt16 = 36

    override func resignFirstResponder() -> Bool {
        editor?.hidePopup()
        return super.resignFirstResponder()
    }
}

@MainActor
final class SqlEditorController: NSObject, ObservableObject, NSTextStorageDelegate, NSTextViewDelegate {
    @Published private(set) var popupVisible = false
    @Published private(set) var shown: [CompletionItem] = []
    @Published private(set) var selected = 0
    /// Top-left of the popup in the editor's frame (top-left origin): just under the caret.
    @Published private(set) var anchor = CGPoint.zero

    let scrollView: NSScrollView
    let textView: SqlTextView
    private var language = "sql"
    private var readOnly = false
    private var ask: (String, UInt32) -> Int = { _, _ in -1 }
    private var runAction: (String) -> Void = { _ in }
    private var configured = false
    private var lastPluginText = ""

    /// End state of every line, and where each line starts (UTF-16).
    private var states: [String] = []
    private var starts: [Int] = [0]
    private var colouring = false

    private var pendingAsk: Int?
    private var askStart: Int?
    private var baseItems: [CompletionItem] = []
    private var context: CompletionContextView?
    private var lastTyped = ""

    /// The editor configured last (the UI driver reads it; nothing else needs it).
    static weak var current: SqlEditorController?

    static let font = NSFont.monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)

    override init() {
        scrollView = NSTextView.scrollableTextView()
        let tv = SqlTextView(frame: scrollView.contentView.bounds)
        tv.autoresizingMask = [.width]
        tv.isVerticallyResizable = true
        tv.textContainer?.widthTracksTextView = true
        tv.isRichText = false
        tv.allowsUndo = true
        tv.isAutomaticQuoteSubstitutionEnabled = false
        tv.isAutomaticDashSubstitutionEnabled = false
        tv.isAutomaticTextReplacementEnabled = false
        tv.isAutomaticSpellingCorrectionEnabled = false
        tv.isContinuousSpellCheckingEnabled = false
        tv.smartInsertDeleteEnabled = false
        tv.font = Self.font
        tv.textColor = .textColor
        tv.backgroundColor = .textBackgroundColor
        tv.textContainerInset = NSSize(width: 4, height: 4)
        tv.setAccessibilityIdentifier("plugin-code-editor")
        textView = tv
        super.init()
        scrollView.documentView = tv
        scrollView.hasVerticalScroller = true
        scrollView.borderType = .noBorder
        tv.editor = self
        tv.delegate = self
        tv.textStorage?.delegate = self
    }

    func configure(language: String, text: String, readOnly: Bool, ask: @escaping (String, UInt32) -> Int, run: @escaping (String) -> Void) {
        self.language = language.isEmpty ? "sql" : language
        self.readOnly = readOnly
        self.ask = ask
        self.runAction = run
        textView.isEditable = !readOnly
        Self.current = self
        guard !configured else { return }
        configured = true
        lastPluginText = text
        textView.string = text // colours through the storage delegate
    }

    /// The plugin sent new text: take it unless the user has changed the text since the last one.
    func pluginText(_ text: String) {
        guard textView.string == lastPluginText else { lastPluginText = text; return }
        lastPluginText = text
        textView.string = text
    }

    var text: String { textView.string }

    func run() { runAction(SqlEditorLogic.runText(textView.string, selection: textView.selectedRange())) }

    func toggleComment() {
        guard !readOnly else { return }
        let sel = textView.selectedRange()
        let ns = textView.string as NSString
        let r = SqlEditorLogic.toggleComment(textView.string, selection: sel)
        let changed = ((r.text as NSString).length - ns.length)
        // Replace the whole touched block through the text view, so ⌘Z undoes it.
        let newBlock = (r.text as NSString).substring(with: NSRange(location: r.lines.location, length: r.lines.length))
        let oldRange = NSRange(location: r.lines.location, length: r.lines.length - changed)
        guard textView.shouldChangeText(in: oldRange, replacementString: newBlock) else { return }
        textView.textStorage?.replaceCharacters(in: oldRange, with: newBlock)
        textView.didChangeText()
        textView.setSelectedRange(r.lines.length > 0 ? NSRange(location: r.lines.location, length: max(0, r.lines.length - (newBlock.hasSuffix("\n") ? 1 : 0))) : sel)
    }

    // MARK: colouring

    nonisolated func textStorage(_ textStorage: NSTextStorage, didProcessEditing editedMask: NSTextStorageEditActions, range editedRange: NSRange, changeInLength delta: Int) {
        guard editedMask.contains(.editedCharacters) else { return }
        // The text system calls this on the main thread, for the text view this controller owns.
        nonisolated(unsafe) let storage = textStorage
        MainActor.assumeIsolated { colour(storage, edited: editedRange) }
    }

    private func colour(_ storage: NSTextStorage, edited: NSRange) {
        guard !colouring else { return }
        colouring = true
        defer { colouring = false }
        let ns = storage.string as NSString
        let newStarts = SqlEditorLogic.lineStarts(ns)
        let delta = newStarts.count - starts.count
        let first = SqlEditorLogic.line(of: edited.location, in: newStarts)
        let lastNew = SqlEditorLogic.line(of: NSMaxRange(edited), in: newStarts)
        let spliced = states.count == starts.count ? SqlEditorLogic.splice(states, first: first, lastNew: lastNew, delta: delta) : []
        let whole = spliced.count != newStarts.count
        states = whole ? Array(repeating: "\u{1}", count: newStarts.count) : spliced
        starts = newStarts
        let lang = language
        let result = SqlEditorLogic.recolour(states: states, first: whole ? 0 : first, mustReach: whole ? newStarts.count - 1 : lastNew) { i, before in
            let range = lineRange(i, ns)
            let spans = highlightLine(language: lang, line: ns.substring(with: range), state: before)
            storage.addAttribute(.foregroundColor, value: NSColor.textColor, range: range)
            storage.removeAttribute(.underlineStyle, range: range)
            for t in spans.tokens {
                let r = NSRange(location: range.location + Int(t.utf16Start), length: Int(t.utf16Len))
                guard NSMaxRange(r) <= NSMaxRange(range) else { continue }
                let role = SqlEditorLogic.role(t.kind)
                if let c = Self.colour(role) { storage.addAttribute(.foregroundColor, value: c, range: r) }
                if role == .error { storage.addAttribute(.underlineStyle, value: NSUnderlineStyle.single.rawValue, range: r) }
            }
            return spans.endState
        }
        states = result.states
    }

    private func lineRange(_ i: Int, _ ns: NSString) -> NSRange {
        let s = starts[i]
        let e = i + 1 < starts.count ? starts[i + 1] - 1 : ns.length
        return NSRange(location: s, length: max(0, e - s))
    }

    static func colour(_ role: SqlEditorLogic.Role) -> NSColor? {
        switch role {
        case .keyword: .systemPurple
        case .string: .systemRed
        case .number: .systemBlue
        case .comment: .systemGreen
        case .type: .systemTeal
        case .function: .systemIndigo
        case .parameter: .systemOrange
        case .error: .systemRed
        case .plain: nil
        }
    }

    // MARK: completions

    nonisolated func textView(_ textView: NSTextView, shouldChangeTextIn affectedCharRange: NSRange, replacementString: String?) -> Bool {
        MainActor.assumeIsolated { lastTyped = replacementString ?? "" }
        return true
    }

    nonisolated func textDidChange(_ notification: Notification) {
        MainActor.assumeIsolated {
            let typed = lastTyped
            lastTyped = ""
            if SqlEditorLogic.triggersCompletion(typed) || popupVisible {
                requestCompletions(explicit: false)
            } else {
                hidePopup()
            }
        }
    }

    nonisolated func textView(_ textView: NSTextView, doCommandBy selector: Selector) -> Bool {
        MainActor.assumeIsolated { handle(selector) }
    }

    func handle(_ selector: Selector) -> Bool {
        guard popupVisible else { return false }
        switch selector {
        case #selector(NSResponder.moveUp(_:)): selected = SqlEditorLogic.move(selected, by: -1, count: shown.count)
        case #selector(NSResponder.moveDown(_:)): selected = SqlEditorLogic.move(selected, by: 1, count: shown.count)
        case #selector(NSResponder.insertNewline(_:)), #selector(NSResponder.insertTab(_:)): accept(selected)
        case #selector(NSResponder.cancelOperation(_:)): hidePopup()
        case #selector(NSResponder.moveLeft(_:)), #selector(NSResponder.moveRight(_:)): hidePopup(); return false
        default: return false
        }
        return true
    }

    func requestCompletions(explicit: Bool) {
        guard !readOnly else { return }
        let cursor = textView.selectedRange()
        guard cursor.length == 0 else { hidePopup(); return }
        let full = textView.string
        let ctx = completionContext(language: language, text: full, cursorUtf16: UInt64(cursor.location))
        guard ctx.ask, explicit || !ctx.prefix.isEmpty else { hidePopup(); return }
        context = ctx
        let start = Int(ctx.replaceUtf16Start)
        if explicit || SqlEditorLogic.needsNewAsk(previousStart: askStart, start: start) {
            askStart = start
            baseItems = []
            let id = ask(full, ctx.charOffset)
            pendingAsk = id >= 0 ? id : nil
            if pendingAsk == nil { hidePopup() }
        } else {
            rerank()
        }
    }

    func receive(ask id: Int, items: [CompletionItem]) {
        guard id == pendingAsk else { return }
        pendingAsk = nil
        baseItems = items
        rerank()
    }

    private func rerank() {
        guard let ctx = context, !baseItems.isEmpty else { if pendingAsk == nil { hidePopup() }; return }
        shown = completionsRank(items: baseItems, prefix: ctx.prefix)
        selected = 0
        guard !shown.isEmpty else { hidePopup(); return }
        anchor = caretAnchor()
        popupVisible = true
    }

    func accept(_ index: Int) {
        guard index >= 0, index < shown.count, let ctx = context else { return }
        let item = shown[index]
        let range = NSRange(location: Int(ctx.replaceUtf16Start), length: Int(ctx.replaceUtf16Len))
        hidePopup()
        lastTyped = ""
        textView.insertText(item.insert, replacementRange: range)
        hidePopup()
    }

    func hidePopup() {
        popupVisible = false
        shown = []
        askStart = nil
        pendingAsk = nil
        baseItems = []
    }

    private func caretAnchor() -> CGPoint {
        guard let lm = textView.layoutManager, let tc = textView.textContainer else { return .zero }
        let loc = textView.selectedRange().location
        let glyph = lm.glyphIndexForCharacter(at: max(0, min(loc, (textView.string as NSString).length)))
        let rect = lm.boundingRect(forGlyphRange: NSRange(location: glyph, length: 0), in: tc)
        let origin = textView.textContainerOrigin
        let inText = NSRect(x: rect.minX + origin.x, y: rect.maxY + origin.y, width: 1, height: 1)
        let clip = scrollView.contentView
        let p = textView.convert(inText.origin, to: clip)
        let visible = CGPoint(x: p.x - clip.bounds.origin.x, y: p.y - clip.bounds.origin.y)
        let maxX = max(0, scrollView.bounds.width - SqlCompletionPopup.width)
        return CGPoint(x: min(max(0, visible.x), maxX), y: max(0, visible.y + 2))
    }
}

#if BASTION_TEST_HOOKS
extension SqlEditorController {
    /// The role drawn at UTF-16 offset `at` (from its colour), for the UI driver.
    func role(at: Int) -> String {
        guard let storage = textView.textStorage, at < storage.length else { return "none" }
        let c = storage.attribute(.foregroundColor, at: at, effectiveRange: nil) as? NSColor
        let roles: [SqlEditorLogic.Role] = [.keyword, .string, .number, .comment, .type, .function, .parameter]
        return roles.first { Self.colour($0) == c }.map { "\($0)" } ?? "plain"
    }
}
#endif
