#if BASTION_TEST_HOOKS
import AppKit

// nm-fit (owner 2026-11-05 (d)): layout-fit checks over every visible window of the app (main window,
// sheets, popovers, panels, alerts). SwiftUI builds no accessibility tree without an assistive client,
// but on macOS its buttons, pop-ups, segmented controls and many labels are AppKit views, so the
// checks walk the view tree. A check fails on:
//   CLIPPED   a control, label, icon or drawn text reaching past its window (also where its scroll
//             view runs past the window), past the sides of the scroll view it sits in, or partly
//             or wholly outside the non-scrolling view that clips it
//   SMALL     a button, toolbar item, segment or pop-up whose hit target is under DS.Size.minHitTarget
//             (24 pt); push buttons keep AppKit's fixed bezel height for their control size
//   OVERLAP   two controls whose frames cross without one holding the other
//   TRUNCATED a control title or one-line label narrower than its natural size
//   WRAPPED   a short label (a few words) broken over lines
// SwiftUI `Text` draws in CGDrawingViews whose string AppKit cannot read: those are checked for
// clipping only. `fit <name>` logs `FIT <name> … ok` or one FAIL line per problem and announces a
// capture of each failing window (`fit-<name>-<n>.png`), taken by the driver (`UIDriverCapture`).
extension Driver {
    @MainActor struct FitElement {
        let kind: String
        let text: String
        /// Window coordinates (origin bottom left).
        let frame: NSRect
        /// The visible part of the scroll view it sits in (rows may be scrolled out of view).
        let scroll: NSRect?
        /// That scroll view scrolls sideways (the tab strip), so content may leave its sides too.
        var scrollsSideways = false
        /// The frame of the nearest ancestor that clips (not the hosting view's whole width).
        let holder: NSRect?
        let view: NSView
        /// Inside a toolbar item: NSToolbar sizes the parts (split-button chevrons, bezels) and the
        /// item viewer takes the click, so the viewer is the hit target.
        var inToolbar = false
        var isControl: Bool { Driver.fitControlKinds.contains(kind) }
    }

    /// AppKit's smallest bezel (push button, pop-up, segment at .small) is 16 pt high.
    static let fitBezelMinHeight: CGFloat = 15.5
    /// A pop-up's bezel padding and up/down arrows beside its title.
    static let fitPopupChrome: CGFloat = 22
    nonisolated static let fitControlKinds: Set<String> = ["button", "icon-button", "popup", "segment", "toolbar-item"]
    /// Labels with more words than this are prose and may wrap.
    static let fitShortLabelWords = 4
    static let fitTolerance: CGFloat = 1

    func fitStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "fit": await fit(arg.isEmpty ? "unnamed" : arg)
        case "even": await even(arg.isEmpty ? "unnamed" : arg)
        case "fit-menus": write(fitMenus())
        case "open-row":
            // `open-row Triggers`: click a row that opens a page and clears its own selection (no selection check).
            guard let row = row(named: arg), let outline else { write("FAIL open-row \(arg): no row"); return true }
            outline.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            await settle()
            write("OPEN-ROW \(arg) -> selected \(selectedNames().isEmpty ? "none" : selectedNames())")
        case "expect-panel":
            // `expect-panel triggers`: the in-window page that is open now (raw value of WindowPanel).
            await settle(0.4)
            let open = commands.panel?.rawValue ?? "none"
            write((open == arg ? "" : "FAIL ") + "PANEL \(open) expected=\(arg)")
        case "fit-views":
            // Debug: view classes in every visible window, by count.
            var counts: [String: Int] = [:]
            func walk(_ v: NSView) { counts[String(describing: type(of: v)).prefix(60).description, default: 0] += 1; v.subviews.forEach(walk) }
            NSApp.windows.filter(\.isVisible).forEach { w in w.contentView?.superview.map(walk) }
            write("FIT-VIEWS " + counts.sorted { $0.value > $1.value }.map { "\($0.key)=\($0.value)" }.joined(separator: " "))
            write("AX trusted=\(AXIsProcessTrusted())")
        case "dismiss":
            // The New Connection form in the inspector closes as its Cancel does.
            if commands.addConnection != nil { commands.addConnection = nil; await settle(0.4) }
            // A manager panel in the window closes as Escape does, once no sheet sits on top of it.
            if commands.panel != nil && window?.attachedSheet == nil { commands.panel = nil; await settle(0.4) }
            // Escape to whatever sheet or popover is open (none is fine), then close what is left.
            if let w = window?.attachedSheet ?? popover {
                w.makeKey()
                appKey("escape")
                await settle(0.5)
                // A SwiftUI sheet closes through its own buttons, not endSheet.
                // Its buttons carry no AppKit title; Escape as a key equivalent reaches the cancel action
                // even while the app is in the background (driver runs).
                for _ in 0..<3 { guard let s = window?.attachedSheet,
                   let esc = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                              windowNumber: s.windowNumber, context: nil, characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}",
                                              isARepeat: false, keyCode: 53)
                    else { break }
                    _ = s.performKeyEquivalent(with: esc)
                    await settle(0.3)
                    // A consumed key equivalent need not close a SwiftUI sheet (background runs): click ⎋.
                    if window?.attachedSheet === s {
                        // ⎋ button first, else the sheet's own Done / Cancel / Close (SwiftUI titles
                        // live in the accessibility label, not the AppKit title).
                        let buttons = s.contentView?.allSubviews(of: NSButton.self).filter(\.isEnabled) ?? []
                        let close = buttons.first { $0.keyEquivalent == "\u{1b}" }
                            ?? buttons.first { ["Done", "Cancel", "Close"].contains($0.title.isEmpty ? ($0.accessibilityLabel() ?? "") : $0.title) }
                        close?.performClick(nil)
                        // Still open (no such button, or a background app ignores the click): the
                        // responder chain's cancelOperation, which SwiftUI sheets map to dismiss.
                        await settle(0.3)
                        if window?.attachedSheet === s, s.isVisible {
                            s.firstResponder?.tryToPerform(#selector(NSResponder.cancelOperation(_:)), with: nil)
                        }
                    }
                    await settle(0.3)
                }
                popover?.close()
            }
            await settle(0.3)
            // A sheet still open breaks every later step (an alert queues behind it): say so.
            let left = window?.attachedSheet
            write("\(left != nil ? "FAIL " : "")DISMISS -> sheet \(left.map { "shown " + sheetText($0) } ?? "none"), popover \(popover != nil ? "shown" : "none")")
        case "ui-zoom":
            // `ui-zoom in|out|reset|<percent>|` (empty logs only), then the scale in effect.
            switch arg {
            case "in": UIZoom.shared.zoomIn()
            case "out": UIZoom.shared.zoomOut()
            case "reset": UIZoom.shared.reset()
            case "": break
            default: UIZoom.shared.set((Double(arg) ?? 100) / 100)
            }
            await settle(0.6)
            write("UI-ZOOM \(UIZoom.shared.percent)% saved=\(Int(UserDefaults.standard.double(forKey: UIZoom.defaultsKey) * 100))% controls=\(UIZoom.shared.controlSize)")
        case "zoom-key":
            // `zoom-key cmd+=|cmd+shift+=|cmd+-|cmd+shift+-|cmd+0|cmd+kp+|cmd+kp-|cmd+kp0`: a key down
            // through the event queue, so the key monitor, menus and terminal see it as typed.
            guard postZoomKey(arg) else { write("FAIL zoom-key \(arg)"); return true }
            await settle(0.8)
            let v = focusedTerminalView()
            write("ZOOM-KEY \(arg) -> ui \(UIZoom.shared.percent)% terminal-zoom \(UIDriver.services?.sessions.selectedTab?.zoom ?? 0) font \(Int(v?.fontSize ?? 0))pt grid \(v?.gridDescription ?? "-")")
        case "zoom-expect":
            // `zoom-expect <ui percent> <terminal zoom steps>`: FAIL unless both are in effect.
            let want = arg.split(separator: " ").compactMap { Int($0) }
            let term = UIDriver.services?.sessions.selectedTab?.zoom ?? 0
            let ok = want.count == 2 && want[0] == UIZoom.shared.percent && want[1] == term
            write("\(ok ? "" : "FAIL ")ZOOM-EXPECT want \(arg) have \(UIZoom.shared.percent) \(term)")
        case "inspector-width":
            // `inspector-width min|max|<pt>`: drag the inspector column's divider there (SwiftUI clamps).
            let target = arg == "min" ? DS.Size.inspectorMin : arg == "max" ? DS.Size.inspectorMax : CGFloat(Double(arg) ?? 300)
            guard let split = inspectorSplit() else {
                // Below the room an inspector column needs on macOS 26+ it draws as an overlay (#1104): no
                // divider to drag, and that is the expected layout, not a failure.
                let room = Int(ContentView.inspectorColumnRoom(inspector: DS.Size.inspectorMin))
                if commands.tree.inspectorPresented {
                    write("INSPECTOR-WIDTH \(arg) -> overlay (no column below \(room) pt)")
                } else if commands.tree.inspectorHiddenByWidth {
                    write("INSPECTOR-WIDTH \(arg) -> hidden by the window width (library + \(room) pt needed)")
                } else {
                    write("FAIL inspector-width: no inspector column")
                }
                return true
            }
            let n = split.arrangedSubviews.count
            split.setPosition(split.bounds.width - target - split.dividerThickness, ofDividerAt: n - 2)
            split.layoutSubtreeIfNeeded()
            await settle(0.5)
            write("INSPECTOR-WIDTH \(arg) -> \(Int(split.arrangedSubviews[n - 1].frame.width)) pt")
        case "term-pty": await termPty()
        default: return false
        }
        return true
    }

    private func fit(_ name: String) async {
        await settle(0.3)
        if ProcessInfo.processInfo.environment["BASTION_FIT_EVEN"] == "1" { await even(name) }
        var failures = 0
        let windows = NSApp.windows.filter { $0.isVisible && $0.frame.width > 40 && $0.frame.height > 20 }
        for (i, w) in windows.enumerated() {
            let problems = fitProblems(in: w)
            failures += problems.count
            let title = w.title.isEmpty ? (w.identifier?.rawValue ?? String(describing: type(of: w))) : w.title
            problems.forEach { write("FAIL FIT \(name) [\(title) \(Int(w.frame.width))x\(Int(w.frame.height))] \($0)") }
            guard !problems.isEmpty else { continue }
            await capture(w, "fit-\(name)-\(i)")
        }
        let checked = windows.map { fitElements(in: $0).count }.reduce(0, +)
        write("FIT \(name) zoom=\(UIZoom.shared.percent)% windows=\(windows.count) elements=\(checked) \(failures == 0 ? "ok" : "\(failures) problems")")
    }

    /// The split view whose last column is the inspector (its width within the inspector's range).
    private func inspectorSplit() -> NSSplitView? {
        let range = (DS.Size.inspectorMin - 2)...(DS.Size.inspectorMax + 2)
        return window?.contentView?.allSubviews(of: NSSplitView.self).first { split in
            guard split.arrangedSubviews.count >= 2, let last = split.arrangedSubviews.last, !last.isHidden else { return false }
            return range.contains(last.frame.width) && split.isVertical
        }
    }

    /// The PTY's own size as the shell sees it (`stty size`), against the drawn grid.
    private func termPty() async {
        guard let v = focusedTerminalView(), let t = UIDriver.services?.sessions.selectedTab?.terminal else { return write("FAIL term-pty") }
        let marker = "PTY\(Int.random(in: 1000...9999))"
        try? t.write(bytes: Data("printf '\(marker)=%s\\n' \"$(stty size | tr ' ' x)\"\r".utf8))
        var seen: String?
        for _ in 0..<40 where seen == nil {
            await settle(0.25)
            // The typed line shows the marker too; the answer is the one followed by digits.
            for line in Self.screenText(t).components(separatedBy: "\n") {
                guard let r = line.range(of: "\(marker)=") else { continue }
                let rest = line[r.upperBound...].prefix { $0.isNumber || $0 == "x" }
                if rest.contains("x"), rest.first?.isNumber == true { seen = String(rest) }
            }
        }
        // stty prints rows then columns; the grid is columns x rows.
        let parts = (seen ?? "").split(separator: "x")
        let pty = parts.count == 2 ? "\(parts[1])x\(parts[0])" : "-"
        write("\(pty == v.gridDescription ? "" : "FAIL ")TERM-PTY grid \(v.gridDescription) pty \(pty) font \(Int(v.fontSize))pt")
    }

    private func postZoomKey(_ spec: String) -> Bool {
        guard spec.hasPrefix("cmd+") else { return false }
        var rest = String(spec.dropFirst(4))
        var flags: NSEvent.ModifierFlags = [.command]
        if rest.hasPrefix("shift+") { flags.insert(.shift); rest.removeFirst(6) }
        // key code, characters as typed (a shifted = types + on a US keyboard).
        let table: [String: (UInt16, String)] = ["=": (24, "="), "-": (27, "-"), "0": (29, "0"), "kp+": (69, "+"), "kp-": (78, "-"), "kp0": (82, "0")]
        guard var (code, chars) = table[rest] else { return false }
        if rest.hasPrefix("kp") { flags.insert(.numericPad) }
        if flags.contains(.shift) { chars = ["=": "+", "-": "_"][chars] ?? chars }
        let target = NSApp.keyWindow ?? window
        guard let e = NSEvent.keyEvent(with: .keyDown, location: .zero, modifierFlags: flags, timestamp: ProcessInfo.processInfo.systemUptime,
                                       windowNumber: target?.windowNumber ?? 0, context: nil, characters: chars,
                                       charactersIgnoringModifiers: chars, isARepeat: false, keyCode: code) else { return false }
        NSApp.postEvent(e, atStart: false)
        return true
    }

    /// Menu bar: every item titled, and no key equivalent used twice (one of them would never fire).
    private func fitMenus() -> String {
        guard let bar = NSApp.mainMenu else { return "FAIL FIT-MENUS no menu bar" }
        var seen: [String: String] = [:]
        var problems: [String] = []
        var count = 0
        // MENU-OVERFLOW: AppKit scrolls a menu taller than the screen and keeps it on screen; the check is that no
        // submenu is taller than the visible screen AND has items that cannot be reached (none are: reported as notes).
        let room = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame.height ?? 800
        var tall: [String] = []
        func walk(_ menu: NSMenu, _ path: String) {
            menu.update()
            if menu.size.height > room { tall.append("\(path) (\(Int(menu.size.height)) > \(Int(room)) pt, scrolls)") }
            for item in menu.items where !item.isSeparatorItem && !item.isHidden {
                count += 1
                let here = "\(path) > \(item.title)"
                if item.title.isEmpty, item.view == nil, item.image == nil { problems.append("untitled item in \(path)") }
                if !item.keyEquivalent.isEmpty, !item.isAlternate {
                    let key = "\(item.keyEquivalentModifierMask.intersection(.deviceIndependentFlagsMask).rawValue):\(item.keyEquivalent.lowercased())"
                    // The same command in two menus (Workspaces in File and Window) is one command.
                    if let other = seen[key] {
                        if other.split(separator: ">").last?.trimmingCharacters(in: .whitespaces) != item.title { problems.append("same key for \(other) and \(here)") }
                    } else { seen[key] = here }
                }
                if let sub = item.submenu { walk(sub, here) }
            }
        }
        for top in bar.items { if let m = top.submenu { walk(m, top.title) } }
        let note = tall.isEmpty ? "" : " NOTE taller than the screen, AppKit scrolls: " + tall.joined(separator: "; ")
        return problems.isEmpty ? "FIT-MENUS \(count) items ok\(note)" : problems.map { "FAIL FIT-MENUS \($0)" }.joined(separator: "\n")
    }

    /// Every visible view the checks look at, in window coordinates.
    func fitElements(in window: NSWindow) -> [FitElement] {
        guard let root = window.contentView?.superview else { return [] }
        var out: [FitElement] = []
        func walk(_ v: NSView, scroll: NSRect?, sideways: Bool, holder: NSRect?, inToolbar: Bool) {
            if v.isHidden || v.alphaValue < 0.01 { return }
            let name = String(describing: type(of: v))
            // AppKit's own chrome (traffic lights, the » overflow) and the terminal grid size themselves.
            if name.hasPrefix("_NSTheme") || name.contains("ClippedItemsIndicator") || v is TerminalNSView { return }
            // A search field's magnifier and clear buttons are its own cell's parts.
            if v.superview is NSSearchField { return }
            // The alignment rect: SwiftUI's button views add focus-ring margins outside the bezel.
            let r = v.superview.map { $0.convert(v.alignmentRect(forFrame: v.frame), to: nil) } ?? v.convert(v.bounds, to: nil)
            guard r.width > 0, r.height > 0 else { return }
            // The outline's disclosure triangles are AppKit's, sized by the row.
            if v.identifier == NSOutlineView.disclosureButtonIdentifier { return }
            var inner = scroll, innerSideways = sideways
            if let clip = v as? NSClipView {
                inner = clip.convert(clip.bounds, to: nil).intersection(scroll ?? .infinite)
                innerSideways = (clip.documentView?.frame.width ?? 0) > clip.bounds.width + 1
            }
            // Toolbar spaces are gaps, not controls.
            if name == "NSToolbarItemViewer", let item = v.value(forKey: "item") as? NSToolbarItem, [.flexibleSpace, .space].contains(item.itemIdentifier) { return }
            if var e = fitElement(v, name: name, frame: r, scroll: scroll, holder: holder) {
                e.inToolbar = inToolbar
                e.scrollsSideways = sideways
                out.append(e)
                // A control's own parts (bezel, image, title cell) are the control.
                if e.kind != "toolbar-item" { return }
            }
            let clipsHere = v.clipsToBounds && !(v is NSClipView) && v.superview != nil
            let toolbar = inToolbar || name == "NSToolbarItemViewer"
            for sub in v.subviews { walk(sub, scroll: inner, sideways: innerSideways, holder: clipsHere ? r : holder, inToolbar: toolbar) }
        }
        walk(root, scroll: nil, sideways: false, holder: nil, inToolbar: false)
        return out
    }

    private func fitElement(_ v: NSView, name: String, frame: NSRect, scroll: NSRect?, holder: NSRect?) -> FitElement? {
        func make(_ kind: String, _ text: String) -> FitElement { FitElement(kind: kind, text: text, frame: frame, scroll: scroll, holder: holder, view: v) }
        if name == "NSToolbarItemViewer" {
            let item = v.value(forKey: "item") as? NSToolbarItem
            return make("toolbar-item", item.map { $0.label.isEmpty ? $0.paletteLabel : $0.label } ?? "")
        }
        switch v {
        case let p as NSPopUpButton: return make("popup", p.titleOfSelectedItem ?? p.title)
        case let s as NSSegmentedControl: return make("segment", (0..<s.segmentCount).compactMap { s.label(forSegment: $0) }.joined(separator: "|"))
        case let b as NSButton:
            // A section header's Show/Hide button: the whole header row takes the click (LibraryOutline).
            if b.identifier == NSOutlineView.showHideButtonIdentifier { return nil }
            let type = (b.cell as? NSButtonCell)?.value(forKey: "buttonType") as? UInt
            let isToggle = type == NSButton.ButtonType.switch.rawValue || type == NSButton.ButtonType.radio.rawValue
            // Borderless buttons (.borderless, .plain: icons) need the whole 24 pt square; bezeled ones
            // keep AppKit's bezel height for their control size.
            let kind = isToggle ? "toggle" : b.isBordered ? "button" : "icon-button"
            return make(kind, b.title.isEmpty ? (b.accessibilityLabel() ?? "") : b.title)
        case let t as NSTextField where !t.isEditable: return make("label", t.stringValue)
        case is NSImageView: return make("image", "")
        default: return name == "CGDrawingView" ? make("drawing", "") : nil
        }
    }

    func fitProblems(in window: NSWindow) -> [String] {
        let elements = fitElements(in: window)
        let t = Self.fitTolerance
        let bounds = NSRect(origin: .zero, size: window.frame.size).insetBy(dx: -t, dy: -t)
        func describe(_ e: FitElement) -> String {
            "\(e.kind) \"\(e.text.prefix(40))\" at \(Int(e.frame.minX)),\(Int(window.frame.height - e.frame.maxY)) \(Int(e.frame.width))x\(Int(e.frame.height))"
        }
        func shown(_ e: FitElement) -> Bool { e.scroll.map { $0.insetBy(dx: -t, dy: -t).contains(e.frame) } ?? true }
        var problems: [String] = []
        for e in elements {
            if let s = e.scroll {
                // Rows scroll vertically out of view; sideways they must fit.
                if !e.scrollsSideways, e.frame.intersects(s), e.frame.width <= s.width, e.frame.minX < s.minX - t || e.frame.maxX > s.maxX + t {
                    problems.append("CLIPPED sideways in its scroll view: \(describe(e))")
                }
                // The part the scroll view shows must be inside the window: a scroll view that
                // runs past the window loses controls that are not scrolled out at all (LF-01).
                let inView = e.frame.intersection(s)
                if !inView.isEmpty, !bounds.contains(inView) {
                    problems.append("CLIPPED by the window: \(describe(e))")
                }
            } else if !bounds.contains(e.frame) {
                problems.append("CLIPPED by the window: \(describe(e))")
            }
            // A non-scrolling clipping holder cuts or hides the control, wholly outside it
            // included: that is a lost control, not one scrolled out of view (LF-01).
            if let h = e.holder, !h.insetBy(dx: -t, dy: -t).contains(e.frame), shown(e) {
                problems.append("CLIPPED by its container: \(describe(e))")
            }
            guard shown(e) else { continue }
            if let small = smallTarget(e) { problems.append("SMALL hit target \(small): \(describe(e))") }
            if let issue = textFit(e) { problems.append("\(issue): \(describe(e))") }
        }
        // Toolbar viewers hold their own button, so controls are compared within one kind of holder.
        let controls = elements.filter { $0.isControl && shown($0) }
        for (i, a) in controls.enumerated() {
            for b in controls[(i + 1)...] {
                let cross = a.frame.intersection(b.frame)
                guard cross.width > 2, cross.height > 2, !a.frame.contains(b.frame), !b.frame.contains(a.frame),
                      !a.view.isDescendant(of: b.view), !b.view.isDescendant(of: a.view) else { continue }
                problems.append("OVERLAP \(describe(a)) with \(describe(b))")
            }
        }
        return problems
    }

    /// Under 24 pt either way; a bezeled push button's height is AppKit's for its control size.
    private func smallTarget(_ e: FitElement) -> String? {
        let min = DS.Size.minHitTarget - 0.5
        if e.inToolbar { return nil }
        switch e.kind {
        case "segment":
            guard let s = e.view as? NSSegmentedControl else { return nil }
            let narrow = (0..<s.segmentCount).first { s.width(forSegment: $0) > 0 && s.width(forSegment: $0) < min }
            return narrow.map { "(segment \($0) \(Int(s.width(forSegment: $0))) pt)" } ?? (e.frame.height < Self.fitBezelMinHeight ? "(height)" : nil)
        case "icon-button":
            return e.frame.width < min || e.frame.height < min ? "(\(Int(e.frame.width))x\(Int(e.frame.height)) pt)" : nil
        case "toolbar-item" where e.text.isEmpty:
            // An unlabelled custom item (the tab strip) holds controls of its own, checked one by one.
            return nil
        case "button", "popup", "toolbar-item":
            if e.frame.width < min { return "(width)" }
            return e.frame.height < Self.fitBezelMinHeight ? "(height)" : nil
        default: return nil
        }
    }

    /// Whether a control title or label fits: its cell's natural size against its bounds.
    func textFit(_ e: FitElement) -> String? {
        let text = e.text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.count > 1, !text.contains("\n"), let control = e.view as? NSControl, let cell = control.cell else { return nil }
        // List rows elide user data (names) by design, with the full text in a tooltip.
        if control.enclosingScrollView?.documentView is NSTableView { return nil }
        var natural = cell.cellSize(forBounds: NSRect(x: 0, y: 0, width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude))
        if let popup = control as? NSPopUpButton, let font = popup.font {
            // A pop-up's cell is as wide as its widest item; only the shown title has to fit, beside the arrows.
            natural.width = ceil((text as NSString).size(withAttributes: [.font: font]).width) + Self.fitPopupChrome
        }
        let b = control.bounds
        let oneLine = natural.height
        if b.height < oneLine * 1.8 {
            return natural.width > b.width + 2 ? "TRUNCATED (needs \(Int(natural.width)) pt, has \(Int(b.width)))" : nil
        }
        // A label several lines tall whose text would fit on one line at its width is not wrapped.
        guard e.kind == "label", natural.width > b.width + 2, text.split(separator: " ").count <= Self.fitShortLabelWords else { return nil }
        return "WRAPPED over lines (\(Int(natural.width)) pt on one, has \(Int(b.width)))"
    }
}
#endif
