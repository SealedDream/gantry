#if BASTION_TEST_HOOKS
import AppKit
import Darwin
import BastionCore

/// Where the last `renders` step left the body counts.
@MainActor enum RenderAudit { static var mark: [String: Int] = [:] }

/// UI driver steps that measure responsiveness and resource use for `uitests/run-all.sh`. Every
/// result is one `PERF <name> <value> <unit>` line, which the runner turns into p50/p95 and checks
/// against its budget.
extension Driver {
    /// Handles a measurement step; false when `cmd` is not one.
    func perfStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "timed-tab": await timedTab(arg)
        case "timed-route": await timedRoute(arg)
        case "timed-new-folder": await timedNewFolder(arg)
        case "timed-add": await timedAdd()
        case "timed-panel": await timedPanel(arg)
        case "echo-latency": await echoLatency(Int(arg) ?? 20)
        case "stall-start": StallWatch.shared.start()
        case "stall-report":
            write(String(format: "PERF ui-stall-max %.1f ms (%d gaps over 50 ms; longest in: %@)", StallWatch.shared.maxGapMs, StallWatch.shared.over50, StallWatch.shared.maxStep as NSString))
            for (step, ms) in StallWatch.shared.stepMax.sorted(by: { $0.value > $1.value }) {
                write(String(format: "STALL-STEP %.1f ms in: %@", ms, step as NSString))
            }
        case "renders":
            // `renders <label>`: body runs per counted view (`RenderCount`) since the last `renders` step;
            // the first one covers the launch (redraw audit).
            write("RENDERS \(arg): \(RenderCount.delta(since: RenderAudit.mark))")
            RenderAudit.mark = RenderCount.counts
        case "resources": await resources(Double(arg) ?? 10)
        case "bench-scrollback": await scrollback(Int(arg) ?? 200_000)
        case "timed-close-tab": await timedCloseTab()
        case "mem-sample", "mem-at", "mem-soak": return await memoryStep(cmd, arg)
        case "pane-watch": await paneWatchStep(arg)
        default: return false
        }
        return true
    }

    /// The toolbar's items by object: SwiftUI's toolbar bridge makes new ones when it rebuilds the
    /// toolbar (MAC-STALLS), so a toggle or a new tab that replaced some rebuilt it.
    func toolbarItemObjects() -> Set<ObjectIdentifier> { Set((window?.toolbar?.items ?? []).map(ObjectIdentifier.init)) }

    private func layoutAndDisplay() {
        window?.contentView?.layoutSubtreeIfNeeded()
        window?.displayIfNeeded()
    }

    /// `timed-tab <index>`: select the n-th tab (0-based) and time the layout and display it causes.
    private func timedTab(_ arg: String) async {
        guard let sv = UIDriver.services, let i = Int(arg), i < sv.sessions.tabs.count else { return write("FAIL timed-tab \(arg)") }
        let t0 = CFAbsoluteTimeGetCurrent()
        sv.sessions.selected = sv.sessions.tabs[i].id
        await Task.yield()
        layoutAndDisplay()
        write(String(format: "PERF tab-switch %.1f ms", (CFAbsoluteTimeGetCurrent() - t0) * 1000))
        await settle(0.1)
    }

    /// `timed-route <target>`: open a dialog through the router (as its menu item does) and time it
    /// until the sheet is on screen; the sheet is closed again afterwards.
    private func timedRoute(_ arg: String) async {
        guard let sv = UIDriver.services, let window else { return write("FAIL timed-route") }
        if arg == "new-connection" { return await timedInspectorForm(sv) }
        let renders = RenderCount.counts
        let t0 = CFAbsoluteTimeGetCurrent()
        sv.router.open(arg)
        // A window panel (any route that opens one, e.g. import-connections opens the import report),
        // else an AppKit sheet.
        func panelDrawn() -> Bool { commands.panel.map { UIProbe.frames[$0.probe] != nil } ?? false }
        while window.attachedSheet == nil && !panelDrawn() && CFAbsoluteTimeGetCurrent() - t0 < 2 {
            try? await Task.sleep(for: .milliseconds(1))
        }
        if let panel = commands.panel, panelDrawn() {
            window.displayIfNeeded()
            write(String(format: "PERF dialog-open %.1f ms (%@) renders %@", (CFAbsoluteTimeGetCurrent() - t0) * 1000, arg, RenderCount.delta(since: renders)))
            await settle(0.2)
            if commands.panel == panel { commands.panel = nil }
            await settle(0.4)
            return
        }
        guard let sheet = window.attachedSheet else { return write("FAIL timed-route \(arg): no sheet or panel") }
        sheet.displayIfNeeded()
        write(String(format: "PERF dialog-open %.1f ms (%@)", (CFAbsoluteTimeGetCurrent() - t0) * 1000, arg))
        await settle(0.2)
        window.endSheet(sheet)
        await settle(0.4)
    }

    /// New Connection opens its form in the inspector (no sheet since 2026-11-15): timed until the
    /// form has a frame and the window has drawn it; then closed as Cancel does.
    private func timedInspectorForm(_ sv: UIDriver.Services) async {
        guard let window else { return write("FAIL timed-route new-connection") }
        let renders = RenderCount.counts
        let t0 = CFAbsoluteTimeGetCurrent()
        sv.router.open("new-connection")
        while UIProbe.frames[Self.newConnectionProbe] == nil && CFAbsoluteTimeGetCurrent() - t0 < 2 {
            try? await Task.sleep(for: .milliseconds(1))
        }
        guard UIProbe.frames[Self.newConnectionProbe] != nil else { return write("FAIL timed-route new-connection: no form") }
        window.displayIfNeeded()
        write(String(format: "PERF dialog-open %.1f ms (new-connection) renders %@", (CFAbsoluteTimeGetCurrent() - t0) * 1000, RenderCount.delta(since: renders)))
        await settle(0.2)
        commands.addConnection = nil
        await settle(0.4)
    }

    static let newConnectionProbe = AddConnectionView.probeId

    /// `timed-new-folder [escape|<name>]`: New Folder in the library root, timed until its row is in
    /// inline rename (no sheet since 2026-11-15); then Escape keeps the default name, or the name is typed
    /// and saved. Logs `NEWFOLDER <name>` with the folder the tree now shows.
    private func timedNewFolder(_ arg: String) async {
        guard let window else { return write("FAIL timed-new-folder") }
        let before = Set(commands.model.tree?.folders.map(\.id) ?? [])
        let renders = RenderCount.counts
        let t0 = CFAbsoluteTimeGetCurrent()
        commands.run("new-subfolder", on: nil)
        while !(window.firstResponder is NSTextView) && CFAbsoluteTimeGetCurrent() - t0 < 2 {
            try? await Task.sleep(for: .milliseconds(1))
        }
        guard let editor = window.firstResponder as? NSTextView else { return write("FAIL timed-new-folder: no inline rename") }
        window.displayIfNeeded()
        write(String(format: "PERF new-folder-inline %.1f ms (renders %@)", (CFAbsoluteTimeGetCurrent() - t0) * 1000, RenderCount.delta(since: renders)))
        await settle(0.2)
        if arg.isEmpty || arg == "escape" {
            editor.doCommand(by: #selector(NSResponder.cancelOperation(_:)))
        } else {
            editor.selectAll(nil)
            editor.insertText(arg, replacementRange: editor.selectedRange())
            editor.doCommand(by: #selector(NSResponder.insertNewline(_:)))
        }
        await settle(0.3)
        let made = commands.model.tree?.folders.filter { !before.contains($0.id) }.map(\.name) ?? []
        write("NEWFOLDER \(made.joined(separator: ","))")
    }

    /// `timed-panel library|inspector`: toggle the panel and, through its slide, report the longest
    /// gap between main run-loop turns (a dropped-frame proxy): owner feedback 4 wants the library
    /// to slide as smoothly as the inspector.
    private func timedPanel(_ which: String) async {
        guard let sv = UIDriver.services else { return write("FAIL timed-panel") }
        var last = CFAbsoluteTimeGetCurrent()
        var worst = 0.0, worstAt = 0.0, frames = 0
        var visibleSeen: [Int] = []
        var firstDip: String?
        let toolbar = window?.toolbar
        // NSToolbar keeps some items hidden at rest; a drop below the count before the toggle is what
        // pushes items into the ">>" overflow chevron.
        let restVisible = toolbar?.visibleItems?.count ?? 0
        let began = CFAbsoluteTimeGetCurrent()
        let timer = Timer(timeInterval: 0.004, repeats: true) { _ in
            let now = CFAbsoluteTimeGetCurrent()
            if now - last > worst { worst = now - last; worstAt = last - began }
            last = now; frames += 1
            // NSToolbar shows its ">>" overflow chevron while some items are not visible.
            if let toolbar {
                let visible = toolbar.visibleItems ?? []
                visibleSeen.append(visible.count)
                // The first tick with an item gone: which ones, and the room the strip had then.
                if firstDip == nil && visible.count < restVisible {
                    let shown = Set(visible.map { $0.itemIdentifier.rawValue })
                    let gone = toolbar.items.filter { !shown.contains($0.itemIdentifier.rawValue) }
                        .map { "\($0.itemIdentifier.rawValue.suffix(28))=\(Int($0.view?.frame.width ?? -1))" }
                    firstDip = String(format: "+%.0f ms gone [%@] area %.0f sidebar %.0f window %.0f", (now - began) * 1000,
                                      gone.joined(separator: ", "), UIDriver.services?.sessions.sessionAreaWidth ?? -1,
                                      UIDriver.services?.sessions.sidebarWidth ?? -1, self.window?.frame.width ?? -1)
                }
            }
        }
        RunLoop.main.add(timer, forMode: .common)
        func shown() -> Bool { which == "inspector" ? commands.tree.inspectorPresented : commands.tree.libraryVisible }
        let before = shown()
        let renders = RenderCount.counts
        let items = toolbarItemObjects()
        let t0 = CFAbsoluteTimeGetCurrent()
        last = t0
        sv.router.open(which == "inspector" ? "toggle-inspector" : "toggle-library")
        layoutAndDisplay()
        let toggleMs = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        try? await Task.sleep(for: .milliseconds(600))
        timer.invalidate()
        // Fewer items may fit once the panel is open: only a dip below both rest states is the flash.
        let floor = min(restVisible, window?.toolbar?.visibleItems?.count ?? 0)
        let overflowTicks = visibleSeen.filter { $0 < floor }.count
        let dir = shown() == before ? "no-change" : (before ? "close" : "open")
        write(String(format: "PERF panel-toggle %.1f ms (%@ %@)", toggleMs, which as NSString, dir as NSString))
        write(String(format: "PERF panel-slide-gap %.1f ms (%@ %@, %d ticks, starts at +%.0f ms)", worst * 1000, which as NSString, dir as NSString, frames, worstAt * 1000))
        write("PERF panel-toolbar-overflow \(overflowTicks) ticks (\(which) \(dir))" + (overflowTicks > 0 ? " first dip \(firstDip ?? "-")" : ""))
        write("PANEL-RENDERS \(which) \(dir): \(RenderCount.delta(since: renders)); toolbar items replaced \(items.subtracting(toolbarItemObjects()).count)")
        await settle(0.3)
    }

    /// `timed-add`: open the toolbar's + menu (as clicking it does) and time it until the popover
    /// window has drawn (owner feedback 9).
    private func timedAdd() async {
        guard let sv = UIDriver.services else { return write("FAIL timed-add") }
        func popover() -> NSWindow? { NSApp.windows.first { $0.isVisible && String(describing: type(of: $0)).contains("Popover") } }
        // The + button's own action (its toggle, as a click runs it, without performClick's highlight delay).
        let button = window?.contentView?.superview?.allSubviews(of: AddPopoverButton.self).first
        // The + button toggles on NSPopover.isShown, which stays true until the close has finished, about
        // 0.6 s after the window has faded. A click before that closed it again, so every second timed
        // open showed nothing (of-b-perf "no popover", final regression 2026-11-26).
        func waitClosed() async {
            let t = CFAbsoluteTimeGetCurrent()
            while (button?.isPopoverShown == true || popover() != nil) && CFAbsoluteTimeGetCurrent() - t < 3 {
                try? await Task.sleep(for: .milliseconds(10))
            }
        }
        await waitClosed()
        let t0 = CFAbsoluteTimeGetCurrent()
        if let button { button.sendAction(button.action, to: button.target) } else { sv.router.open("add") }
        while popover() == nil && CFAbsoluteTimeGetCurrent() - t0 < 2 {
            try? await Task.sleep(for: .milliseconds(1))
        }
        guard let pop = popover() else { return write("FAIL timed-add: no popover\(button == nil ? " (no + button)" : "")") }
        pop.displayIfNeeded()
        write(String(format: "PERF add-menu-open %.1f ms", (CFAbsoluteTimeGetCurrent() - t0) * 1000))
        await settle(0.2)
        // Closed once, by the same button (it toggles), and waited for until the close has finished.
        if let button { button.sendAction(button.action, to: button.target) } else if let esc = NSEvent.keyEvent(
            with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0, windowNumber: pop.windowNumber, context: nil,
            characters: "\u{1b}", charactersIgnoringModifiers: "\u{1b}", isARepeat: false, keyCode: 53) {
            pop.makeKey()
            pop.sendEvent(esc)
        }
        await waitClosed()
        await settle(0.2)
    }

    /// `echo-latency <n>`: type n letters into the selected terminal one at a time and time each until
    /// the terminal view has refreshed to a screen showing the echo (what its next display pass draws).
    private func echoLatency(_ n: Int) async {
        guard UIDriver.services?.sessions.selectedTab?.terminal != nil else { return write("FAIL echo-latency: no terminal") }
        defer { TerminalNSView.didRefresh = nil }
        var typed = ""
        for i in 0..<n {
            typed += String(UnicodeScalar(UInt8(97 + i % 26)))
            let ms = await timeEcho(typed)
            write(ms.map { String(format: "PERF keystroke-echo %.2f ms", $0) } ?? "FAIL echo-latency: no echo for \(typed)")
            await settle(0.03)
        }
        // Clear the typed line (Ctrl-U) so later steps start at an empty prompt.
        sendKey("\u{15}", keyCode: 32, flags: .control)
        await settle(0.2)
    }

    /// Sends the last letter of `typed` and returns the ms until a view refresh shows all of `typed`.
    private func timeEcho(_ typed: String) async -> Double? {
        let t0 = CFAbsoluteTimeGetCurrent()
        let shown: Double? = await withCheckedContinuation { cont in
            var resumed = false
            let finish: (Double?) -> Void = { v in
                guard !resumed else { return }
                resumed = true
                TerminalNSView.didRefresh = nil
                cont.resume(returning: v)
            }
            TerminalNSView.didRefresh = { s in
                if Self.screenText(s).contains(typed) { finish((CFAbsoluteTimeGetCurrent() - t0) * 1000) }
            }
            sendKey(String(typed.last!), keyCode: 0, flags: [])
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { MainActor.assumeIsolated { finish(nil) } }
        }
        return shown
    }

    /// `bench-scrollback <lines>`: print that many lines in the selected local shell and time until
    /// the last one is on screen, with the stall watchdog running.
    private func scrollback(_ lines: Int) async {
        guard let t = UIDriver.services?.sessions.selectedTab?.terminal else { return write("FAIL bench-scrollback: no terminal") }
        StallWatch.shared.start()
        let t0 = CFAbsoluteTimeGetCurrent()
        for ch in "seq 1 \(lines)\r" { sendKey(String(ch), keyCode: ch == "\r" ? 36 : 0, flags: []) }
        let last = "\n\(lines)"
        while !Self.screenText(t).contains(last) && CFAbsoluteTimeGetCurrent() - t0 < 120 {
            try? await Task.sleep(for: .milliseconds(20))
        }
        let ms = (CFAbsoluteTimeGetCurrent() - t0) * 1000
        write(Self.screenText(t).contains(last) ? String(format: "PERF scrollback-%d %.0f ms", lines, ms) : "FAIL bench-scrollback: \(lines) not shown")
        write(String(format: "PERF ui-stall-max %.1f ms (during scrollback)", StallWatch.shared.maxGapMs))
    }

    private func timedCloseTab() async {
        guard let sv = UIDriver.services, let tab = sv.sessions.selectedTab else { return write("FAIL timed-close-tab") }
        let t0 = CFAbsoluteTimeGetCurrent()
        sv.sessions.close(tab)
        layoutAndDisplay()
        write(String(format: "PERF tab-close %.1f ms", (CFAbsoluteTimeGetCurrent() - t0) * 1000))
    }

    /// `resources <seconds>`: this process's CPU use over the interval and its resident memory.
    private func resources(_ seconds: Double) async {
        let (cpu0, wall0) = (Self.cpuSeconds(), CFAbsoluteTimeGetCurrent())
        try? await Task.sleep(for: .seconds(seconds))
        let cpu = (Self.cpuSeconds() - cpu0) / (CFAbsoluteTimeGetCurrent() - wall0) * 100
        write(String(format: "PERF cpu %.2f %% over %.0f s", cpu, seconds))
        write(String(format: "PERF memory %.1f MB", Double(Self.residentBytes()) / 1_048_576))
    }

    static func cpuSeconds() -> Double {
        var u = rusage()
        getrusage(RUSAGE_SELF, &u)
        func s(_ t: timeval) -> Double { Double(t.tv_sec) + Double(t.tv_usec) / 1e6 }
        return s(u.ru_utime) + s(u.ru_stime)
    }

    static func residentBytes() -> UInt64 {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
        }
        return kr == KERN_SUCCESS ? info.phys_footprint : 0
    }
}

/// Main-thread watchdog for tests: a 5 ms timer in common run-loop modes; the longest gap between
/// two ticks is the longest the main thread was blocked.
@MainActor
final class StallWatch {
    static let shared = StallWatch()
    private var timer: Timer?
    private var last = CFAbsoluteTimeGetCurrent()
    private(set) var maxGapMs = 0.0
    private(set) var over50 = 0
    /// The script step running now, and the one that held the longest gap (stall-report names it).
    var step = ""
    private(set) var maxStep = ""
    /// Longest gap per step, for steps with one over 50 ms (stall-report lists them).
    private(set) var stepMax: [String: Double] = [:]

    func start() {
        timer?.invalidate()
        maxGapMs = 0
        stepMax = [:]
        over50 = 0
        maxStep = ""
        last = CFAbsoluteTimeGetCurrent()
        let t = Timer(timeInterval: 0.005, repeats: true) { _ in
            MainActor.assumeIsolated { StallWatch.shared.tick() }
        }
        RunLoop.main.add(t, forMode: .common)
        timer = t
    }

    private var paused = false

    /// Test-only work between `pause` and `resume` (a check, not a user action) is not counted.
    func pause() { paused = true }
    func resume() { paused = false; last = CFAbsoluteTimeGetCurrent() }

    private func tick() {
        guard !paused else { return }
        let now = CFAbsoluteTimeGetCurrent()
        let gap = (now - last) * 1000
        last = now
        if gap > maxGapMs { maxGapMs = gap; maxStep = step }
        if gap > 50 {
            over50 += 1
            stepMax[step] = max(stepMax[step] ?? 0, gap)
        }
    }
}

#endif
