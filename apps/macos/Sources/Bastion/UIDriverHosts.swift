#if BASTION_TEST_HOOKS
import AppKit
import BastionCore

/// UI driver steps for host status, triggers and per-host colours (NM-B), printed as text so a
/// run with the screen locked (no captures) still checks them.
extension Driver {
    /// Handles one of these steps; false when `cmd` is not one.
    func hostsStep(_ cmd: String, _ arg: String) async -> Bool {
        switch cmd {
        case "host-colours": hostColours()
        case "host-status-rows": await hostStatusRows(Double(arg) ?? 5)
        case "triggers-list": triggersList()
        case "trigger-cells": triggerCells(arg)
        default: return false
        }
        return true
    }

    /// `host-colours`: every connection's effective accent, or `none`.
    private func hostColours() {
        let rows = AppIpc.connections(in: commands.model.tree).map { c -> String in
            guard let p = HostColors.shared.paint(for: c.id), let rgb = p.accent.usingColorSpace(.sRGB) else { return "\(c.name)=none" }
            return String(format: "%@=#%02x%02x%02x", c.name, Int(rgb.redComponent * 255), Int(rgb.greenComponent * 255), Int(rgb.blueComponent * 255))
        }
        write("HOST-COLOURS " + rows.sorted().joined(separator: " "))
    }

    /// `host-status-rows [seconds]`: the same core dashboard the sheet uses, shown for that long.
    private func hostStatusRows(_ seconds: Double) async {
        guard let lib = commands.model.library else { return write("FAIL host-status-rows: no library") }
        let d = HostStatusDashboard(intervalSecs: HostStatusPanel.defaultInterval)
        guard let n = try? d.load(library: lib) else { return write("FAIL host-status-rows: load") }
        d.setVisible(visible: true)
        await settle(seconds)
        let rows = d.snapshot().map { "\($0.name)=\($0.state)" }.sorted()
        d.setVisible(visible: false)
        write("HOST-STATUS targets=\(n) " + rows.joined(separator: " "))
    }

    /// `triggers-list`: the loaded triggers, or the load error.
    private func triggersList() {
        let rt = TriggerRuntime.shared
        guard let lib = rt.library else { return write("TRIGGERS error=\(rt.loadError ?? "none")") }
        let names = ((try? lib.list()) ?? []).map { "\($0.name)(\($0.enabled ? "on" : "off"))" }
        write("TRIGGERS " + names.joined(separator: " "))
    }

    /// `trigger-cells <text>`: foreground and bold of the first cell of `text` on the focused screen.
    private func triggerCells(_ text: String) {
        guard let t = UIDriver.services?.sessions.selectedTab?.terminal, let first = text.first else { return write("FAIL trigger-cells") }
        let s = t.fastScreen()
        let cols = max(Int(s.cols), 1)
        for start in stride(from: 0, to: s.cells.count, by: cols) {
            let row = s.cells[start..<min(start + cols, s.cells.count)]
            let line = row.map(\.text).joined()
            guard let r = line.range(of: text) else { continue }
            let col = line.distance(from: line.startIndex, to: r.lowerBound)
            let cell = row[row.startIndex + col]
            guard cell.text == String(first) else { continue }
            return write(String(format: "TRIGGER-CELLS %@ fg=#%06x bold=%@", text, cell.fg & 0xffffff, cell.bold ? "yes" : "no"))
        }
        write("FAIL trigger-cells: \(text) not on screen")
    }
}
#endif
