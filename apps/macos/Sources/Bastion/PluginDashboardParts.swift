import SwiftUI

/// Plugin API 1.6 display items: the `stat` tile and the `status` and `meter` table cells
/// (`plugins/wit/plugin.wit`). System colours only, so light and dark both follow the OS.
enum PluginTone {
    /// A bar's colour: accent, amber from 85 %, red from 90 % (owner, 2026-11-23).
    static let warnAt = 0.85
    static let criticalAt = 0.90

    static func bar(_ fraction: Double) -> Color {
        fraction >= criticalAt ? .red : fraction >= warnAt ? .orange : .accentColor
    }

    static func dot(_ tone: String) -> Color {
        switch tone {
        case "good": return .green
        case "warning": return .orange
        case "critical": return .red
        default: return .secondary
        }
    }

    /// A row whose status cell is `off` (a stopped guest) is drawn dimmed.
    static func isDimmed(_ row: [Any?]) -> Bool {
        row.contains { ($0 as? [String: Any])?["tone"] as? String == "off" }
    }
}

/// A thin bar, 4 pt high, filled to `fraction`.
struct PluginBar: View {
    let fraction: Double
    var body: some View {
        GeometryReader { g in
            ZStack(alignment: .leading) {
                Capsule().fill(Color.secondary.opacity(0.2))
                Capsule().fill(PluginTone.bar(fraction)).frame(width: g.size.width * min(max(fraction, 0), 1))
            }
        }
        .frame(height: 4)
        .accessibilityElement()
        .accessibilityValue("\(Int((fraction * 100).rounded())) percent")
    }
}

/// A summary tile: title, value, detail and an optional bar. Tiles share a row's width.
struct PluginStatTile: View {
    let rec: [String: Any]
    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(rec["title"] as? String ?? "").font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1)
            Text(rec["value"] as? String ?? "").font(.title3.weight(.semibold)).monospacedDigit().lineLimit(1).minimumScaleFactor(0.8)
            if let f = rec["fraction"] as? Double { PluginBar(fraction: f) }
            Text(rec["detail"] as? String ?? "").font(DS.Font.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
        }
        .padding(.vertical, 8).padding(.horizontal, 10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 6))
    }
}

extension PluginCellView {
    /// A cell as UI tests read it: the text, with a status cell's tone first ("[good] lab-web")
    /// and a meter's percent first ("[88%] 3.5 GiB / 4.0 GiB").
    static func driverText(_ v: Any?) -> String {
        if let rec = v as? [String: Any], let tone = rec["tone"] as? String { return "[\(tone)] \(text(v))" }
        if let rec = v as? [String: Any], let f = rec["fraction"] as? Double { return "[\(Int((f * 100).rounded()))%] \(text(v))" }
        return text(v)
    }
}

/// One table cell: text, a number (integers without ".0"), a status dot, or a meter.
struct PluginCellView: View {
    let value: Any?
    var body: some View {
        if let rec = value as? [String: Any], let tone = rec["tone"] as? String {
            HStack(spacing: 6) {
                Circle().fill(PluginTone.dot(tone)).frame(width: 7, height: 7)
                Text(rec["text"] as? String ?? "").lineLimit(1)
            }
        } else if let rec = value as? [String: Any], let f = rec["fraction"] as? Double {
            HStack(spacing: 6) {
                PluginBar(fraction: f).frame(maxWidth: 60)
                Text(rec["text"] as? String ?? "").monospacedDigit().lineLimit(1)
            }
        } else {
            Text(Self.text(value)).foregroundStyle(value == nil ? .secondary : .primary).lineLimit(1)
        }
    }

    /// A cell as text: "NULL" for none, whole numbers without a fraction.
    static func text(_ v: Any?) -> String {
        guard let v else { return "NULL" }
        if let rec = v as? [String: Any], let t = rec["text"] as? String { return t }
        if let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() {
            let d = n.doubleValue
            if d.rounded() == d, abs(d) < 1e15 { return String(Int64(d)) }
            return n.stringValue
        }
        return "\(v)"
    }
}
