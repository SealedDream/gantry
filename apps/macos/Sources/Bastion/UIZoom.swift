import AppKit
import SwiftUI

/// Settings › General › Interface size: one scale for the app's text and controls (owner
/// 2026-11-05 (d)). SwiftUI on macOS ignores Dynamic Type, so the design-system fonts (`DS.Font`)
/// read `scale` themselves; a view's body that reads them re-renders when it changes (Observation
/// tracks the read). Controls follow through `controlSize`. Saved across restarts.
@MainActor @Observable
final class UIZoom {
    static let shared = UIZoom()
    /// The steps Zoom In and Zoom Out walk; 1 is Actual Size.
    static let steps: [Double] = [0.75, 0.9, 1, 1.1, 1.25, 1.5, 1.75, 2]
    static let defaultsKey = "uiZoom"

    private(set) var scale: Double

    private init() {
        let saved = UserDefaults.standard.double(forKey: Self.defaultsKey)
        scale = Self.steps.contains(saved) ? saved : 1
    }

    var percent: Int { Int((scale * 100).rounded()) }

    func zoomIn() { set(Self.steps.first { $0 > scale + 0.001 } ?? scale) }
    func zoomOut() { set(Self.steps.last { $0 < scale - 0.001 } ?? scale) }
    func reset() { set(1) }

    /// Any step (the driver sets 90/125/150 directly); other values are ignored.
    func set(_ value: Double) {
        guard Self.steps.contains(value), value != scale else { return }
        scale = value
        UserDefaults.standard.set(value, forKey: Self.defaultsKey)
    }

    /// Bordered controls have a fixed height per size, so bigger text needs the bigger size.
    var controlSize: ControlSize {
        switch scale {
        case ..<0.95: .small
        case ..<1.2: .regular
        default: .large
        }
    }

    nonisolated static let keypadPlus: UInt16 = 69, keypadMinus: UInt16 = 78, keypad0: UInt16 = 82

    /// ⌘= / ⌘+ / ⌘- / ⌘0 (main row or keypad) zoom only the session content: the focused tab's
    /// terminal text. The app's own UI scale is a Settings › General choice, never a key (owner
    /// feedback 2026-11-07 #13). Returns whether the event was a zoom key.
    func handle(_ event: NSEvent) -> Bool {
        let mods = event.modifierFlags.intersection([.command, .shift, .option, .control])
        guard !isRecordingShortcut(), mods.contains(.command), !mods.contains(.option), !mods.contains(.control) else { return false }
        guard let step = Self.zoomStep(keyCode: event.keyCode, characters: event.charactersIgnoringModifiers,
                                       keypad: event.modifierFlags.contains(.numericPad), shift: mods.contains(.shift)) else { return false }
        terminalZoom?(step.delta)
        return true
    }

    struct ZoomStep: Equatable { let delta: Int? }

    /// The zoom a key asks for: +1, -1, or reset (`delta` nil); nil when it is not a zoom key.
    nonisolated static func zoomStep(keyCode: UInt16, characters: String?, keypad: Bool, shift: Bool) -> ZoomStep? {
        if keypad {
            switch keyCode {
            case keypadPlus: return ZoomStep(delta: 1)
            case keypadMinus: return ZoomStep(delta: -1)
            case keypad0: return ZoomStep(delta: nil)
            default: return nil
            }
        }
        if shift {
            // ⌘⇧= / ⌘⇧- on US layouts (the + and _ keys).
            switch keyCode {
            case keyEquals: return ZoomStep(delta: 1)
            case keyMinus: return ZoomStep(delta: -1)
            default: return nil
            }
        }
        switch characters {
        case "=", "+": return ZoomStep(delta: 1)
        case "-": return ZoomStep(delta: -1)
        case "0": return ZoomStep(delta: nil)
        default: return nil
        }
    }

    nonisolated static let keyEquals: UInt16 = 24, keyMinus: UInt16 = 27
    /// Bigger/Smaller/Actual text for the focused session tab (set by the app); nil resets.
    var terminalZoom: ((Int?) -> Void)?
    /// Settings › Keyboard is recording a chord: every key goes to the recorder.
    var isRecordingShortcut: () -> Bool = { false }
    private var monitor: Any?

    /// Takes the zoom keys before menus and the terminal see them (the menu items show ⌘+, ⌘-,
    /// ⌘0, but AppKit would only match the exact shown character).
    func installKeyMonitor() {
        guard monitor == nil else { return }
        monitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { event in
            MainActor.assumeIsolated { UIZoom.shared.handle(event) } ? nil : event
        }
    }
}

extension View {
    /// A window's root: default text and control size follow the UI zoom.
    func uiZoomRoot() -> some View { modifier(UIZoomRoot()) }
}

private struct UIZoomRoot: ViewModifier {
    func body(content: Content) -> some View {
        content.font(DS.Font.body).controlSize(UIZoom.shared.controlSize)
            // MAC-MODERN-UI: bordered buttons without a DS role still get the current capsule shape.
            .buttonBorderShape(.capsule)
    }
}
