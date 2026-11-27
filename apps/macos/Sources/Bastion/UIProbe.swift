import SwiftUI

/// Window-space frames of views marked `.uiProbe(id)`, recorded only during a driver run, so the
/// `frame` step can measure SwiftUI layout without an accessibility client.
@MainActor
enum UIProbe {
    static let isActive = TestHooks.isScripted
    static var frames: [String: CGRect] { entries.mapValues(\.rect) }
    /// Which view instance wrote each id last: when a view is replaced by another with the same id
    /// (switching the inspector from a folder to a connection), the old one's `onDisappear` can run
    /// after the new one recorded its frame, and must not erase it.
    fileprivate static var entries: [String: (owner: UUID, rect: CGRect)] = [:]
}

private struct UIProbeModifier: ViewModifier {
    let id: String
    @State private var owner = UUID()

    func body(content: Content) -> some View {
        content
            .onGeometryChange(for: CGRect.self) { $0.frame(in: .global) } action: { UIProbe.entries[id] = (owner, $0) }
            .onDisappear { if UIProbe.entries[id]?.owner == owner { UIProbe.entries[id] = nil } }
    }
}

extension View {
    @ViewBuilder func uiProbe(_ id: String) -> some View {
        if UIProbe.isActive && !id.isEmpty { modifier(UIProbeModifier(id: id)) } else { self }
    }
}
