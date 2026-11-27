import SwiftUI

/// "Reconnecting to <name>" over the top-trailing corner of a pane while the core reports the SSH
/// link as connecting, reconnecting or paused. The core's own plain line in the terminal stays (it is
/// shared with Windows); this badge is the Mac's visible state. Hidden for "Connection lost", which
/// the bottom bar already shows with its Reconnect button. Display only: no hit testing.
struct ReconnectBadge: View {
    let status: String?
    let name: String
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    static func isReconnecting(_ status: String?) -> Bool {
        guard let status else { return false }
        return status != "Connection lost"
    }

    var body: some View {
        if Self.isReconnecting(status), let status {
            HStack(spacing: DS.Space.xs) {
                ProgressView().controlSize(.mini)
                Text("Reconnecting to \(name)").font(DS.Font.caption).lineLimit(1).truncationMode(.middle)
            }
            .padding(.horizontal, DS.Space.s).padding(.vertical, DS.Space.xs)
            .background(.regularMaterial, in: Capsule())
            .padding(DS.Space.s)
            .help(status)
            .allowsHitTesting(false)
            .transition(reduceMotion ? .opacity : .opacity.combined(with: .move(edge: .top)))
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Reconnecting to \(name), \(status)")
            .accessibilityIdentifier("reconnect-badge")
        }
    }
}
