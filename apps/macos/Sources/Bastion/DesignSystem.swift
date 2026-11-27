import SwiftUI
import BastionCore

/// Single source for layout and type values used by the shell. Views take spacing, sizes and
/// fonts from here instead of literals so both panes stay on the same 4-point grid.
enum DS {
    enum Motion {
        /// The "Native spring" style (assets/icon/README.md): 300 ms cubic-bezier(.32,.72,0,1).
        static let panel = Animation.timingCurve(0.32, 0.72, 0, 1, duration: 0.3)
        /// Reduce Motion: no movement, a 100 ms fade.
        static let reducedFade = Animation.easeInOut(duration: 0.1)

        static func spring(reduced: Bool) -> Animation { reduced ? reducedFade : panel }
    }

    enum Space {
        static let xxs: CGFloat = 4
        static let xs: CGFloat = 8
        static let s: CGFloat = 12
        static let m: CGFloat = 16
        static let l: CGFloat = 24
        static let xl: CGFloat = 32
    }

    /// SF Pro at the macOS text-style sizes times the UI zoom (`UIZoom`; SwiftUI on macOS has no
    /// Dynamic Type). Every SwiftUI font in the app comes from here so View › Zoom reaches it.
    enum Font {
        /// Points at Actual Size, as AppKit sizes the text styles.
        static func points(_ style: SwiftUI.Font.TextStyle) -> CGFloat {
            switch style {
            case .largeTitle: 26
            case .title: 22
            case .title2: 17
            case .title3: 15
            case .headline, .body: 13
            case .callout: 12
            case .subheadline: 11
            default: 10 // footnote, caption, caption2
            }
        }
        @MainActor static var zoom: CGFloat { UIZoom.shared.scale }
        @MainActor static func style(_ style: SwiftUI.Font.TextStyle, design: SwiftUI.Font.Design = .default) -> SwiftUI.Font {
            .system(size: points(style) * zoom, weight: style == .headline ? .semibold : .regular, design: design)
        }
        /// A fixed point size (symbols, monospaced previews) under the zoom.
        @MainActor static func size(_ points: CGFloat, weight: SwiftUI.Font.Weight = .regular, design: SwiftUI.Font.Design = .default) -> SwiftUI.Font {
            .system(size: points * zoom, weight: weight, design: design)
        }
        @MainActor static var caption: SwiftUI.Font { style(.caption) }
        @MainActor static var caption2: SwiftUI.Font { style(.caption2) }
        @MainActor static var callout: SwiftUI.Font { style(.callout) }
        @MainActor static var subheadline: SwiftUI.Font { style(.subheadline) }
        @MainActor static var headline: SwiftUI.Font { style(.headline) }
        @MainActor static var body: SwiftUI.Font { style(.body) }
        @MainActor static var bodyStrong: SwiftUI.Font { body.weight(.semibold) }
        @MainActor static var title3: SwiftUI.Font { style(.title3) }
        @MainActor static var title2: SwiftUI.Font { style(.title2) }
        @MainActor static var title: SwiftUI.Font { title3.weight(.semibold) }
        @MainActor static var mono: SwiftUI.Font { style(.body, design: .monospaced) }
    }

    /// UI-01 type roles (docs/DESIGN_SYSTEM.md): section label, item name, secondary text. AppKit
    /// fonts, for the tree and other cell-based lists.
    enum Role {
        @MainActor static var sectionLabel: NSFont { .systemFont(ofSize: NSFont.smallSystemFontSize * Font.zoom, weight: .semibold) }
        @MainActor static var itemName: NSFont { .systemFont(ofSize: NSFont.systemFontSize * Font.zoom, weight: .medium) }
        @MainActor static var secondary: NSFont { .monospacedDigitSystemFont(ofSize: NSFont.smallSystemFontSize * Font.zoom, weight: .regular) }
    }

    enum Size {
        /// The unpinned session title bar's strip: thin, but tall enough to find with the pointer.
        static let titleStrip: CGFloat = 4
        /// The narrowest session area worth keeping beside the inspector.
        static let sessionAreaMin: CGFloat = 220
        /// The session column's own fitting width on macOS 26+ (measured 233 pt with the SDK 27 link, #1104),
        /// before SwiftUI adds the library and inspector it extends under.
        static let sessionContentMin: CGFloat = 240
        /// A connection page's readable column, at the leading edge; wider windows leave the rest empty.
        static let connectionPageMax: CGFloat = 720
        /// Folder dashboard (DASH-01): Name and Address keep a readable width; other columns share the rest.
        static let dashboardNameMin: CGFloat = 120
        static let dashboardNameIdeal: CGFloat = 200
        static let dashboardAddressIdeal: CGFloat = 160
        /// Session tabs: the narrowest a tab shrinks to (icon and a few letters) before the
        /// strip scrolls with ‹ ›, and the widest it grows to.
        static let tabMin: CGFloat = 116
        /// Content-sized tabs (owner feedback 12): never narrower than this; no upper cap (owner 2026-11-16).
        static let tabContentMin: CGFloat = 72
        static let tabMax: CGFloat = 200
        /// A pinned, icon-only tab.
        static let pinnedTab: CGFloat = 34
        static let verticalTabs: CGFloat = 220
        static let sidebarMin: CGFloat = 200
        static let sidebarIdeal: CGFloat = 250
        /// Compact header, library hidden: traffic lights plus the switcher icon before the tabs.
        static let compactHiddenLeading: CGFloat = 130
        /// Credentials section under the connection tree when expanded.
        static let credentialsSection: CGFloat = 180
        /// The credentials bar's height range when dragged (owner 2026-11-16).
        static let credentialsSectionMin: CGFloat = 80
        static let credentialsSectionMax: CGFloat = 600
        /// Inspector limits, as in the core's `theme::INSPECTOR_*`.
        static let inspectorMin: CGFloat = 260
        static let inspectorIdeal: CGFloat = 300
        static let inspectorMax: CGFloat = 460
        /// Quick Connect popover anchor from the session area's trailing edge, so the popover clears it.
        static let quickConnectAnchorInset: CGFloat = 200
        static let labelColumn: CGFloat = 88
        static let dialogWidth: CGFloat = 360
        static let emptyStateWidth: CGFloat = 320
        static let swatch: CGFloat = 18
        static let settingsWidth: CGFloat = 440
        static let editorWidth: CGFloat = 780
        static let editorHeight: CGFloat = 520
        static let editorNav: CGFloat = 200
        static let editorLabel: CGFloat = 150
        static let addMenuWidth: CGFloat = 340
        static let numberField: CGFloat = 120
        static let managerWidth: CGFloat = 520
        static let managerHeight: CGFloat = 340
        static let paletteWidth: CGFloat = 560
        static let paletteRows: CGFloat = 320
        /// Smallest click target (owner 2026-11-05 layout-fit rule).
        static let minHitTarget: CGFloat = 24
        /// Owner 2026-11-05 (d): the main window works from 600 x 400 (nm-resize, nm-fit). The
        /// height is the content's, under the 38 pt unified toolbar, so the window frame reaches 400.
        static let windowMinWidth: CGFloat = 600
        static let windowMinHeight: CGFloat = 362
        /// Tree selection shape, as AppKit's source-list selection.
        static let selectionInset: CGFloat = 10
        static let selectionRadius: CGFloat = 5
        /// Shortcut recorder button: fits "Type shortcut…" and the longest chord (⌃⌥⇧⌘F12).
        static let shortcutField: CGFloat = 104
        /// Longest workspace name the toolbar shows before truncating.
        static let toolbarWorkspace: CGFloat = 150
    }
}

/// SF Symbol for a connection's protocol; the mapping lives in `Icons` (from the core's icon ids).
func protocolSymbol(_ proto: String) -> String {
    Icons.symbol(proto)
}

extension Error {
    /// The sentence to show a person: the core's message without the bridge's wrapping.
    var userMessage: String {
        guard case FfiError.Failed(let message, _)? = self as? FfiError else { return localizedDescription }
        let text = message.hasPrefix("invalid input: ") ? String(message.dropFirst("invalid input: ".count)) : message
        return text.prefix(1).uppercased() + text.dropFirst()
    }
}

/// Icon-only buttons: the icon centred in at least a DS.Size.minHitTarget square that takes the
/// click, so small symbols keep a 24 pt target (nm-fit SMALL). The title stays the accessibility label.
struct IconHitTargetLabelStyle: LabelStyle {
    /// One square for every icon button in a row (MAC-UI-02 evenness): a minimum let wide symbols
    /// ("folder" 27 pt, "arrow.left.arrow.right" 25 pt high) grow their own button, so rows had
    /// uneven sizes and gaps. The square fits the widest body-size symbol and follows View › Zoom.
    static let bodyEms: CGFloat = 2.15
    @MainActor static var side: CGFloat {
        max(DS.Size.minHitTarget, (DS.Font.points(.body) * DS.Font.zoom * bodyEms).rounded(.up))
    }

    func makeBody(configuration: Configuration) -> some View {
        configuration.icon
            .frame(width: Self.side, height: Self.side)
            .contentShape(Rectangle())
    }
}

extension LabelStyle where Self == IconHitTargetLabelStyle {
    static var iconHitTarget: IconHitTargetLabelStyle { .init() }
}

extension View {
    /// An icon (a button's label) in at least a 24 pt square that takes the click.
    func iconHitTarget() -> some View {
        frame(minWidth: DS.Size.minHitTarget, minHeight: DS.Size.minHitTarget).contentShape(Rectangle())
    }
}

/// The app's two button roles (MAC-MODERN-UI). macOS 26+ draws them in Liquid Glass; macOS 14–25
/// get the bordered capsule that matches it. Use these instead of the default bezel for any
/// standalone action button (sheet footers, empty states, inline actions).
extension View {
    /// The one main action of a sheet or page (Run, Save, Add Connection).
    @ViewBuilder func dsPrimaryButton() -> some View {
        if #available(macOS 26, *) {
            buttonStyle(.glassProminent).buttonBorderShape(.capsule)
        } else {
            buttonStyle(.borderedProminent).buttonBorderShape(.capsule)
        }
    }

    /// A secondary action beside the primary one (Done, Cancel, Import…).
    @ViewBuilder func dsSecondaryButton() -> some View {
        if #available(macOS 26, *) {
            buttonStyle(.glass).buttonBorderShape(.capsule)
        } else {
            buttonStyle(.bordered).buttonBorderShape(.capsule)
        }
    }
}

/// A sheet's bottom bar: status text on the left, actions on the right, on the window background.
struct SheetFooter<Actions: View>: View {
    let status: String
    var isProblem = false
    @ViewBuilder var actions: Actions

    var body: some View {
        HStack(spacing: DS.Space.s) {
            Text(status).font(DS.Font.callout)
                .foregroundStyle(isProblem ? Color.red : Color.secondary)
                .lineLimit(2).textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
            actions
        }
        .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
    }
}
