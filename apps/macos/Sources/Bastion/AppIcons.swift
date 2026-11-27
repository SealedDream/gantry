import AppKit

/// Line icons for the app's own pages (Tasks, Triggers, Audit Log, Activity, Plugins). They use
/// the secondary label colour, so they never look like a connection's coloured tile. The SF Symbols
/// match the owner-approved drawings in docs/design/icons/app-*.svg.
enum AppIcons: String, CaseIterable {
    case tasks = "checklist"
    case triggers = "bolt"
    case auditLog = "checkmark.shield"
    case activity = "clock.arrow.circlepath"
    case plugins = "powerplug"

    var label: String {
        switch self {
        case .tasks: "Tasks"
        case .triggers: "Triggers"
        case .auditLog: "Audit Log"
        case .activity: "Activity"
        case .plugins: "Plugins"
        }
    }

    @MainActor static func image(_ icon: AppIcons, pointSize: CGFloat) -> NSImage? {
        let config = NSImage.SymbolConfiguration(pointSize: pointSize, weight: .regular)
            .applying(.init(hierarchicalColor: .secondaryLabelColor))
        return NSImage(systemSymbolName: icon.rawValue, accessibilityDescription: icon.label)?.withSymbolConfiguration(config)
    }
}
