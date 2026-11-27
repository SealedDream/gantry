/// The app-wide terminal colour choice (`terminal.theme`). Foundation only, so tests/terminal-theme-choice builds it alone.
enum TerminalThemeChoice {
    /// Follows the app's light or dark look (core `termthemes::MATCH_APP`, the default, owner 2026-11-15).
    static let matchApp = "match-app"

    /// The theme id a `terminal.theme` value stands for: Match app theme is Bastion Light in a light app and Bastion Dark
    /// in a dark one (core `termthemes::app_theme_id`); any other value, such as a dark theme in a light app, is itself.
    static func id(_ value: String, appIsDark: Bool) -> String {
        guard value == matchApp else { return value }
        return appIsDark ? "bastion-dark" : "bastion-light"
    }
}
