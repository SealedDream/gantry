import AppKit
import BastionCore

/// Copy and Save Snippet for log views (Journal/Event Log, task output). Text is cleaned by the
/// core (escape sequences and control bytes removed) and a saved snippet is a new owner-only file
/// that never replaces an existing one.
enum LogSnippet {
    /// Folder Save Snippet writes to without asking (UI driver); nil shows a folder panel.
    @MainActor static var folderOverride: URL?
    /// The pasteboard Copy writes to (the UI driver uses its own).
    @MainActor static var board = NSPasteboard.general

    @MainActor static func copy(_ lines: [String]) {
        let text = cleanLogSnippet(text: lines.joined(separator: "\n"), stripAnsi: true)
        guard !text.isEmpty else { return }
        board.clearContents()
        board.setString(text, forType: .string)
    }

    /// Ask for a folder (unless overridden), write the snippet, and return a status line.
    @MainActor static func save(_ lines: [String], name: String, header: String) -> (message: String, isError: Bool)? {
        guard let dir = folderOverride ?? chooseFolder() else { return nil }
        do {
            let path = try exportLogSnippet(dir: dir.path, name: name, header: header, text: lines.joined(separator: "\n"), stripAnsi: true)
            if folderOverride == nil { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
            return ("Saved \((path as NSString).lastPathComponent)", false)
        } catch {
            return ("\(error)", true)
        }
    }

    @MainActor private static func chooseFolder() -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.prompt = "Save Snippet Here"
        panel.directoryURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func header(_ title: String) -> String {
        "# \(title) · \(Date.now.formatted(date: .abbreviated, time: .standard))"
    }
}

extension Notification.Name {
    /// Copy the visible lines of the selected log view (UI driver).
    static let logCopyVisible = Notification.Name("BastionLogCopyVisible")
    /// Save the selected lines (or all visible lines) of the selected log view as a snippet (UI driver).
    static let logSaveSnippet = Notification.Name("BastionLogSaveSnippet")
}
