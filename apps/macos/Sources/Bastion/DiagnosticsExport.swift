import AppKit
import BastionCore
import UniformTypeIdentifiers

/// Help ▸ Export Diagnostics… (LOG-NATIVE-01 item 7, Native Mac): asks where to save, says what is
/// inside, and writes the zip off the main thread. The file stays where the user saves it.
@MainActor
enum DiagnosticsExport {
    /// Starts the app log next to the library (test runs with `BASTION_LIBRARY` use their own).
    static func startLog() {
        AppLog.url = LibraryModel.dataDir.appendingPathComponent("bastion.log")
        AppLog.redactor = { logRedact(text: $0) }
        DetailedLog.apply(SettingsModel())
        AppLog.info("Launched \(version.0) (\(version.1)) on macOS \(ProcessInfo.processInfo.operatingSystemVersionString)")
    }

    static var version: (String, String) {
        let info = Bundle.main.infoDictionary ?? [:]
        return (info["CFBundleShortVersionString"] as? String ?? "dev", info["CFBundleVersion"] as? String ?? "dev")
    }

    static func counts(_ tree: FolderView?) -> DiagnosticsCounts {
        var c = DiagnosticsCounts()
        func walk(_ f: FolderView) {
            c.folders += f.folders.count
            for conn in f.connections {
                c.connections += 1
                c.byProtocol[conn.protocol, default: 0] += 1
            }
            f.folders.forEach(walk)
        }
        if let tree { walk(tree) }
        return c
    }

    static func inputs(_ tree: FolderView?) -> DiagnosticsBundle.Inputs {
        let log = AppLog.url ?? LibraryModel.dataDir.appendingPathComponent("bastion.log")
        let reports = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/DiagnosticReports")
        return DiagnosticsBundle.Inputs(
            summary: DiagnosticsBundle.summary(version: version.0, build: version.1, os: ProcessInfo.processInfo.operatingSystemVersionString,
                                               counts: counts(tree), created: Date(), detailedLog: AppLog.detailed),
            settings: SettingsModel.path,
            logs: [log, log.appendingPathExtension("1")].filter { FileManager.default.fileExists(atPath: $0.path) },
            crash: DiagnosticsBundle.latestCrash(in: reports),
            home: NSHomeDirectory(), user: NSUserName())
    }

    /// Shows the save dialog; returns an error text, or nil on success or cancel.
    static func run(_ tree: FolderView?, done: @escaping @MainActor (String?) -> Void) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.zip]
        let day = Date().formatted(.iso8601.year().month().day())
        panel.nameFieldStringValue = "Gantry diagnostics \(day).zip"
        panel.message = "Contains \(DiagnosticsBundle.contents)."
        guard panel.runModal() == .OK, let url = panel.url else { return done(nil) }
        write(tree, to: url, done: done)
    }

    static func write(_ tree: FolderView?, to url: URL, done: @escaping @MainActor (String?) -> Void) {
        let inputs = inputs(tree)
        Task.detached(priority: .userInitiated) {
            let problem: String?
            do { try DiagnosticsBundle.write(inputs, to: url); problem = nil } catch { problem = "Diagnostics export failed: \(error.localizedDescription)" }
            AppLog.write(problem == nil ? .info : .error, problem ?? "Exported diagnostics")
            await MainActor.run { done(problem) }
        }
    }
}
