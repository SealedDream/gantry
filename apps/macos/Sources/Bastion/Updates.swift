import AppKit
import BastionCore

/// "Check for Updates…": the core checks the latest GitHub release's signed manifest, and on
/// request downloads this Mac's archive (size and SHA-256 checked against the signed manifest).
/// After a second confirmation the app in /Applications is replaced and relaunched.
enum UpdateChecker {
    /// Title of the check made at launch (`updates.check-at-launch`), for the UI test driver.
    @MainActor static var lastLaunchReport: String?

    /// The release asset this build installs from (see scripts/release.sh).
    static var assetName: String {
        #if arch(arm64)
        "Gantry-macos-arm64.zip"
        #else
        "Gantry-macos-x86_64.zip"
        #endif
    }

    enum Action {
        case download(file: String, version: String)
        case install(zip: URL, version: String)
    }

    struct Report: Identifiable {
        let id = UUID()
        var available = false
        let title: String
        let message: String
        /// The confirm button's step, when there is one.
        var action: Action?

        var actionTitle: String {
            switch action {
            case .download: "Download"
            case .install: "Install and Relaunch"
            case nil: "OK"
            }
        }
    }

    static func check() async -> Report {
        let result = await Task.detached { Result { try checkForUpdates() } }.value
        switch result {
        case .success(let s) where s.available:
            let expires = s.manifestExpires.map {
                Date(timeIntervalSince1970: TimeInterval($0)).formatted(date: .abbreviated, time: .omitted)
            }
            let file = s.files.first { $0.name == assetName }
            let size = file.map { ByteCountFormatter.string(fromByteCount: Int64($0.size), countStyle: .file) }
            return Report(available: true, title: "Gantry \(s.latest) is available",
                          message: ["You have \(s.installed).", s.notes.isEmpty ? nil : s.notes,
                                    size.map { "Download: \($0), checked against the signed release before it is used." }
                                        ?? "This release has no build for this Mac.",
                                    expires.map { "Signed release information, valid until \($0)." }]
                              .compactMap { $0 }.joined(separator: "\n\n"),
                          action: file.map { .download(file: $0.name, version: s.latest) })
        case .success(let s):
            return Report(title: "Gantry is up to date", message: "Version \(s.installed) is the latest release.")
        case .failure(let e) where isOffline(e):
            // Offline mode (BASTION_OFFLINE=1): refused before any packet; not a failure to report.
            return Report(title: offlineTitle, message: "Offline mode is on, so Gantry does not contact the update server.")
        case .failure(let e):
            return failure("Could not check for updates", e)
        }
    }

    static let offlineTitle = "Not checked: offline mode"

    /// The core's `CoreError::Offline` (error code `offline`).
    static func isOffline(_ e: Error) -> Bool {
        if case FfiError.Failed(_, let code) = e { return code == "offline" }
        return false
    }

    /// Runs a report's action and returns the next report to show.
    static func perform(_ action: Action) async -> Report {
        switch action {
        case .download(let file, let version):
            let result = await Task.detached { Result { try UpdateInstaller.download(file) } }.value
            switch result {
            case .success(let zip):
                return Report(title: "Gantry \(version) is ready",
                              message: "The download matches the signed release. Install it now? Gantry will quit, replace \(UpdateInstaller.destination.path) and reopen. Open sessions will close.",
                              action: .install(zip: zip, version: version))
            case .failure(let e):
                return failure("Could not download the update", e)
            }
        case .install(let zip, let version):
            let result = await Task.detached { Result { try UpdateInstaller.install(zip, version: version) } }.value
            switch result {
            case .success(let app):
                await MainActor.run { UpdateInstaller.relaunch(app) }
                return Report(title: "Relaunching…", message: "")
            case .failure(let e):
                return failure("Could not install the update", e)
            }
        }
    }

    private static func failure(_ title: String, _ e: Error) -> Report {
        let message: String
        if case FfiError.Failed(let m, _) = e { message = m } else { message = (e as? LocalizedError)?.errorDescription ?? "\(e)" }
        let code = errorCode(area: "UPD", message: message)
        AppLog.failure(code: code, message)
        return Report(title: title, message: "\(message)\n\n\(code)")
    }
}

/// Download, unpack, check and swap the app bundle. Builds are ad hoc signed, so the checks are
/// the signed manifest (done in the core), the bundle id and version, and `codesign --verify`
/// (the bundle is intact).
enum UpdateInstaller {
    struct Failure: LocalizedError {
        let errorDescription: String?
        init(_ message: String) { errorDescription = message }
    }

    private static let bundleId = "dev.gantry.terminal"

    /// The running app when it lives in /Applications, else /Applications/Gantry.app.
    static var destination: URL {
        let running = Bundle.main.bundleURL
        return running.deletingLastPathComponent().path == "/Applications" && running.pathExtension == "app"
            ? running : URL(fileURLWithPath: "/Applications/Gantry.app")
    }

    static func download(_ file: String) throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("BastionUpdate-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return URL(fileURLWithPath: try downloadUpdate(fileName: file, destDir: dir.path))
    }

    /// Unpacks `zip`, checks the app inside, and puts it at `destination`; returns that URL.
    static func install(_ zip: URL, version: String) throws -> URL {
        let unpacked = zip.deletingLastPathComponent().appendingPathComponent("unpacked")
        try run("/usr/bin/ditto", ["-x", "-k", zip.path, unpacked.path])
        let app = unpacked.appendingPathComponent("Gantry.app")
        guard let info = Bundle(url: app)?.infoDictionary,
              info["CFBundleIdentifier"] as? String == bundleId else {
            throw Failure("The download does not contain Gantry.app.")
        }
        guard info["CFBundleShortVersionString"] as? String == version else {
            throw Failure("The downloaded app is not version \(version).")
        }
        try run("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path])
        try? run("/usr/bin/xattr", ["-dr", "com.apple.quarantine", app.path])
        let target = destination
        do {
            if FileManager.default.fileExists(atPath: target.path) {
                _ = try FileManager.default.replaceItemAt(target, withItemAt: app, backupItemName: nil, options: [])
            } else {
                try FileManager.default.moveItem(at: app, to: target)
            }
        } catch {
            NSWorkspace.shared.activateFileViewerSelecting([app])
            throw Failure("Could not write \(target.path) (\(error.localizedDescription)). The verified app is shown in Finder: drag it to Applications.")
        }
        try? FileManager.default.removeItem(at: zip.deletingLastPathComponent())
        return target
    }

    /// Opens `app` once this process has exited, then quits.
    @MainActor static func relaunch(_ app: URL) {
        let waiter = Process()
        waiter.executableURL = URL(fileURLWithPath: "/bin/sh")
        waiter.arguments = ["-c", "pid=$1; shift; while kill -0 \"$pid\" 2>/dev/null; do sleep 0.2; done; exec /usr/bin/open \"$@\"", "sh",
                            String(ProcessInfo.processInfo.processIdentifier)] + testRelaunchArguments() + [app.path]
        do {
            try waiter.run()
            QuitConfirm.terminateWithoutAsking()
        } catch {
            NSLog("Gantry relaunch failed: %@", "\(error)")
        }
    }

    /// Test builds: the relaunched app keeps the test's BASTION_* settings (its throwaway library and
    /// the fake update server, never the user's own data) and opens in the background. Not the UI
    /// script, which belongs to the first run. Release builds pass nothing.
    private static func testRelaunchArguments() -> [String] {
        #if BASTION_TEST_HOOKS
        return ["-g"] + ProcessInfo.processInfo.environment
            .filter { $0.key.hasPrefix("BASTION_") && $0.key != "BASTION_UI_SCRIPT" }
            .sorted { $0.key < $1.key }
            .flatMap { ["--env", "\($0.key)=\($0.value)"] }
        #else
        return []
        #endif
    }

    private static func run(_ tool: String, _ args: [String]) throws {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        let err = Pipe()
        p.standardError = err
        try p.run()
        p.waitUntilExit()
        guard p.terminationStatus == 0 else {
            let text = String(data: err.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            throw Failure("\(URL(fileURLWithPath: tool).lastPathComponent) failed: \(text.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }
}
