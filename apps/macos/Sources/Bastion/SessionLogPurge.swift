import Foundation
import BastionCore

/// Applies session log retention once at launch (LOG-CORE-02): keep-days and size limit from
/// Settings, and each folder's own keep-days when the library is open. Off the main thread; a
/// failure is logged, never shown, and the next launch tries again.
enum SessionLogPurge {
    @MainActor static func run(library: Library?, settingFolder: String) {
        let dataDir = LibraryModel.dataDir.path
        DispatchQueue.global(qos: .utility).async { _ = purge(library: library, settingFolder: settingFolder, dataDir: dataDir) }
    }

    /// Purges every root now; returns the files deleted. Blocking: call off the main thread.
    static func purge(library: Library?, settingFolder: String, dataDir: String) -> UInt32 {
        var deleted: UInt32 = 0
        for root in SessionLogFiles.purgeRoots(settingFolder: settingFolder) {
            do {
                let r = try library.map { try $0.purgeSessionLogs(root: root, dataDir: dataDir) } ?? purgeSessionLogs(root: root, dataDir: dataDir)
                deleted += r.deletedFiles
                if r.deletedFiles > 0 { AppLog.info("Session logs: deleted \(r.deletedFiles) old file(s), \(r.freedBytes) bytes") }
            } catch {
                AppLog.warn("Session logs: retention failed for \(root.isEmpty ? "default folder" : root): \(error)")
            }
        }
        return deleted
    }
}
