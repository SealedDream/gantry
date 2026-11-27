import Foundation
import BastionRdp

/// Cisco's OpenH264 binary, fetched on first RDP use so Cisco (not Bastion) distributes the
/// H.264 code and pays its licence. rdp-ffi checks the SHA-256 against Cisco's release list
/// before loading it; anything that fails here just leaves RDP on its non-H.264 codecs.
enum OpenH264 {
    static let version = "2.6.0"

    private static var arch: String {
        #if arch(arm64)
        "arm64"
        #else
        "x64"
        #endif
    }

    static var fileName: String { "libopenh264-\(version)-mac-\(arch).dylib" }

    @MainActor static var libraryURL: URL {
        LibraryModel.dataDir.appendingPathComponent("codecs", isDirectory: true).appendingPathComponent(fileName)
    }

    /// Seconds to wait for Cisco's server before giving up until the next launch.
    private static let timeout: TimeInterval = 15
    /// Largest decoded library accepted (same as rdp-ffi MAX_LIBRARY).
    static let maxLibrary = 32 * 1024 * 1024
    @MainActor private static var attempted = false

    /// Hands rdp-ffi the library if it is on disk. If not, starts one background download per
    /// launch and never delays the connect: H.264 takes effect from the next session.
    @MainActor static func prepare() {
        let url = libraryURL
        if FileManager.default.fileExists(atPath: url.path) {
            setOpenh264LibraryPath(path: url.path)
            return
        }
        guard !attempted else { return }
        attempted = true
        // Offline mode (the same switch as the core and rdp-ffi): never contact Cisco; RDP uses
        // its other codecs, as when the server cannot be reached.
        if ProcessInfo.processInfo.environment["BASTION_OFFLINE"] == "1" {
            return NSLog("offline: OpenH264 is not downloaded")
        }
        Task.detached {
            do {
                try await download(to: url)
                setOpenh264LibraryPath(path: url.path)
            } catch {
                NSLog("OpenH264 unavailable, RDP uses non-H.264 codecs: \(error)")
            }
        }
    }

    private static func download(to url: URL) async throws {
        let source = URL(string: "http://ciscobinary.openh264.org/\(fileName).bz2")!
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * 4
        let (archive, response) = try await URLSession(configuration: config).download(from: source)
        defer { try? FileManager.default.removeItem(at: archive) }
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else {
            throw CocoaError(.fileReadUnknown, userInfo: [NSLocalizedDescriptionKey: "HTTP \(status)"])
        }
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let partial = url.appendingPathExtension("partial")
        try BoundedBunzip.decompress(archive, to: partial, limit: maxLibrary)
        try FileManager.default.moveItem(at: partial, to: url)
    }
}
