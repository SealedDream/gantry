import Foundation

/// Decompresses a .bz2 file with /usr/bin/bunzip2, stopping as soon as the decoded output
/// passes `limit` bytes (a bzip2 bomb would otherwise fill the disk). Same cap as rdp-ffi's
/// `decompress_bounded` (openh264.rs, MAX_LIBRARY). On any failure `destination` is removed.
enum BoundedBunzip {
    enum Failure: Error, Equatable {
        case tooLarge
        case badArchive(Int32)
    }

    private static let chunkSize = 1 << 16

    static func decompress(_ archive: URL, to destination: URL, limit: Int) throws {
        FileManager.default.createFile(atPath: destination.path, contents: nil)
        do {
            try run(archive, destination, limit)
        } catch {
            try? FileManager.default.removeItem(at: destination)
            throw error
        }
    }

    private static func run(_ archive: URL, _ destination: URL, _ limit: Int) throws {
        let out = try FileHandle(forWritingTo: destination)
        defer { try? out.close() }
        let pipe = Pipe()
        let bunzip = Process()
        bunzip.executableURL = URL(fileURLWithPath: "/usr/bin/bunzip2")
        bunzip.arguments = ["-c", archive.path]
        bunzip.standardOutput = pipe
        bunzip.standardError = FileHandle.nullDevice
        try bunzip.run()
        let reader = pipe.fileHandleForReading
        var written = 0
        while let chunk = try reader.read(upToCount: chunkSize), !chunk.isEmpty {
            written += chunk.count
            if written > limit {
                bunzip.terminate()
                bunzip.waitUntilExit()
                throw Failure.tooLarge
            }
            try out.write(contentsOf: chunk)
        }
        bunzip.waitUntilExit()
        guard bunzip.terminationStatus == 0 else { throw Failure.badArchive(bunzip.terminationStatus) }
    }
}
