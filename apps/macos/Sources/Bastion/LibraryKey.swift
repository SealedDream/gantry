import CryptoKit
import BastionCore
import Foundation
import LocalAuthentication

/// The device key that opens every library on this Mac (OF-F, owner points 14/15/20). It is
/// never a Keychain item: an ad-hoc build's Keychain access is pinned to its code hash, so every
/// update prompted again. Instead (owner decision 2026-11-07, option A + Touch ID):
/// - Touch ID on (default when available): the key is sealed by a Secure Enclave P-256 key
///   (`.userPresence`: Touch ID or the login password). The enclave key's opaque blob and the
///   sealed key are 0600 files; the blob only works inside this Mac's enclave, and no entitlement
///   or code identity is involved, so a rebuilt app opens it with just Touch ID.
/// - Touch ID off or unavailable: the key is a 0600 file only this account can read.
/// The key is read once per launch and cached; every caller shares that one read.
enum LibraryKey {
    enum Failure: LocalizedError {
        case cancelled, corrupt
        var errorDescription: String? {
            switch self {
            case .cancelled: return "Touch ID was cancelled."
            case .corrupt: return "The library key file is damaged."
            }
        }
    }

    private static let lock = NSLock()
    nonisolated(unsafe) private static var cached: String?

    static var useSecureEnclave: Bool { SecureEnclave.isAvailable }
    private static let salt = Data("bastion-device-key/v1".utf8)

    private static func files(_ dir: URL) -> (plain: URL, enclave: URL, sealed: URL) {
        (dir.appendingPathComponent("device-key"), dir.appendingPathComponent("device-key.se"), dir.appendingPathComponent("device-key.sealed"))
    }

    /// True when reading the device key would show Touch ID (sealed, not read yet this launch).
    /// The launch then defers Personal so the unlock sheet's one Touch ID opens both.
    static func needsPrompt(in dir: URL) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if cached != nil || TestHooks.env("BASTION_DEVICE_KEY").map({ !$0.isEmpty }) == true { return false }
        return FileManager.default.fileExists(atPath: files(dir).sealed.path)
    }

    /// The device key (hex) for `dir`, created on first use. `touchID` picks how a new key is
    /// kept, and converts an existing one after it opened. `context`: an already evaluated
    /// Touch ID context (the unlock sheet's) opens the sealed key without a second prompt.
    /// Throws `.cancelled` when Touch ID was dismissed: callers stay quiet and show the locked state.
    static func deviceKey(in dir: URL, touchID: Bool, context: LAContext? = nil) throws -> String {
        lock.lock()
        defer { lock.unlock() }
        if let cached { return cached }
        if let test = TestHooks.env("BASTION_DEVICE_KEY"), !test.isEmpty {
            cached = test
            return test
        }
        let f = files(dir)
        let fm = FileManager.default
        let key: String
        if fm.fileExists(atPath: f.sealed.path) {
            key = try unseal(f, context: context)
        } else if fm.fileExists(atPath: f.plain.path) {
            guard let s = try? String(contentsOf: f.plain, encoding: .utf8), !s.isEmpty else { throw Failure.corrupt }
            key = s.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            key = personalNewDeviceKey()
        }
        try store(key, f, touchID: touchID && useSecureEnclave)
        cached = key
        return key
    }

    /// Keep `key` the way the setting asks, removing the other form only after the new one is written.
    private static func store(_ key: String, _ f: (plain: URL, enclave: URL, sealed: URL), touchID: Bool) throws {
        let fm = FileManager.default
        let sealed = EnclaveSeal.Files(enclave: f.enclave, sealed: f.sealed)
        if touchID {
            if fm.fileExists(atPath: f.sealed.path) { return }
            try EnclaveSeal.seal(Data(key.utf8), to: sealed, flags: .userPresence, salt: salt, info: info)
            try? fm.removeItem(at: f.plain)
        } else {
            if fm.fileExists(atPath: f.plain.path), !fm.fileExists(atPath: f.sealed.path) { return }
            try EnclaveSeal.writePrivate(Data(key.utf8), to: f.plain)
            EnclaveSeal.remove(sealed)
        }
    }

    private static let info = Data("library-key".utf8)

    private static func unseal(_ f: (plain: URL, enclave: URL, sealed: URL), context: LAContext?) throws -> String {
        let ctx = context ?? LAContext()
        if context == nil { ctx.localizedReason = "open your Gantry libraries" }
        do {
            let plain = try EnclaveSeal.open(EnclaveSeal.Files(enclave: f.enclave, sealed: f.sealed), salt: salt, info: info, context: ctx)
            guard let s = String(data: plain, encoding: .utf8) else { throw Failure.corrupt }
            return s
        } catch EnclaveSeal.Failure.cancelled {
            throw Failure.cancelled
        } catch EnclaveSeal.Failure.corrupt {
            throw Failure.corrupt
        }
    }

    /// Tests only: forget the cached key.
    static func resetForTests() { lock.lock(); cached = nil; lock.unlock() }
}
