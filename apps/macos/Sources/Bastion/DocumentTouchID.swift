import BastionCore
import CryptoKit
import Foundation
import LocalAuthentication

/// "Save for Touch ID" on the unlock sheet. Per document, this Mac keeps:
/// - a random 32-byte wrapping key, sealed by a Secure Enclave key whose access control is
///   `.biometryCurrentSet` (only the fingers enrolled now; re-enrolling or removing Touch ID
///   makes it unreadable, and the Mac login password does NOT open it);
/// - the document key wrapped by that key (core `exportKeyWrappedBy`, XChaCha20-Poly1305 bound
///   to the document id). Never the password.
/// All three are 0600 files in `<data dir>/touch-id/`. No login-Keychain item and no
/// code-signing identity is needed, so it also works in the owner's unsigned builds.
/// Older builds kept the wrapped key in a data-protection Keychain item (`DocumentKeychain`);
/// it is still read once with the same Touch ID and then moved here.
@MainActor
enum DocumentTouchID {
    private static let salt = Data("bastion-document-touch-id/v1".utf8)
    private static let info = Data("document-wrapping-key".utf8)

    private static var dir: URL { LibraryModel.dataDir.appendingPathComponent("touch-id", isDirectory: true) }

    private static func files(_ id: String) -> (seal: EnclaveSeal.Files, wrapped: URL) {
        let safe = id.filter { $0.isHexDigit || $0 == "-" }
        return (EnclaveSeal.Files(enclave: dir.appendingPathComponent("\(safe).se"), sealed: dir.appendingPathComponent("\(safe).sealed")),
                dir.appendingPathComponent("\(safe).wrapped"))
    }

    /// Touch ID can open this document on this Mac (no prompt to find out).
    static func isSaved(_ id: String) -> Bool {
        let f = files(id)
        return f.seal.exist && FileManager.default.fileExists(atPath: f.wrapped.path)
    }

    /// Saved here, or still in an older build's Keychain item (moved on first Touch ID use).
    static func hasCopy(_ id: String) -> Bool { isSaved(id) || DocumentKeychain.exists(documentId: id) }

    /// Whether this Mac can keep a Touch ID copy at all (enclave present, policy allows it).
    static var available: Bool { SecureEnclave.isAvailable && documentBiometricUnlockAllowed() }

    /// Save the unlocked document's key for Touch ID. Needs no Touch ID itself.
    static func save(_ handle: BastionDocument) throws {
        let id = handle.info().id
        let f = files(id)
        var raw = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }
        defer { raw.resetBytes(in: 0..<raw.count) }
        let wrapped = try handle.exportKeyWrappedBy(wrappingKey: raw)
        try EnclaveSeal.seal(raw, to: f.seal, flags: .biometryCurrentSet, salt: salt, info: info)
        try EnclaveSeal.writePrivate(Data(wrapped.utf8), to: f.wrapped)
        DocumentKeychain.delete(documentId: id)
    }

    /// Forget this Mac's Touch ID copy ("Don't save for Touch ID").
    static func forget(_ id: String) {
        let f = files(id)
        EnclaveSeal.remove(f.seal)
        try? FileManager.default.removeItem(at: f.wrapped)
        DocumentKeychain.delete(documentId: id)
    }

    /// One Touch ID evaluation, shown over the unlock sheet. Returns the authenticated context
    /// (reused for every key this unlock opens), or nil when cancelled or unavailable.
    static func authenticate(name: String) async -> LAContext? {
        let context = LAContext()
        context.localizedFallbackTitle = "Use Password"
        context.localizedCancelTitle = "Cancel"
        do {
            let ok = try await context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "unlock “\(name)”")
            return ok ? context : nil
        } catch {
            return nil
        }
    }

    /// Unlock `handle` with an authenticated `context`. False when this Mac keeps no copy.
    /// A legacy Keychain copy is used once and moved into the enclave store.
    static func unlock(_ handle: BastionDocument, context: LAContext) throws -> Bool {
        let id = handle.info().id
        let f = files(id)
        if isSaved(id) {
            var raw = try EnclaveSeal.open(f.seal, salt: salt, info: info, context: context)
            defer { raw.resetBytes(in: 0..<raw.count) }
            let wrapped = try String(contentsOf: f.wrapped, encoding: .utf8)
            try handle.unlockKeyWrappedBy(wrapped: wrapped, wrappingKey: raw)
            return true
        }
        guard let legacy = try DocumentKeychain.read(documentId: id, context: context) else { return false }
        try handle.unlockWrappedKey(wrapped: legacy)
        try? save(handle)
        return true
    }
}
