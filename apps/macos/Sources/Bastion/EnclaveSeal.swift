import Darwin
import CryptoKit
import Foundation
import LocalAuthentication

/// Seal a small secret to this Mac's Secure Enclave: an enclave P-256 key (with the given
/// access control) and an ephemeral ECDH share derive an AES-GCM key over the secret. The
/// enclave key's opaque blob and the sealed bytes are 0600 files; the blob only works inside
/// this Mac's enclave. No Keychain item, entitlement or code identity is involved, so an
/// unsigned rebuild opens it with only the user's presence. Used by `LibraryKey` (device key,
/// `.userPresence`) and `DocumentTouchID` (document key, `.biometryCurrentSet`).
enum EnclaveSeal {
    enum Failure: LocalizedError {
        case cancelled, corrupt
        var errorDescription: String? {
            switch self {
            case .cancelled: return "Touch ID was cancelled."
            case .corrupt: return "The sealed key file is damaged."
            }
        }
    }

    struct Files {
        let enclave: URL
        let sealed: URL
        var exist: Bool { FileManager.default.fileExists(atPath: sealed.path) && FileManager.default.fileExists(atPath: enclave.path) }
    }

    private static let peerLen = 64

    /// Creating and sealing use the enclave key's public half only: no Touch ID here.
    static func seal(_ secret: Data, to f: Files, flags: SecAccessControlCreateFlags, salt: Data, info: Data) throws {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags.union(.privateKeyUsage), &err) else {
            throw err.map { $0.takeRetainedValue() as Error } ?? Failure.corrupt
        }
        let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
        let eph = P256.KeyAgreement.PrivateKey()
        let sym = try eph.sharedSecretFromKeyAgreement(with: se.publicKey).hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
        guard let combined = try AES.GCM.seal(secret, using: sym).combined else { throw Failure.corrupt }
        try writePrivate(se.dataRepresentation, to: f.enclave)
        try writePrivate(eph.publicKey.rawRepresentation + combined, to: f.sealed)
    }

    /// Open with `context`: an already evaluated context opens without another prompt; a fresh
    /// one shows the system Touch ID sheet. Cancel and failed Touch ID throw `.cancelled`.
    static func open(_ f: Files, salt: Data, info: Data, context: LAContext) throws -> Data {
        let blob = try Data(contentsOf: f.sealed)
        guard blob.count > peerLen else { throw Failure.corrupt }
        do {
            let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: Data(contentsOf: f.enclave), authenticationContext: context)
            let peer = try P256.KeyAgreement.PublicKey(rawRepresentation: blob.prefix(peerLen))
            let sym = try se.sharedSecretFromKeyAgreement(with: peer).hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt, sharedInfo: info, outputByteCount: 32)
            return try AES.GCM.open(AES.GCM.SealedBox(combined: blob.dropFirst(peerLen)), using: sym)
        } catch {
            if isCancel(error) { throw Failure.cancelled }
            throw error
        }
    }

    /// Touch ID dismissed or failed, recognised by error domain and code (never by message text):
    /// LocalAuthentication cancels and failures, the Security cancel/auth status, CoreCrypto's
    /// errSecUserCanceled, and the same inside an underlying error.
    static func isCancel(_ error: Error) -> Bool {
        if case CryptoKitError.underlyingCoreCryptoError(let code) = error {
            return code == errSecUserCanceled || code == errSecAuthFailed
        }
        let ns = error as NSError
        if ns.domain == LAErrorDomain {
            let codes: [LAError.Code] = [.userCancel, .appCancel, .systemCancel, .authenticationFailed, .userFallback]
            return codes.map(\.rawValue).contains(ns.code)
        }
        if ns.domain == NSOSStatusErrorDomain, ns.code == Int(errSecUserCanceled) || ns.code == Int(errSecAuthFailed) { return true }
        if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? Error { return isCancel(underlying) }
        return false
    }

    static func remove(_ f: Files) {
        try? FileManager.default.removeItem(at: f.sealed)
        try? FileManager.default.removeItem(at: f.enclave)
    }

    /// Write `data` to a temporary file created 0600 from the start (O_CREAT|O_EXCL), flush it,
    /// then rename it over `url`. The temporary file is removed on any failure.
    static func writePrivate(_ data: Data, to url: URL) throws {
        let fm = FileManager.default
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let tmp = url.appendingPathExtension("tmp")
        Darwin.unlink(tmp.path)
        let fd = Darwin.open(tmp.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var ok = false
        defer { if !ok { Darwin.unlink(tmp.path) } }
        let written = data.withUnsafeBytes { buf -> Int in
            var off = 0
            while off < buf.count {
                let n = Darwin.write(fd, buf.baseAddress! + off, buf.count - off)
                if n <= 0 { return -1 }
                off += n
            }
            return off
        }
        let synced = fsync(fd) == 0
        Darwin.close(fd)
        guard written == data.count, synced else { throw POSIXError(.EIO) }
        guard Darwin.rename(tmp.path, url.path) == 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        ok = true
    }
}
