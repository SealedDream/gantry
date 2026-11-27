import BastionCore
import Foundation

/// Keychain Deny/Cancel (-128) is the user's choice, not an error (owner point 15): recognise it
/// wherever it surfaces and never show the raw "Keychain error -128" text.
enum KeychainQuiet {
    struct LockedPersonal: Error {}

    static func isCancel(_ error: Error) -> Bool {
        if case LibraryKey.Failure.cancelled = error { return true }
        if case EnclaveSeal.Failure.cancelled = error { return true }
        if case let FfiError.Failed(_, code) = error, code == "cancelled" { return true }
        return "\(error)".contains("Keychain error -128")
    }

    /// The user-facing text of a core error (its message, not the Swift enum dump).
    static func message(_ error: Error) -> String {
        if case let FfiError.Failed(message, _) = error { return message }
        return error.localizedDescription
    }
}
