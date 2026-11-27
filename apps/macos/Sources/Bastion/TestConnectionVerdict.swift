import Foundation

// SEC-07: what a finished Test Connection report means, and the host-key question put to the
// user. Plain values with no core or UI types, so `tests/sec-07-verdict-test.sh` can check them
// without building the app.

/// One step of a report, reduced to what the verdict needs.
struct ProbeStepFact: Equatable {
    /// `dns`, `tcp`, `handshake`, `host_key`, `jump_host`, `login`.
    let kind: String
    /// `ok`, `warn`, `failed`, `skipped`.
    let status: String
}

/// Why the host-key check failed (SEC-07-FU1), from the report's `hostKeyFailure`.
enum HostKeyRefusal: Equatable {
    /// A known host showed another key.
    case changed
    /// known_hosts could not be read.
    case knownHostsUnreadable
    /// The report did not say (an older core, or a kind this app does not know).
    case unspecified

    init(_ kind: String?) {
        switch kind {
        case "changed": self = .changed
        case "known_hosts_unreadable": self = .knownHostsUnreadable
        default: self = .unspecified
        }
    }
}

/// What a finished test means for the panel. Decided here and nowhere else.
enum ProbeVerdict: Equatable {
    /// The target's key is not in known_hosts and the sign-in would send a password. Nothing
    /// was sent; the test goes on only after the user confirms this fingerprint.
    case waitingForHostKey(fingerprint: String)
    case cancelled
    /// The host-key check itself failed (a known host showed another key, or known_hosts could
    /// not be read). Never offered for confirmation in a test.
    case hostKeyRefused(HostKeyRefusal)
    case failed
    case passed

    /// The waiting fingerprint is read before `ok`: a waiting report has `ok == true` because no
    /// step failed, and must never count as a working connection.
    static func of(ok: Bool, cancelled: Bool, needsHostKeyConfirmation: String?, steps: [ProbeStepFact],
                   hostKeyFailure: String? = nil) -> ProbeVerdict {
        if cancelled { return .cancelled }
        if steps.contains(where: { $0.kind == "host_key" && $0.status == "failed" }) { return .hostKeyRefused(HostKeyRefusal(hostKeyFailure)) }
        if let fingerprint = needsHostKeyConfirmation {
            // A blank fingerprint cannot be shown or confirmed: fail safe, never a pass.
            return fingerprint.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? .failed : .waitingForHostKey(fingerprint: fingerprint)
        }
        return ok ? .passed : .failed
    }

    /// The line above the steps, where the steps alone could be misread.
    var headline: (text: String, isError: Bool)? {
        switch self {
        case .waitingForHostKey:
            (HostKeyQuestion.waitingHeadline, false)
        case .hostKeyRefused(.changed):
            ("The server's host key has changed since the last connection. Do not connect until the administrator confirms the new key; no sign-in was sent.", true)
        case .hostKeyRefused(.knownHostsUnreadable):
            ("The known_hosts file could not be read, so the host key was not checked. Check the file's permissions; no sign-in was sent.", true)
        case .hostKeyRefused(.unspecified):
            ("The host key was refused. It cannot be confirmed from a test, and no sign-in was sent.", true)
        case .cancelled, .failed, .passed:
            nil
        }
    }
}

/// The host key a test is waiting on. It is always the target's: the core never offers a jump
/// host's key for confirmation in a test (an unknown jump-host key is a failed step).
struct HostKeyQuestion: Equatable, Identifiable {
    static let trustTitle = "Trust and Test Sign-In"
    static let waitingHeadline = "Sign-in not tested: the host key is not confirmed. Press Test Connection again to review the key."

    let host: String
    let jumpHosts: [String]
    /// Exactly the string from the report; confirming sends back this and nothing else.
    let fingerprint: String
    /// The user confirmed another fingerprint for the previous run and the server now shows this one.
    let differsFromConfirmed: Bool

    var id: String { fingerprint }

    /// The host as named in the prompt; on a jump-host route it says whose key this is.
    var subject: String {
        if jumpHosts.isEmpty { return host }
        return "\(host) (the target, reached through jump host\(jumpHosts.count == 1 ? "" : "s") \(jumpHosts.joined(separator: ", ")))"
    }

    /// Under the fingerprint: what confirming does and does not do.
    var note: String {
        let scope = "Trusting applies to this test only. Nothing is saved to known_hosts, so the first real connection asks again. No sign-in has been sent yet."
        return differsFromConfirmed ? "The server now shows a different key from the one you confirmed. " + scope : scope
    }

    /// The question for `verdict`, or nil when the test is not waiting. `lastConfirmed` is the
    /// fingerprint the user confirmed for the run that produced this verdict, if any.
    static func from(_ verdict: ProbeVerdict, host: String, jumpHosts: [String], lastConfirmed: String?) -> HostKeyQuestion? {
        guard case .waitingForHostKey(let fingerprint) = verdict else { return nil }
        return HostKeyQuestion(host: host, jumpHosts: jumpHosts, fingerprint: fingerprint,
                               differsFromConfirmed: lastConfirmed != nil && lastConfirmed != fingerprint)
    }
}
