use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("document is corrupt: {0}")]
    Corrupt(String),
    #[error("document was modified elsewhere (expected revision {expected}, found {found})")]
    Conflict { expected: u64, found: u64 },
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("vault is locked or the password is wrong")]
    VaultAuth,
    #[error("refusing to substitute secret variable `{0}` into this context")]
    SecretLeak(String),
    #[error("SSH error: {0}")]
    Ssh(String),
    #[error("unknown host key {fingerprint}; verify it with the server administrator before trusting it")]
    HostKeyUnknown { fingerprint: String },
    #[error("HOST KEY CHANGED (known_hosts line {line}) — possible man-in-the-middle attack; connection refused")]
    HostKeyChanged { line: usize },
    /// A jump host (not the final target) presented an unknown key. `hop` is `host:port`.
    #[error("unknown host key {fingerprint} on jump host {hop}; verify it before trusting it")]
    JumpHostKeyUnknown { hop: String, fingerprint: String },
    #[error("authentication failed")]
    AuthFailed,
    /// The user dismissed a system prompt (Keychain -128). Frontends stay quiet about it.
    #[error("cancelled")]
    Cancelled,
    /// The account needs a second factor; retry with an authenticator (TOTP) code.
    #[error("two-step login: an authenticator code is required or the code was wrong")]
    TwoFactorRequired,
    #[error("connection timed out")]
    Timeout,
    #[error("blocked by security policy: {0}")]
    PolicyDenied(String),
    /// An imported host (or a jump host in its chain) still has unanswered placeholders.
    /// SSH negotiation found no algorithm both sides accept. `weak_allowable` lists the weak
    /// ones the server offers that Bastion can enable for this host on explicit opt-in.
    #[error("no common {} algorithm: the server offers only {}{}", kind.label(), server_offers.join(", "), if weak_allowable.is_empty() { String::new() } else { format!(" (weak; can be allowed for this host: {})", weak_allowable.join(", ")) })]
    NoCommonAlgorithm { kind: crate::algorithms::AlgoKind, server_offers: Vec<String>, weak_allowable: Vec<String> },
    /// Offline mode refused a destination off the LAN (see `offline`). Optional online
    /// features show nothing for it.
    #[error("offline: {0}")]
    Offline(String),
    #[error("needs configuration: {missing:?}")]
    NeedsConfiguration { missing: Vec<String> },
}

pub type Result<T> = std::result::Result<T, CoreError>;

impl CoreError {
    /// A stable, machine-readable class for hosts (retry, reload, unlock, Save As) so they never
    /// parse the display message. New variants map to an existing code or add a new one; codes
    /// are never renamed.
    pub fn code(&self) -> &'static str {
        match self {
            CoreError::Io(_) => "io",
            CoreError::Corrupt(_) => "corrupt",
            CoreError::Conflict { .. } => "conflict",
            CoreError::NotFound(_) => "not_found",
            CoreError::Invalid(_) => "invalid",
            CoreError::VaultAuth => "vault_locked",
            CoreError::SecretLeak(_) | CoreError::PolicyDenied(_) => "policy",
            CoreError::Ssh(_) | CoreError::NoCommonAlgorithm { .. } => "ssh",
            CoreError::HostKeyUnknown { .. } | CoreError::JumpHostKeyUnknown { .. } => "host_key_unknown",
            CoreError::HostKeyChanged { .. } => "host_key_changed",
            CoreError::AuthFailed => "auth_failed",
            CoreError::Cancelled => "cancelled",
            CoreError::TwoFactorRequired => "two_factor_required",
            CoreError::Timeout => "timeout",
            CoreError::Offline(_) => "offline",
            CoreError::NeedsConfiguration { .. } => "needs_configuration",
        }
    }
}

#[cfg(test)]
mod code_tests {
    use super::CoreError;

    #[test]
    fn document_errors_keep_a_stable_code_apart_from_the_message() {
        assert_eq!(CoreError::Conflict { expected: 3, found: 4 }.code(), "conflict");
        assert_eq!(CoreError::Corrupt("x".into()).code(), "corrupt");
        assert_eq!(CoreError::NotFound("x".into()).code(), "not_found");
        assert_eq!(CoreError::VaultAuth.code(), "vault_locked");
        assert_eq!(CoreError::Offline("x".into()).code(), "offline");
        assert_eq!(CoreError::Timeout.code(), "timeout");
        assert_eq!(CoreError::Io(std::io::Error::other("disk")).code(), "io");
        // The message no longer decides the class: wording can change freely.
        assert!(!CoreError::VaultAuth.to_string().contains("vault_locked"));
    }
}
