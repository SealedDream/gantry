//! The plugin broker's decisions (PLUG-02a; design in `docs/specs/plugins.md`, sections 4, 5
//! and 10; threats T18.1 to T18.27 in `THREAT_MODEL.md`).
//!
//! Everything here is pure logic or a small state machine. Time, policy, the released secrets
//! and the entry's route are passed in; nothing reads the disk, the network or the clock on its
//! own. PLUG-02b wires these decisions to the helper processes, and PLUG-02c exports them.
//!
//! - [`gate`]: whether a plugin may load under policy and the current rollout stage.
//! - [`grants`]: permissions checked on every call; one entry per helper; one release per entry.
//! - [`secret`]: released secrets and the one secret check.
//! - [`http`]: the HTTP helper (API 1.1): `[http]` rules, request checks, the login header,
//!   the strict response reader and the echo check.
//! - [`open`]: a plugin asks the app to open SSH, RDP or VNC (API 1.2): host and address
//!   checks, the reported-address set, the user-action stamp and the rate.
//! - [`exec`]: declared SSH commands (API 1.5): templates, typed arguments, quoting, caps.
//! - [`stream`]: "local" per route, the TLS gate, the preamble, stream and connection caps.
//! - [`abort`]: abort-byte registrations and what a stop sends.
//! - [`view`]: frames, message kinds, view lists and the update rate.
//! - [`caps`]: result data held by the core, per view, per plugin and in total.
//! - [`cache`]: the compiled-code store index and the compile helper's limits.
//! - [`lock`]: which helpers stop when a document or the credentials lock.
//! - [`audit`]: the `Category::Plugin` events these decisions produce.

pub mod abort;
pub mod audit;
pub mod cache;
pub mod exec;
pub mod caps;
pub mod gate;
pub mod grants;
pub mod http;
pub mod http_session;
pub mod lock;
pub mod open;
pub mod secret;
pub mod stream;
pub mod view;

use std::fmt;

/// What a plugin call gets back when the broker says no. The text is in the core's words and
/// never holds a secret, another entry's name or another tab's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Not allowed: a permission, a policy, a lock, or the secret check.
    Denied(String),
    /// Well formed but over a limit, or not valid for this state. The helper keeps running.
    Invalid(String),
    /// The network or the server failed (a plugin stream). The helper keeps running.
    Io(String),
    /// A plugin stream's connect or handshake ran out of time.
    TimedOut,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Denied(r) => write!(f, "denied: {r}"),
            Failure::Invalid(r) => write!(f, "invalid: {r}"),
            Failure::Io(r) => write!(f, "io: {r}"),
            Failure::TimedOut => write!(f, "timed out"),
        }
    }
}

/// Something only a broken or compromised helper can send. The core kills the helper (a
/// trust-withdrawing stop) and audits it (section 5, "Messages").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolViolation(pub String);

impl fmt::Display for ProtocolViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "protocol violation: {}", self.0)
    }
}

/// Why a helper stopped (section 5, "Stops").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StopReason {
    // Ordinary stops: abort bytes are sent.
    UserCancel,
    TabClosed,
    LimitKill,
    HangKill,
    Crash,
    DocumentLocked,
    CredentialsLockedByPolicy,
    // Trust-withdrawing stops: abort bytes are dropped unsent.
    Revoked,
    PolicyChanged,
    TurnedOff,
    Removed,
    SafeMode,
    ProtocolViolation,
    NoSandbox,
}

impl StopReason {
    /// A stop that withdraws trust never lets the plugin act again, not even to cancel.
    pub fn withdraws_trust(self) -> bool {
        matches!(
            self,
            StopReason::Revoked
                | StopReason::PolicyChanged
                | StopReason::TurnedOff
                | StopReason::Removed
                | StopReason::SafeMode
                | StopReason::ProtocolViolation
                | StopReason::NoSandbox
        )
    }

    /// The name used in audit records.
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::UserCancel => "cancel",
            StopReason::TabClosed => "tab-closed",
            StopReason::LimitKill => "limit",
            StopReason::HangKill => "hang",
            StopReason::Crash => "crash",
            StopReason::DocumentLocked => "document-locked",
            StopReason::CredentialsLockedByPolicy => "credentials-locked-policy",
            StopReason::Revoked => "revoked",
            StopReason::PolicyChanged => "policy",
            StopReason::TurnedOff => "turned-off",
            StopReason::Removed => "removed",
            StopReason::SafeMode => "safe-mode",
            StopReason::ProtocolViolation => "protocol-violation",
            StopReason::NoSandbox => "no-sandbox",
        }
    }
}

/// At most this many helpers run at once, compile helpers included (section 5, "Caps").
pub const MAX_HELPERS: usize = 8;
