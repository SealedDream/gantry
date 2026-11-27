//! Stable error codes for support requests (LOG-ERRCODES). A code is `GT-<AREA>-<NNN>`; the
//! catalogue is `docs/ERROR-CODES.md`. Codes are never renamed or reused. Errors we do not
//! recognise get the area's `000` code and keep their own message.
//!
//! [`redact`] cleans text before it reaches the app log: no passwords, keys, tokens, host names
//! or addresses.

use crate::error::CoreError;
use regex::Regex;
use std::sync::OnceLock;

/// Areas, as the apps pass them. Anything else maps to `APP`.
pub const AREAS: &[&str] = &["SSH", "RDP", "VNC", "VAULT", "NET", "PLUG", "UPD", "FILE", "APP"];

/// Every known code with its meaning (kept in step with `docs/ERROR-CODES.md` by a test).
pub const CATALOGUE: &[(&str, &str)] = &[
    ("GT-APP-000", "Unrecognised error"),
    ("GT-APP-001", "File or disk error"),
    ("GT-APP-002", "Document is damaged"),
    ("GT-APP-003", "Changed elsewhere"),
    ("GT-APP-004", "Not found"),
    ("GT-APP-005", "Invalid input"),
    ("GT-APP-006", "Blocked by policy"),
    ("GT-APP-007", "Needs configuration"),
    ("GT-SSH-000", "Unrecognised SSH error"),
    ("GT-SSH-001", "Authentication failed"),
    ("GT-SSH-002", "Unknown host key"),
    ("GT-SSH-003", "Host key changed"),
    ("GT-SSH-004", "No common algorithm"),
    ("GT-SSH-005", "Second factor required"),
    ("GT-RDP-000", "Unrecognised RDP error"),
    ("GT-RDP-001", "Authentication failed"),
    ("GT-RDP-002", "Certificate not trusted"),
    ("GT-RDP-003", "Security negotiation failed"),
    ("GT-VNC-000", "Unrecognised VNC error"),
    ("GT-VNC-001", "Authentication failed"),
    ("GT-VAULT-000", "Unrecognised vault error"),
    ("GT-VAULT-001", "Vault locked or wrong password"),
    ("GT-VAULT-002", "Authenticator code needed"),
    ("GT-NET-000", "Unrecognised network error"),
    ("GT-NET-001", "Host unreachable or refused"),
    ("GT-NET-002", "Name not found (DNS)"),
    ("GT-NET-003", "Timed out"),
    ("GT-NET-004", "Blocked by offline mode"),
    ("GT-PLUG-000", "Unrecognised plugin error"),
    ("GT-PLUG-001", "Plugin failed to load"),
    ("GT-PLUG-002", "Plugin signature not valid"),
    ("GT-PLUG-003", "Docker not installed on the host"),
    ("GT-PLUG-004", "Docker permission denied (not in the docker group)"),
    ("GT-PLUG-005", "Docker daemon not running"),
    ("GT-UPD-000", "Unrecognised update error"),
    ("GT-UPD-001", "Update check failed"),
    ("GT-UPD-002", "Update failed verification"),
    ("GT-FILE-000", "Unrecognised file transfer error"),
    ("GT-FILE-001", "Permission denied"),
    ("GT-FILE-002", "No space left"),
];

fn norm_area(area: &str) -> &'static str {
    let up = area.trim().to_ascii_uppercase();
    AREAS.iter().copied().find(|a| *a == up).unwrap_or("APP")
}

fn generic(area: &str) -> &'static str {
    match norm_area(area) {
        "SSH" => "GT-SSH-000",
        "RDP" => "GT-RDP-000",
        "VNC" => "GT-VNC-000",
        "VAULT" => "GT-VAULT-000",
        "NET" => "GT-NET-000",
        "PLUG" => "GT-PLUG-000",
        "UPD" => "GT-UPD-000",
        "FILE" => "GT-FILE-000",
        _ => "GT-APP-000",
    }
}

fn auth_for(area: &str) -> &'static str {
    match norm_area(area) {
        "RDP" => "GT-RDP-001",
        "VNC" => "GT-VNC-001",
        "VAULT" => "GT-VAULT-001",
        _ => "GT-SSH-001",
    }
}

/// The code for a core error. `area` picks the code for errors that read the same everywhere
/// (authentication failed) and the generic code.
pub fn for_error(area: &str, e: &CoreError) -> &'static str {
    match e {
        CoreError::Io(_) => "GT-APP-001",
        CoreError::Corrupt(_) => "GT-APP-002",
        CoreError::Conflict { .. } => "GT-APP-003",
        CoreError::NotFound(_) => "GT-APP-004",
        CoreError::Invalid(_) => "GT-APP-005",
        CoreError::SecretLeak(_) | CoreError::PolicyDenied(_) => "GT-APP-006",
        CoreError::NeedsConfiguration { .. } => "GT-APP-007",
        CoreError::VaultAuth => "GT-VAULT-001",
        CoreError::TwoFactorRequired => "GT-VAULT-002",
        CoreError::HostKeyUnknown { .. } | CoreError::JumpHostKeyUnknown { .. } => "GT-SSH-002",
        CoreError::HostKeyChanged { .. } => "GT-SSH-003",
        CoreError::NoCommonAlgorithm { .. } => "GT-SSH-004",
        CoreError::AuthFailed => auth_for(area),
        CoreError::Timeout => "GT-NET-003",
        CoreError::Offline(_) => "GT-NET-004",
        CoreError::Ssh(m) => classify(area, m),
        CoreError::Cancelled => generic(area),
    }
}

/// The code for an error message the apps only have as text. Order matters: the most
/// specific phrases are checked first.
pub fn classify(area: &str, message: &str) -> &'static str {
    let m = message.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| m.contains(w));
    let area_n = norm_area(area);
    if has(&["host key changed", "remote host identification has changed"]) {
        return "GT-SSH-003";
    }
    if has(&["unknown host key"]) {
        return "GT-SSH-002";
    }
    if has(&["no common", "no matching"]) && area_n == "SSH" {
        return "GT-SSH-004";
    }
    if has(&["vault is locked", "wrong password", "wrong master password", "vault locked"]) {
        return "GT-VAULT-001";
    }
    if has(&["two-step", "authenticator code"]) {
        return "GT-VAULT-002";
    }
    if has(&["offline:"]) {
        return "GT-NET-004";
    }
    if has(&["signature"]) {
        return if area_n == "UPD" { "GT-UPD-002" } else { "GT-PLUG-002" };
    }
    if area_n == "UPD" && has(&["checksum", "hash", "verif"]) {
        return "GT-UPD-002";
    }
    if area_n == "RDP" && has(&["certificate"]) {
        return "GT-RDP-002";
    }
    if area_n == "RDP" && has(&["negotiation", "nla", "credssp"]) {
        return "GT-RDP-003";
    }
    if has(&["authentication failed", "auth failed", "login failed", "logon failure", "access denied", "invalid credentials"]) {
        return auth_for(area);
    }
    if has(&["could not resolve", "failed to lookup", "name or service not known", "nodename nor servname", "no such host", "dns"]) {
        return "GT-NET-002";
    }
    if has(&["timed out", "timeout"]) {
        return "GT-NET-003";
    }
    if has(&["connection refused", "unreachable", "no route to host", "actively refused", "network is down"]) {
        return "GT-NET-001";
    }
    if has(&["no space left", "disk full"]) {
        return "GT-FILE-002";
    }
    if area_n == "FILE" && has(&["permission denied"]) {
        return "GT-FILE-001";
    }
    if area_n == "PLUG" && has(&["load", "start", "manifest"]) {
        return "GT-PLUG-001";
    }
    if area_n == "UPD" && has(&["check", "download", "feed"]) {
        return "GT-UPD-001";
    }
    generic(area)
}

/// Meaning of a code, if it is in the catalogue.
pub fn meaning(code: &str) -> Option<&'static str> {
    CATALOGUE.iter().find(|(c, _)| *c == code).map(|(_, m)| *m)
}

fn rules() -> &'static [(Regex, &'static str)] {
    static R: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    R.get_or_init(|| {
        let r = |p: &str| Regex::new(p).expect("redaction pattern");
        vec![
            // Private keys and certificates, whole block.
            (r(r"(?s)-----BEGIN [A-Z0-9 ]+-----.*?(-----END [A-Z0-9 ]+-----|$)"), "(key)"),
            // name=value and name: value pairs for secrets.
            (r(r#"(?i)\b(password|passwd|pwd|passphrase|secret|token|api[_-]?key|apikey|authorization|bearer|otp|totp|pin)\b(\s*[:=]\s*|\s+is\s+)(?:(?:bearer|basic|token)\s+)?("[^"]*"|'[^']*'|\S+)"#), "$1=(secret)"),
            // A bare auth scheme and its credential ("Bearer abc").
            (r(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), "$1 (secret)"),
            // URLs with a user and password.
            (r(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), "$1(user):(secret)@"),
            // Long base64 or hex runs (tokens, keys).
            (r(r"\b[A-Za-z0-9+/=_-]{32,}\b"), "(secret)"),
            // user@host
            (r(r"\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\b"), "(user)@(host)"),
            // IPv4, optional port
            (r(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "(host)"),
            // IPv6 (at least two groups with ::, or 7 colons)
            (r(r"(?i)\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}\b|(?i)\b[0-9a-f]{0,4}::[0-9a-f:]+\b"), "(host)"),
            // Host names: two or more labels ending in letters (example.com, srv1.lab.local).
            (r(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\b"), "(host)"),
        ]
    })
}

/// Removes secrets, user names in `user@host`, host names and addresses from a log line.
/// Used for every detailed-log entry and every error written to the log.
pub fn redact(text: &str) -> String {
    let mut out = text.replace(['\r', '\n'], " ");
    for (re, with) in rules() {
        out = re.replace_all(&out, *with).into_owned();
    }
    out
}

#[cfg(test)]
#[path = "errcodes_tests.rs"]
mod tests;
