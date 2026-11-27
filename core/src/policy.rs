//! Security policy: connection classification, protocol restrictions, confirmation rules and
//! customer credential isolation. A managed (enterprise) policy can only tighten a user policy.
//!
//! Local enforcement limits: a user with full control of their OS account can modify this
//! process. Policy here prevents accidents and enforces defaults; enterprise guarantees need
//! MDM-delivered, signed policy plus server-side controls (see SECURITY_ARCHITECTURE.md).
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::error::{CoreError, Result};
use crate::model::{Connection, Protocol};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    #[default]
    Unclassified,
    Test,
    Development,
    Staging,
    Production,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    #[serde(default)]
    pub environment: Environment,
    /// Customer / tenant this connection belongs to. Drives credential isolation.
    #[serde(default)]
    pub customer: Option<String>,
    #[serde(default)]
    pub customer_sensitive: bool,
    #[serde(default)]
    pub privileged_infrastructure: bool,
}

impl Classification {
    pub fn is_sensitive(&self) -> bool {
        self.environment == Environment::Production || self.customer_sensitive || self.privileged_infrastructure
    }
}

/// Actions whose risk the policy grades.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Connect,
    RunCommand,
    BulkCommand { hosts: usize },
    FileWrite,
    ForcePowerOff,
    DeleteVm,
    SnapshotRevert,
    SnapshotDelete,
    StorageDelete,
    CredentialChange,
    ExportConfiguration,
}

impl Action {
    fn destructive(self) -> bool {
        matches!(
            self,
            Action::ForcePowerOff
                | Action::DeleteVm
                | Action::SnapshotRevert
                | Action::SnapshotDelete
                | Action::StorageDelete
                | Action::CredentialChange
        )
    }
}

/// Protocols that send credentials or data unencrypted. Disabled unless explicitly allowed.
pub const LEGACY_PROTOCOLS: &[Protocol] = &[Protocol::Telnet, Protocol::Ftp];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    /// Legacy protocols the user has explicitly accepted the risk for.
    pub allowed_legacy: BTreeSet<Protocol>,
    /// When set (managed mode), legacy exceptions are forbidden entirely.
    pub forbid_legacy: bool,
    /// Protocols disabled outright.
    pub denied_protocols: BTreeSet<Protocol>,
    /// Bulk operations touching at least this many hosts require confirmation.
    pub bulk_confirm_threshold: usize,
    /// Require confirmation for any command or file write on sensitive connections.
    pub confirm_sensitive_writes: bool,
    /// Allow a credential scoped to one customer to be used for another customer's connection.
    pub allow_cross_customer_credentials: bool,
    pub inactivity_lock_secs: Option<u64>,
    pub allow_session_recording: bool,
    /// Lock every credential (broker leases, password vault, Vaultwarden) when the OS session
    /// locks or the machine sleeps, whatever the user's own setting. Live sessions keep running.
    pub lock_credentials_on_os_lock: bool,
    /// Refuse OSC 52 clipboard writes from remote programs even on connections that allow them.
    /// (OSC 52 clipboard reads are always refused.)
    pub forbid_osc52_write: bool,
    /// When set, web tabs never offer or perform "Fill sign-in" (B13).
    #[serde(default)]
    pub forbid_web_autofill: bool,
    /// RDP must use Network Level Authentication (CredSSP): servers that only offer TLS or
    /// standard RDP security, which show their own logon screen, are refused.
    pub require_rdp_nla: bool,
    /// Documents may only be exported with secrets stripped, even into a protected file.
    pub forbid_secret_export: bool,
    /// Weak SSH algorithms (SHA-1 kex/MACs, CBC ciphers, `ssh-rsa`) may never be enabled.
    pub forbid_weak_ssh_algorithms: bool,
    /// Longest idle time, in minutes, before an open document locks; the user's setting may be
    /// shorter but never longer or "never".
    pub document_auto_lock_max_minutes: Option<u32>,
    /// Documents unlock with their password only (no Touch ID / Windows Hello).
    pub password_only_document_unlock: bool,
    /// Longest time, in minutes, an app may reuse the login it remembers for a connection after
    /// the last successful sign-in with it (SEC-03). 0 means no limit: until Lock or quit. The
    /// apps hold the remembered login; the core holds only this number.
    pub session_login_reuse_minutes: u32,
    /// Plugins (`docs/specs/plugins.md` section 10): every plugin is off.
    pub plugins_disabled: bool,
    /// Only Official plugins may load.
    pub plugins_official_only: bool,
    /// When set, only these plugin ids may load. Combined with a managed list by intersection.
    pub plugins_allowed_ids: Option<BTreeSet<String>>,
    /// Unverified plugins (no valid release record) may never load, whatever the user's setting.
    pub forbid_unverified_plugins: bool,
    /// Plugin helpers that hold a released password stop when credentials lock (T18.27).
    pub stop_plugin_helpers_on_credentials_lock: bool,
    /// "Allow unencrypted" may not be turned on for a plugin entry's direct stream.
    pub forbid_plugin_unencrypted: bool,
    /// A plugin entry's TLS mode may not be off on any route, gateways and tunnels included.
    pub forbid_plugin_tls_off: bool,
    /// Plugins may not ask to open connections (plugin API 1.2, `plugin_open = off`).
    #[serde(default)]
    pub plugin_open_disabled: bool,
    /// Plugins may not run their declared commands over SSH (plugin API 1.5, `plugin_exec = off`).
    #[serde(default)]
    pub plugin_exec_disabled: bool,
    /// Plugins may ask to open connections only to addresses the entry's server reported
    /// (`plugin_open = reported_only`).
    #[serde(default)]
    pub plugin_open_reported_only: bool,
    /// B15: the user's switch for dynamic folders (folders filled by a saved local task). Off by
    /// default.
    pub dynamic_folders_enabled: bool,
    /// B15: dynamic folders may never run, whatever the user's switch (managed policy).
    pub forbid_dynamic_folders: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            allowed_legacy: BTreeSet::new(),
            forbid_legacy: false,
            denied_protocols: BTreeSet::new(),
            bulk_confirm_threshold: 2,
            confirm_sensitive_writes: true,
            allow_cross_customer_credentials: false,
            inactivity_lock_secs: Some(15 * 60),
            allow_session_recording: false,
            lock_credentials_on_os_lock: false,
            forbid_osc52_write: false,
            forbid_web_autofill: false,
            require_rdp_nla: false,
            forbid_secret_export: false,
            forbid_weak_ssh_algorithms: false,
            document_auto_lock_max_minutes: None,
            password_only_document_unlock: false,
            session_login_reuse_minutes: 0,
            plugins_disabled: false,
            plugins_official_only: false,
            plugins_allowed_ids: None,
            forbid_unverified_plugins: false,
            stop_plugin_helpers_on_credentials_lock: false,
            forbid_plugin_unencrypted: false,
            forbid_plugin_tls_off: false,
            plugin_open_disabled: false,
            plugin_exec_disabled: false,
            plugin_open_reported_only: false,
            dynamic_folders_enabled: false,
            forbid_dynamic_folders: false,
        }
    }
}

impl Policy {
    pub fn check_protocol(&self, protocol: Protocol) -> Result<()> {
        if self.denied_protocols.contains(&protocol) {
            return Err(CoreError::PolicyDenied(format!("{protocol:?} is disabled by policy")));
        }
        if LEGACY_PROTOCOLS.contains(&protocol) && (self.forbid_legacy || !self.allowed_legacy.contains(&protocol)) {
            return Err(CoreError::PolicyDenied(format!(
                "{protocol:?} is unencrypted and disabled by default; enable it explicitly with a documented risk acceptance"
            )));
        }
        Ok(())
    }

    /// Whether `action` on `connection` needs explicit user confirmation.
    pub fn requires_confirmation(&self, action: Action, classification: &Classification) -> bool {
        match action {
            a if a.destructive() => true,
            Action::ExportConfiguration => true,
            Action::BulkCommand { hosts } => hosts >= self.bulk_confirm_threshold,
            Action::RunCommand | Action::FileWrite => self.confirm_sensitive_writes && classification.is_sensitive(),
            _ => false,
        }
    }

    /// Credential isolation: a credential scoped to customer A is refused for customer B's
    /// connection unless policy explicitly allows cross-customer use.
    pub fn check_credential_scope(&self, credential_scope: Option<&str>, connection: &Connection) -> Result<()> {
        let target = connection.classification.customer.as_deref();
        match (credential_scope, target) {
            (Some(c), Some(t)) if c != t && !self.allow_cross_customer_credentials => Err(CoreError::PolicyDenied(
                format!("credential belongs to customer `{c}` and cannot be used for customer `{t}`"),
            )),
            (Some(c), None) if !self.allow_cross_customer_credentials => Err(CoreError::PolicyDenied(format!(
                "credential belongs to customer `{c}`; the connection has no customer assigned"
            ))),
            _ => Ok(()),
        }
    }

    /// Combine with a managed policy: every setting takes the stricter of the two values,
    /// so a user-level preference can never relax an enterprise requirement.
    pub fn with_managed(&self, managed: &Policy) -> Policy {
        let forbid_legacy = self.forbid_legacy || managed.forbid_legacy;
        Policy {
            allowed_legacy: if forbid_legacy {
                BTreeSet::new()
            } else {
                self.allowed_legacy.intersection(&managed.allowed_legacy).copied().collect()
            },
            forbid_legacy,
            denied_protocols: self.denied_protocols.union(&managed.denied_protocols).copied().collect(),
            bulk_confirm_threshold: self.bulk_confirm_threshold.min(managed.bulk_confirm_threshold),
            confirm_sensitive_writes: self.confirm_sensitive_writes || managed.confirm_sensitive_writes,
            allow_cross_customer_credentials: self.allow_cross_customer_credentials && managed.allow_cross_customer_credentials,
            inactivity_lock_secs: match (self.inactivity_lock_secs, managed.inactivity_lock_secs) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
            allow_session_recording: self.allow_session_recording && managed.allow_session_recording,
            lock_credentials_on_os_lock: self.lock_credentials_on_os_lock || managed.lock_credentials_on_os_lock,
            forbid_osc52_write: self.forbid_osc52_write || managed.forbid_osc52_write,
            forbid_web_autofill: self.forbid_web_autofill || managed.forbid_web_autofill,
            require_rdp_nla: self.require_rdp_nla || managed.require_rdp_nla,
            forbid_secret_export: self.forbid_secret_export || managed.forbid_secret_export,
            forbid_weak_ssh_algorithms: self.forbid_weak_ssh_algorithms || managed.forbid_weak_ssh_algorithms,
            // 0 means "no cap" (see `docunlock::effective_auto_lock_minutes`), so it is
            // normalised away before the minimum: a zero can never relax a positive cap (TM-01).
            document_auto_lock_max_minutes: match (no_cap_as_none(self.document_auto_lock_max_minutes), no_cap_as_none(managed.document_auto_lock_max_minutes)) {
                (Some(a), Some(b)) => Some(a.min(b)),
                (a, b) => a.or(b),
            },
            password_only_document_unlock: self.password_only_document_unlock || managed.password_only_document_unlock,
            session_login_reuse_minutes: effective_session_login_reuse_minutes(self.session_login_reuse_minutes, managed.session_login_reuse_minutes),
            plugins_disabled: self.plugins_disabled || managed.plugins_disabled,
            plugins_official_only: self.plugins_official_only || managed.plugins_official_only,
            plugins_allowed_ids: match (&self.plugins_allowed_ids, &managed.plugins_allowed_ids) {
                (Some(a), Some(b)) => Some(a.intersection(b).cloned().collect()),
                (a, b) => a.clone().or_else(|| b.clone()),
            },
            forbid_unverified_plugins: self.forbid_unverified_plugins || managed.forbid_unverified_plugins,
            stop_plugin_helpers_on_credentials_lock: self.stop_plugin_helpers_on_credentials_lock || managed.stop_plugin_helpers_on_credentials_lock,
            forbid_plugin_unencrypted: self.forbid_plugin_unencrypted || managed.forbid_plugin_unencrypted,
            forbid_plugin_tls_off: self.forbid_plugin_tls_off || managed.forbid_plugin_tls_off,
            plugin_open_disabled: self.plugin_open_disabled || managed.plugin_open_disabled,
            plugin_exec_disabled: self.plugin_exec_disabled || managed.plugin_exec_disabled,
            plugin_open_reported_only: self.plugin_open_reported_only || managed.plugin_open_reported_only,
            // The switch is the user's; a managed ban always wins (C2).
            dynamic_folders_enabled: self.dynamic_folders_enabled,
            forbid_dynamic_folders: self.forbid_dynamic_folders || managed.forbid_dynamic_folders,
        }
    }
}

/// A document auto-lock cap of 0 is the "no cap" sentinel; treat it as absent.
fn no_cap_as_none(cap: Option<u32>) -> Option<u32> {
    cap.filter(|m| *m > 0)
}

/// The reuse time in force for a remembered login, in minutes: the smaller non-zero one of the
/// user's value and the managed maximum. 0 means no limit (until Lock or quit) and is the result
/// only when both are 0, so a zero never relaxes a limit.
pub fn effective_session_login_reuse_minutes(user_minutes: u32, policy_max: u32) -> u32 {
    match (user_minutes, policy_max) {
        (0, m) | (m, 0) => m,
        (a, b) => a.min(b),
    }
}

/// Whether an app may still reuse the login it remembers for a connection. `remembered_at` is
/// the time of the last successful sign-in with it and `now` the current time, both in seconds
/// on the same clock; `minutes` is the reuse time in force (0 = until Lock or quit). Under a
/// limit, a login is usable for less than `minutes` whole minutes; a clock that went backwards
/// leaves its age unknown, so it is not usable.
pub fn remembered_login_usable(remembered_at: u64, now: u64, minutes: u32) -> bool {
    if minutes == 0 {
        return true;
    }
    now.checked_sub(remembered_at).is_some_and(|age_secs| age_secs < u64::from(minutes) * 60)
}

/// Whether credentials lock when the OS session locks (audit TM-04): the user's own choice OR
/// the managed requirement. A policy that cannot be read is treated as requiring it.
pub fn lock_on_os_lock(user_pref: bool, policy: &crate::error::Result<Policy>) -> bool {
    user_pref || policy.as_ref().map_or(true, |p| p.lock_credentials_on_os_lock)
}

/// Whether Telnet may be used (B7): never under a managed `forbid_legacy`; otherwise when the
/// user turned on "Allow Telnet" (`settings::ALLOW_TELNET_SETTING`) or the managed policy lists
/// it in `allowed_legacy`. A policy that cannot be read forbids it.
pub fn telnet_allowed(user_allows: bool, policy: &crate::error::Result<Policy>) -> bool {
    match policy {
        Ok(p) => !p.forbid_legacy && !p.denied_protocols.contains(&Protocol::Telnet) && (user_allows || p.allowed_legacy.contains(&Protocol::Telnet)),
        Err(_) => false,
    }
}

/// `policy` with Telnet added to `allowed_legacy` when `telnet_allowed` says so, for
/// `check_protocol` at connect time.
pub fn with_user_telnet(mut policy: Policy, user_allows: bool) -> Policy {
    if telnet_allowed(user_allows, &Ok(policy.clone())) {
        policy.allowed_legacy.insert(Protocol::Telnet);
    }
    policy
}

/// Largest managed policy file accepted.
pub const MAX_MANAGED_POLICY_BYTES: u64 = 64 * 1024;

/// Where an administrator (MDM, installer) places the managed policy: macOS
/// `/Library/Application Support/Gantry/policy.json`, Windows
/// `%ProgramData%\Gantry\policy.json`, elsewhere `/etc/gantry/policy.json`.
/// A policy an administrator installed under the old product name (`Bastion`) still applies and
/// wins when present: a file a user may create at the new path never overrides it.
pub fn managed_policy_path() -> std::path::PathBuf {
    let (current, legacy) = managed_policy_paths();
    if legacy.exists() { legacy } else { current }
}

fn managed_policy_paths() -> (std::path::PathBuf, std::path::PathBuf) {
    #[cfg(target_os = "macos")]
    return ("/Library/Application Support/Gantry/policy.json".into(), "/Library/Application Support/Bastion/policy.json".into());
    #[cfg(windows)]
    {
        let base = std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| "C:\\ProgramData".into()));
        return (base.join("Gantry").join("policy.json"), base.join("Bastion").join("policy.json"));
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    return ("/etc/gantry/policy.json".into(), "/etc/bastion/policy.json".into());
}

impl Policy {
    /// Parse a managed policy (JSON with the field names above; missing fields keep their
    /// defaults, unknown fields are an error so a misspelt restriction is never ignored).
    pub fn parse_managed(bytes: &[u8]) -> Result<Policy> {
        if bytes.len() as u64 > MAX_MANAGED_POLICY_BYTES {
            return Err(CoreError::Invalid("managed policy file is too large".into()));
        }
        serde_json::from_slice(bytes).map_err(|e| CoreError::Invalid(format!("managed policy: {e}")))
    }

    /// Load the managed policy at `path`: `Ok(None)` when there is none. On Unix the file must
    /// be owned by root and not writable by group or others, so a user process cannot plant or
    /// loosen it (on Windows: owned by and writable only by SYSTEM/Administrators, file and
    /// folder); anything else, or an unparsable file, is an error the caller must fail closed on.
    pub fn load_managed(path: &std::path::Path) -> Result<Option<Policy>> {
        let meta = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !meta.is_file() {
            return Err(CoreError::Invalid("managed policy is not a regular file".into()));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if meta.uid() != 0 || meta.mode() & 0o022 != 0 {
                return Err(CoreError::Invalid("managed policy must be owned by root and not writable by group or others".into()));
            }
        }
        // On Windows the file and its folder must be owned by SYSTEM/Administrators and
        // writable by no one else: %ProgramData% lets any user create a `Bastion` folder.
        #[cfg(windows)]
        for p in [Some(path), path.parent()].into_iter().flatten() {
            crate::winacl::check_admin_only(p).map_err(|e| CoreError::Invalid(format!("managed policy rejected: {e}")))?;
        }
        if meta.len() > MAX_MANAGED_POLICY_BYTES {
            return Err(CoreError::Invalid("managed policy file is too large".into()));
        }
        Policy::parse_managed(&std::fs::read(path)?).map(Some)
    }
}

#[cfg(test)]
mod b7_tests {
    use super::*;

    #[test]
    fn telnet_is_allowed_only_by_the_user_switch_or_managed_policy_and_never_when_forbidden() {
        let none: Result<Policy> = Ok(Policy::default());
        assert!(!telnet_allowed(false, &none), "off by default");
        assert!(telnet_allowed(true, &none), "user switch");
        let allow: Result<Policy> = Ok(Policy { allowed_legacy: [Protocol::Telnet].into(), ..Policy::default() });
        assert!(telnet_allowed(false, &allow), "managed allow");
        let forbid: Result<Policy> = Ok(Policy { forbid_legacy: true, allowed_legacy: [Protocol::Telnet].into(), ..Policy::default() });
        assert!(!telnet_allowed(true, &forbid), "managed forbid beats the user switch");
        let denied: Result<Policy> = Ok(Policy { denied_protocols: [Protocol::Telnet].into(), ..Policy::default() });
        assert!(!telnet_allowed(true, &denied));
        let broken: Result<Policy> = Err(CoreError::Invalid("bad policy".into()));
        assert!(!telnet_allowed(true, &broken), "an unreadable policy forbids it");
    }

    #[test]
    fn check_protocol_follows_the_user_switch() {
        assert!(with_user_telnet(Policy::default(), false).check_protocol(Protocol::Telnet).is_err());
        assert!(with_user_telnet(Policy::default(), true).check_protocol(Protocol::Telnet).is_ok());
        let forbid = Policy { forbid_legacy: true, ..Policy::default() };
        assert!(with_user_telnet(forbid, true).check_protocol(Protocol::Telnet).is_err());
        // The switch is about Telnet only.
        assert!(with_user_telnet(Policy::default(), true).check_protocol(Protocol::Ftp).is_err());
    }
}
