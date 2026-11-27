//! PLUG-02c: the plugin broker's app-facing decisions (`bastion_core::plugin::broker`, PLUG-02a).
//!
//! Only what a frontend must ask: the plugin policy keys in force, whether a plugin may load, and
//! the warning before a plugin field value that matches the entry's saved password is stored.
//! Everything else in the broker runs inside the core and the helper (PLUG-02b). The rollout stage
//! is fixed in the core (`Rollout::OFFICIAL_ONLY`), never chosen by an app.
use bastion_core::plugin::broker::{gate, secret, Failure};
use bastion_core::plugin::Tier;
use bastion_core::policy::Policy;
use zeroize::Zeroize;

use crate::policy::effective;

/// The plugin keys of the policy in force (spec section 10). Read-only.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PluginPolicyView {
    /// Why the managed policy cannot be used. While set, every plugin is refused.
    pub error: Option<String>,
    pub plugins_disabled: bool,
    pub official_only: bool,
    /// `None`: no list, every id may load (subject to the other keys).
    pub allowed_ids: Option<Vec<String>>,
    pub forbid_unverified: bool,
    pub stop_helpers_on_credentials_lock: bool,
    pub forbid_unencrypted: bool,
    pub forbid_tls_off: bool,
}

fn view_of(policy: &bastion_core::Result<Policy>) -> PluginPolicyView {
    let (p, error) = match policy {
        Ok(p) => (p.clone(), None),
        Err(e) => (Policy { plugins_disabled: true, ..Policy::default() }, Some(e.to_string())),
    };
    PluginPolicyView {
        error,
        plugins_disabled: p.plugins_disabled,
        official_only: p.plugins_official_only,
        allowed_ids: p.plugins_allowed_ids.map(|s| s.into_iter().collect()),
        forbid_unverified: p.forbid_unverified_plugins,
        stop_helpers_on_credentials_lock: p.stop_plugin_helpers_on_credentials_lock,
        forbid_unencrypted: p.forbid_plugin_unencrypted,
        forbid_tls_off: p.forbid_plugin_tls_off,
    }
}

/// What Settings shows about the plugin policy. A broken managed policy shows plugins off.
#[uniffi::export]
pub fn plugin_policy_state() -> PluginPolicyView {
    view_of(&effective())
}

fn parse_tier(tier: &str) -> Option<Tier> {
    match tier {
        "official" => Some(Tier::Official),
        "external" => Some(Tier::External),
        "unverified" => Some(Tier::Unverified),
        _ => None,
    }
}

fn failure_text(f: Failure) -> String {
    match f {
        Failure::Denied(r) | Failure::Invalid(r) | Failure::Io(r) => r,
        Failure::TimedOut => "timed out".into(),
    }
}

fn may_load_under(policy: &bastion_core::Result<Policy>, id: &str, tier: &str, allow_unverified: bool, safe_mode: bool) -> Option<String> {
    let Some(tier) = parse_tier(tier) else {
        return Some(format!("unknown plugin tier `{tier}`"));
    };
    let policy = match policy {
        Ok(p) => p,
        // Fail closed: a managed policy that cannot be read refuses every plugin.
        Err(e) => return Some(e.to_string()),
    };
    gate::may_load(policy, gate::Rollout::current(), id, tier, allow_unverified, safe_mode).err().map(failure_text)
}

/// Whether plugin `id` may load. `tier` is `official`, `external` or `unverified`;
/// `allow_unverified` is the user's "Allow unverified plugins" setting; `safe_mode` the app's Safe
/// mode. `None`: it may load. Otherwise the reason, in the core's words, to show on its row.
#[uniffi::export]
pub fn plugin_may_load(id: String, tier: String, allow_unverified: bool, safe_mode: bool) -> Option<String> {
    may_load_under(&effective(), &id, &tier, allow_unverified, safe_mode)
}

/// Call before storing a plugin field value. `entry_password` is the entry's saved password when
/// credentials are unlocked, else `None` (then nothing is compared: a stated residual). Returns
/// the warning to show (the user may cancel or confirm), or `None` to save. The copy of the
/// password and of the value passed in are wiped before return; nothing is kept.
#[uniffi::export]
pub fn plugin_field_save_warning(mut value: String, entry_password: Option<String>) -> Option<String> {
    let mut pw = entry_password;
    let out = match secret::field_save(&value, pw.as_deref().map(str::as_bytes)) {
        secret::FieldSave::Save => None,
        secret::FieldSave::WarnMatchesPassword => Some(secret::FIELD_MATCHES_PASSWORD_WARNING.to_string()),
    };
    if let Some(p) = pw.as_mut() {
        p.zeroize();
    }
    // The value may itself be the password (that is what is being checked).
    value.zeroize();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_core::CoreError;
    use std::collections::BTreeSet;

    fn broken() -> bastion_core::Result<Policy> {
        Err(CoreError::PolicyDenied("broken".into()))
    }

    #[test]
    fn official_loads_under_the_default_policy_and_others_wait_for_their_rollout() {
        let ok = Ok(Policy::default());
        assert_eq!(may_load_under(&ok, "pg", "official", false, false), None);
        assert_eq!(may_load_under(&ok, "pg", "external", false, false).as_deref(), Some("External plugins are not available yet"));
        assert_eq!(may_load_under(&ok, "pg", "unverified", true, false).as_deref(), Some("Unverified plugins are not available yet"));
    }

    #[test]
    fn safe_mode_policy_keys_and_a_broken_policy_refuse() {
        let ok = Ok(Policy::default());
        assert!(may_load_under(&ok, "pg", "official", false, true).unwrap().contains("Safe mode"));
        let off = Ok(Policy { plugins_disabled: true, ..Policy::default() });
        assert!(may_load_under(&off, "pg", "official", false, false).unwrap().contains("off by policy"));
        let list = Ok(Policy { plugins_allowed_ids: Some(BTreeSet::from(["ssh".to_string()])), ..Policy::default() });
        assert!(may_load_under(&list, "pg", "official", false, false).unwrap().contains("not on the policy's list"));
        assert_eq!(may_load_under(&list, "ssh", "official", false, false), None);
        assert!(may_load_under(&broken(), "pg", "official", false, false).is_some());
    }

    #[test]
    fn an_unknown_tier_is_refused() {
        assert!(may_load_under(&Ok(Policy::default()), "pg", "Official", false, false).unwrap().contains("unknown plugin tier"));
        assert!(may_load_under(&Ok(Policy::default()), "pg", "", false, false).is_some());
    }

    #[test]
    fn policy_view_projects_every_plugin_key_and_a_broken_policy_shows_plugins_off() {
        let p = Policy {
            plugins_disabled: false,
            plugins_official_only: true,
            plugins_allowed_ids: Some(BTreeSet::from(["b".to_string(), "a".to_string()])),
            forbid_unverified_plugins: true,
            stop_plugin_helpers_on_credentials_lock: true,
            forbid_plugin_unencrypted: true,
            forbid_plugin_tls_off: true,
            ..Policy::default()
        };
        let v = view_of(&Ok(p));
        assert_eq!(
            v,
            PluginPolicyView {
                error: None,
                plugins_disabled: false,
                official_only: true,
                allowed_ids: Some(vec!["a".into(), "b".into()]),
                forbid_unverified: true,
                stop_helpers_on_credentials_lock: true,
                forbid_unencrypted: true,
                forbid_tls_off: true,
            }
        );
        let d = view_of(&Ok(Policy::default()));
        assert!(!d.plugins_disabled && d.allowed_ids.is_none() && d.error.is_none());
        let b = view_of(&broken());
        assert!(b.plugins_disabled && b.error.is_some());
    }

    #[test]
    fn field_warning_for_the_password_and_its_encodings_only() {
        let pw = Some("hunter22".to_string());
        assert_eq!(plugin_field_save_warning("hunter22".into(), pw.clone()).as_deref(), Some(secret::FIELD_MATCHES_PASSWORD_WARNING));
        // hex of "hunter22"
        assert!(plugin_field_save_warning("68756e7465723232".into(), pw.clone()).is_some());
        assert_eq!(plugin_field_save_warning("postgres".into(), pw), None);
        assert_eq!(plugin_field_save_warning("hunter22".into(), None), None);
    }
}
