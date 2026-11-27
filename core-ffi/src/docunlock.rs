//! Document-first launch (`bastion_core::docunlock`): wrong-password back-off status, a
//! wrapped document key for a biometry-protected Keychain item, auto-lock decisions, each
//! document's own state folder, and recent document details for the Welcome / Unlock screens.
//!
//! The wrapped key is sealed under a per-device wrapping key kept in the OS key store (macOS
//! Keychain, Windows DPAPI), so the blob the app keeps behind Touch ID is useless elsewhere and
//! never contains the password.
use std::path::{Path, PathBuf};

use bastion_core::docfile::{self, DocumentKey, RecentDocuments};
use bastion_core::docunlock;
#[cfg(not(any(target_os = "macos", windows)))]
use bastion_core::CoreError;

use crate::documents::{BastionDocument, RECENT_FILE};
use crate::{FfiError, FfiResult};

/// A 32-byte wrapping key from caller bytes (wrong length = refused, as a wrong key).
fn key_from_bytes(raw: &[u8]) -> bastion_core::Result<DocumentKey> {
    let key: [u8; 32] = raw.try_into().map_err(|_| bastion_core::CoreError::VaultAuth)?;
    Ok(zeroize::Zeroizing::new(key))
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn to_json<T: serde::Serialize>(v: &T) -> FfiResult<String> {
    serde_json::to_string(v).map_err(|e| FfiError::failed(e.to_string()))
}

#[cfg(any(target_os = "macos", windows))]
const WRAPPING_ITEM: &str = "document-wrapping-key";

/// This device's wrapping key, created on first use.
#[cfg(any(target_os = "macos", windows))]
fn wrapping_key() -> bastion_core::Result<DocumentKey> {
    use bastion_core::provider::CredentialProvider;
    use bastion_core::vault::Secret;
    let p = crate::documents::provider();
    // Only a missing item creates a key: any other read error (cancelled, locked, I/O) must not
    // replace the shared key and orphan every enrolled blob. Serialise first-use creation.
    static CREATE: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = CREATE.lock().unwrap_or_else(|e| e.into_inner());
    match p.fetch(WRAPPING_ITEM) {
        Ok(hex) => return docfile::key_from_hex(hex.expose()),
        Err(bastion_core::CoreError::NotFound(_)) => {}
        Err(e) => return Err(e),
    }
    let key = docfile::new_wrapping_key();
    p.store(WRAPPING_ITEM, &Secret::new(docfile::key_to_hex(&key).as_str()))?;
    Ok(key)
}

#[cfg(not(any(target_os = "macos", windows)))]
fn wrapping_key() -> bastion_core::Result<DocumentKey> {
    Err(CoreError::Invalid("biometric unlock needs the macOS Keychain or Windows DPAPI".into()))
}

#[derive(uniffi::Record)]
pub struct UnlockStatusView {
    /// Wrong passwords since the last unlock.
    pub failures: u32,
    /// Seconds before the next password may be tried (0 = now).
    pub wait_secs: u64,
}

#[uniffi::export]
impl BastionDocument {
    /// For the Unlock screen: wrong passwords so far and the wait before the next try.
    pub fn unlock_status(&self) -> UnlockStatusView {
        let a = docunlock::UnlockBackoff::in_dir(&self.data_dir).get(self.file().id());
        UnlockStatusView { failures: a.failures, wait_secs: a.wait_secs(now()) }
    }

    /// The unlocked document's key, wrapped for this device (hex). Store it in a Keychain item
    /// with `kSecAccessControlBiometryCurrentSet`; delete that item when biometrics are turned off.
    pub fn export_wrapped_key(&self) -> FfiResult<String> {
        docunlock::check_biometric_allowed(&crate::policy::effective_for_documents()?)?;
        let key = wrapping_key()?;
        Ok(self.file().export_wrapped_key(&key)?.to_string())
    }

    /// Unlock with a blob from `export_wrapped_key`, read from the Keychain after Touch ID.
    pub fn unlock_wrapped_key(&self, wrapped: String) -> FfiResult<()> {
        let r = crate::policy::effective_for_documents().and_then(|p| docunlock::check_biometric_allowed(&p)).and_then(|()| wrapping_key()).and_then(|k| self.file().unlock_with_wrapped_key(&wrapped, &k));
        if r.is_ok() {
            docunlock::UnlockBackoff::in_dir(&self.data_dir).record_success(self.file().id())?;
        }
        self.after_unlock("biometric", r)
    }

    /// The unlocked document's key wrapped by `wrapping_key` (32 random bytes the app holds;
    /// zeroised here after use). Mac: the app keeps that key sealed by a Secure Enclave key that
    /// only the currently enrolled fingers open (`biometryCurrentSet`), so no login-Keychain item
    /// and no code-signing identity is involved. Refused when policy disallows biometric unlock.
    pub fn export_key_wrapped_by(&self, wrapping_key: Vec<u8>) -> FfiResult<String> {
        let raw = zeroize::Zeroizing::new(wrapping_key);
        docunlock::check_biometric_allowed(&crate::policy::effective_for_documents()?)?;
        let key = key_from_bytes(&raw)?;
        Ok(self.file().export_wrapped_key(&key)?.to_string())
    }

    /// Unlock with a blob from `export_key_wrapped_by` and the same wrapping key, released by
    /// Touch ID. Audited as a biometric unlock (as `unlock_biometric`); the back-off reset after a
    /// success is best effort and never undoes the unlock or its audit line.
    pub fn unlock_key_wrapped_by(&self, wrapped: String, wrapping_key: Vec<u8>) -> FfiResult<()> {
        let raw = zeroize::Zeroizing::new(wrapping_key);
        let r = crate::policy::effective_for_documents()
            .and_then(|p| docunlock::check_biometric_allowed(&p))
            .and_then(|()| key_from_bytes(&raw))
            .and_then(|k| self.file().unlock_with_wrapped_key(&wrapped, &k));
        let out = self.after_unlock("biometric", r);
        if out.is_ok() {
            let _ = docunlock::UnlockBackoff::in_dir(&self.data_dir).record_success(self.file().id());
        }
        out
    }

    /// This document's own state folder: pass it as `dataDir` to the open-session set
    /// (`openSessionsSave` / `openSessionsBegin`) and to connection history / recent sessions.
    pub fn state_dir(&self) -> FfiResult<String> {
        Ok(docunlock::document_state_dir(&self.data_dir, self.file().id())?.display().to_string())
    }
}

/// Recent documents with details, newest first:
/// `[{"path","name","id","present","protected","biometric","lastOpenedAt"}]`. The first with
/// `present` is the last-used document for the Unlock screen; missing ones show "Locate…".
#[uniffi::export]
pub fn recent_document_details(data_dir: String) -> FfiResult<String> {
    let dir = PathBuf::from(&data_dir);
    let list = RecentDocuments::new(dir.join(RECENT_FILE)).list();
    to_json(&docunlock::recent_details(Path::new(&data_dir), &list))
}

/// The idle minutes in force under the managed policy: `user_minutes` (the
/// `document.auto-lock-minutes` value, 0 = never) capped by `document_auto_lock_max_minutes`.
#[uniffi::export]
pub fn document_auto_lock_minutes(user_minutes: u32) -> u32 {
    auto_lock_minutes_under(user_minutes, &crate::policy::effective_for_documents())
}

/// A broken managed policy never means "no cap": it means the short fail-closed cap (F08).
fn auto_lock_minutes_under(user_minutes: u32, policy: &bastion_core::Result<bastion_core::policy::Policy>) -> u32 {
    match policy {
        Ok(p) => docunlock::policy_auto_lock_minutes(user_minutes, p),
        Err(_) if user_minutes == 0 => crate::policy::BROKEN_POLICY_AUTO_LOCK_MINUTES,
        Err(_) => user_minutes.min(crate::policy::BROKEN_POLICY_AUTO_LOCK_MINUTES),
    }
}

/// Biometric unlock is allowed only under a readable policy that permits it (F08).
fn biometric_allowed_under(policy: &bastion_core::Result<bastion_core::policy::Policy>) -> bool {
    policy.as_ref().is_ok_and(|p| docunlock::check_biometric_allowed(p).is_ok())
}

/// False when the managed policy allows only the document password: hide "Unlock with
/// biometrics" and skip Touch ID / Windows Hello.
#[uniffi::export]
pub fn document_biometric_unlock_allowed() -> bool {
    biometric_allowed_under(&crate::policy::effective_for_documents())
}

/// The managed cap in force: the policy maximum, or the short fail-closed cap when the policy
/// cannot be read (F08).
fn managed_cap_under(policy: &bastion_core::Result<bastion_core::policy::Policy>) -> Option<u32> {
    match policy {
        Ok(p) => p.document_auto_lock_max_minutes.filter(|m| *m > 0),
        Err(_) => Some(crate::policy::BROKEN_POLICY_AUTO_LOCK_MINUTES),
    }
}

fn document_auto_lock_due_under(minutes: u32, idle_secs: u64, screen_locked: bool, asleep: bool, remember_until_quit: bool, policy: &bastion_core::Result<bastion_core::policy::Policy>) -> Option<docunlock::LockReason> {
    docunlock::document_lock_due(minutes, managed_cap_under(policy), idle_secs, screen_locked, asleep, remember_until_quit)
}

/// Whether to lock now: `"idle"`, `"screenLocked"`, `"sleep"` or `None`. `minutes` is the
/// user's setting or `document_auto_lock_minutes` of it (capping twice changes nothing); the
/// managed cap is re-read here so "remember until quit" can never outlast it (TM-02).
/// `idle_secs` is the time since the last input in the app.
#[uniffi::export]
pub fn document_auto_lock_due(minutes: u32, idle_secs: u64, screen_locked: bool, asleep: bool, remember_until_quit: bool) -> Option<String> {
    document_auto_lock_due_under(minutes, idle_secs, screen_locked, asleep, remember_until_quit, &crate::policy::effective_for_documents())
        .and_then(|r| serde_json::to_value(r).ok())
        .and_then(|v| v.as_str().map(String::from))
}

/// The idle minutes in force: the `document.auto-lock-minutes` value (0 = never) capped by a
/// managed policy maximum (`None` or 0 = no policy).
#[uniffi::export]
pub fn effective_auto_lock_minutes(user_minutes: u32, policy_max: Option<u32>) -> u32 {
    docunlock::effective_auto_lock_minutes(user_minutes, policy_max)
}


#[cfg(test)]
mod policy_fail_closed_tests {
    use super::*;
    use bastion_core::CoreError;

    fn broken() -> bastion_core::Result<bastion_core::policy::Policy> {
        Err(CoreError::PolicyDenied("the managed policy cannot be used".into()))
    }

    /// F08: a broken managed policy never allows biometric unlock.
    #[test]
    fn broken_policy_denies_biometric_unlock() {
        assert!(!biometric_allowed_under(&broken()));
        assert!(biometric_allowed_under(&Ok(Default::default())));
    }

    /// F08: a broken managed policy caps auto-lock instead of meaning "never".
    #[test]
    fn broken_policy_caps_auto_lock() {
        assert_eq!(auto_lock_minutes_under(0, &broken()), crate::policy::BROKEN_POLICY_AUTO_LOCK_MINUTES);
        assert_eq!(auto_lock_minutes_under(30, &broken()), crate::policy::BROKEN_POLICY_AUTO_LOCK_MINUTES);
        assert_eq!(auto_lock_minutes_under(0, &Ok(Default::default())), 0);
    }

    /// TM-02: remember-until-quit never outlasts a managed cap, nor a broken policy's cap.
    #[test]
    fn remember_until_quit_cannot_outlast_the_managed_cap() {
        let capped = Ok(bastion_core::policy::Policy { document_auto_lock_max_minutes: Some(1), ..Default::default() });
        assert_eq!(document_auto_lock_due_under(1, 3_600, false, false, true, &capped), Some(docunlock::LockReason::Idle));
        assert_eq!(document_auto_lock_due_under(1, 3_600, false, false, false, &capped), Some(docunlock::LockReason::Idle));
        assert_eq!(document_auto_lock_due_under(1, 30, false, false, true, &capped), None);
        assert_eq!(document_auto_lock_due_under(1, 3_600, false, false, true, &Ok(Default::default())), None, "no cap: remember keeps it open");
        let broken_cap = u64::from(crate::policy::BROKEN_POLICY_AUTO_LOCK_MINUTES) * 60;
        assert_eq!(document_auto_lock_due_under(0, broken_cap, false, false, true, &broken()), Some(docunlock::LockReason::Idle));
    }
}
