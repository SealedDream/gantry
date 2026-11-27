//! Vaultwarden bridge: unlock with the master password (held only for the duration of the call),
//! keep the decrypted login items inside Rust, and hand the UI names and usernames only.
//! `<data dir>/vaultwarden.json` remembers the server URL, e-mail and a per-install device id;
//! the master password and item secrets are never written anywhere.
use std::path::PathBuf;
use std::sync::Mutex;

use bastion_core::provider::{CredentialProvider, ProviderStatus};
use bastion_core::vault::Secret;
use bastion_core::vaultwarden::{login, VaultwardenLogin, VaultwardenProvider};
use bastion_core::CoreError;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{FfiError, FfiResult};

const CONFIG_FILE: &str = "vaultwarden.json";

#[derive(Default, Serialize, Deserialize)]
struct Config {
    server_url: Option<String>,
    email: Option<String>,
    device_id: Option<String>,
}

#[derive(uniffi::Record)]
pub struct VaultwardenConfigView {
    pub server_url: Option<String>,
    pub email: Option<String>,
}

#[derive(uniffi::Record)]
pub struct VaultwardenItemView {
    pub id: String,
    pub name: String,
    pub username: Option<String>,
}

/// The normalised server URL, or why it is not accepted (https only; http on loopback).
#[uniffi::export]
pub fn check_vaultwarden_url(url: String) -> FfiResult<String> {
    Ok(bastion_core::vaultwarden::check_url(url.trim())?)
}

#[derive(uniffi::Object)]
pub struct VaultwardenSession {
    config_path: PathBuf,
    config: Mutex<Config>,
    provider: VaultwardenProvider,
    /// Refresh token and account key of the current unlock (memory only), for `resync`.
    login: Mutex<Option<VaultwardenLogin>>,
    /// Organisation or undecryptable items left out by the last unlock.
    skipped: Mutex<u32>,
    /// When the items were last fetched (Unix seconds); cleared on lock.
    last_sync: Mutex<Option<u64>>,
}

#[uniffi::export]
impl VaultwardenSession {
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> Self {
        let config_path = PathBuf::from(data_dir).join(CONFIG_FILE);
        let config = std::fs::read(&config_path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        VaultwardenSession { config_path, config: Mutex::new(config), provider: VaultwardenProvider::new(), login: Mutex::new(None), skipped: Mutex::new(0), last_sync: Mutex::new(None) }
    }

    pub fn config(&self) -> VaultwardenConfigView {
        let c = self.config.lock().unwrap_or_else(|e| e.into_inner());
        VaultwardenConfigView { server_url: c.server_url.clone(), email: c.email.clone() }
    }

    /// Log in and sync (blocking network I/O: call off the main thread). On success the server
    /// URL and e-mail are remembered; the password is not. An account with two-step login fails
    /// with `FfiError::TwoFactorRequired` until `totp` holds the current authenticator code.
    pub fn unlock(&self, server_url: String, email: String, master_password: String, totp: Option<String>) -> FfiResult<Vec<VaultwardenItemView>> {
        let master_password = Secret::new(master_password);
        let (server_url, email) = (server_url.trim().to_string(), email.trim().to_string());
        if email.is_empty() || master_password.expose().is_empty() {
            return Err(FfiError::failed("e-mail and master password are required".into()));
        }
        let device_id = self.device_id();
        let totp = totp.filter(|c| !c.trim().is_empty());
        let (result, session) = login(&server_url, &email, master_password.expose(), &device_id, totp.as_deref())?;
        *self.login.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
        self.apply(result);
        {
            let mut c = self.config.lock().unwrap_or_else(|e| e.into_inner());
            c.server_url = Some(server_url);
            c.email = Some(email);
            c.device_id = Some(device_id);
        }
        self.save_config()?;
        Ok(self.items())
    }

    /// Fetch the items again with the in-memory refresh token: no master password, no code.
    /// Fails when locked or when the server no longer accepts the token (unlock again then).
    pub fn resync(&self) -> FfiResult<Vec<VaultwardenItemView>> {
        let mut guard = self.login.lock().unwrap_or_else(|e| e.into_inner());
        let session = guard.as_mut().ok_or_else(|| FfiError::failed("Vaultwarden is locked; unlock it first".into()))?;
        let result = session.resync()?;
        drop(guard);
        self.apply(result);
        Ok(self.items())
    }

    /// Forget the items, the refresh token and the account key.
    pub fn lock(&self) {
        *self.login.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.last_sync.lock().unwrap_or_else(|e| e.into_inner()) = None;
        self.provider.lock();
    }

    /// Unix seconds of the last successful unlock or re-sync while unlocked.
    pub fn last_sync(&self) -> Option<u64> {
        *self.last_sync.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn is_unlocked(&self) -> bool {
        self.provider.status() == ProviderStatus::Available
    }

    pub fn items(&self) -> Vec<VaultwardenItemView> {
        self.provider.list().into_iter().map(|i| VaultwardenItemView { id: i.id, name: i.name, username: i.username }).collect()
    }

    pub fn skipped(&self) -> u32 {
        *self.skipped.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl VaultwardenSession {
    /// Password and username of an item, for a connect. Stays inside Rust.
    pub fn secret_for(&self, item_id: &str) -> FfiResult<(Secret, Option<String>)> {
        let password = self.provider.fetch(item_id).map_err(|e| match e {
            CoreError::VaultAuth => FfiError::failed("Vaultwarden is locked; unlock it in Credentials".into()),
            CoreError::NotFound(_) => FfiError::failed("the Vaultwarden item has no password or no longer exists".into()),
            e => e.into(),
        })?;
        let username = self.provider.fetch(&format!("{item_id}#username")).ok().map(|s| s.expose().to_string());
        Ok((password, username))
    }

    fn apply(&self, result: bastion_core::vaultwarden::SyncResult) {
        *self.skipped.lock().unwrap_or_else(|e| e.into_inner()) = result.skipped as u32;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).ok();
        *self.last_sync.lock().unwrap_or_else(|e| e.into_inner()) = now;
        self.provider.unlock(result);
    }

    /// The stored device id, or a new one (saved together with the first successful unlock).
    fn device_id(&self) -> String {
        let c = self.config.lock().unwrap_or_else(|e| e.into_inner());
        c.device_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string())
    }

    fn save_config(&self) -> FfiResult<()> {
        let bytes = serde_json::to_vec_pretty(&*self.config.lock().unwrap_or_else(|e| e.into_inner())).map_err(|e| FfiError::failed(e.to_string()))?;
        let tmp = self.config_path.with_extension("json.tmp");
        std::fs::write(&tmp, bytes).map_err(CoreError::from)?;
        std::fs::rename(&tmp, &self.config_path).map_err(CoreError::from)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locked_session_refuses_secrets_and_bad_urls_never_persist() {
        let dir = std::env::temp_dir().join(format!("bastion-vw-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let s = VaultwardenSession::new(dir.to_string_lossy().into_owned());
        assert!(!s.is_unlocked() && s.items().is_empty());
        assert!(s.secret_for("x").is_err());
        assert!(s.unlock("http://vault.example.com".into(), "a@b.c".into(), "pw".into(), None).is_err(), "plain http off loopback refused");
        assert!(s.unlock("https://x".into(), "".into(), "pw".into(), None).is_err());
        assert_eq!(s.config().server_url, None, "a failed unlock remembers nothing");
        assert!(!dir.join(CONFIG_FILE).exists());
        assert!(s.resync().is_err(), "re-sync needs an unlock first");
        std::fs::remove_dir_all(dir).ok();
    }
}
