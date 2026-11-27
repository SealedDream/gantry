//! External credential providers for the Mac app: 1Password (`op` CLI), KeePass `.kdbx` and
//! HashiCorp Vault KV, the same core service the C ABI uses (`bastion_core::external_providers`).
//! All three are read-only and keep no decrypted cache.
//!
//! The app opens a provider, unlocks it, and registers it. Secrets never come back out: a
//! connect with `SshLogin::Provider { reference: "<provider id>:<item>" }` (for example
//! `keepass:<entry uuid>#username`) reads the secret inside the core at dial time.
//! [`CredentialProviderHandle::check_item`] tests a reference without revealing it.
use std::path::Path;
use std::sync::Arc;

use bastion_core::external_providers::{self as ext, ExternalProvider, ProviderRegistry};
use bastion_core::vault::Secret;

use crate::FfiResult;

/// Outcome of an unlock or an item check.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCheck {
    Ok,
    /// The password, key file or token was refused (or the provider is signed out).
    AuthFailed,
    /// The item does not exist (check only).
    NotFound,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct ProviderStatusView {
    /// `onepassword`, `keepass` or `hcvault`.
    pub id: String,
    /// `available`, `locked` or `unavailable`.
    pub status: String,
    pub reason: Option<String>,
}

/// A KeePass entry without its secret.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct ProviderItemView {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    /// Group names from the root down, root excluded.
    pub group: Vec<String>,
}

impl From<ext::ProviderCheck> for ProviderCheck {
    fn from(c: ext::ProviderCheck) -> Self {
        match c {
            ext::ProviderCheck::Ok => ProviderCheck::Ok,
            ext::ProviderCheck::AuthFailed => ProviderCheck::AuthFailed,
            ext::ProviderCheck::NotFound => ProviderCheck::NotFound,
        }
    }
}

/// Read the secret for `"<provider id>:<item>"` from a registered provider, inside the core.
pub(crate) fn resolve(reference: &str) -> FfiResult<Secret> {
    Ok(ProviderRegistry::global().resolve(reference)?)
}

/// Lock and drop every registered provider (the "Lock Credentials" action). Open handles stay
/// usable but locked.
#[uniffi::export]
pub fn lock_all_providers() {
    ProviderRegistry::global().lock_all();
}

/// One opened provider.
#[derive(uniffi::Object)]
pub struct CredentialProviderHandle {
    kind: Arc<ExternalProvider>,
}

fn handle(kind: ExternalProvider) -> Arc<CredentialProviderHandle> {
    Arc::new(CredentialProviderHandle { kind: Arc::new(kind) })
}

#[uniffi::export]
impl CredentialProviderHandle {
    /// 1Password through its CLI. `op_path` none looks `op` up on PATH and the usual install
    /// dirs; `account` none uses op's default account. Desktop-app sign-in needs no unlock; a
    /// service-account token can be given with `unlock`.
    #[uniffi::constructor]
    pub fn open_onepassword(op_path: Option<String>, account: Option<String>) -> FfiResult<Arc<Self>> {
        Ok(handle(ExternalProvider::onepassword(op_path, account)?))
    }

    /// A KeePass `.kdbx` file (read-only). It starts locked.
    #[uniffi::constructor]
    pub fn open_keepass(path: String) -> Arc<Self> {
        handle(ExternalProvider::keepass(path))
    }

    /// A HashiCorp Vault KV mount, `kv_version` 1 or 2. `base_url` must be https (http only on
    /// loopback). It starts locked.
    #[uniffi::constructor]
    pub fn open_hcvault(base_url: String, kv_version: u8, namespace: Option<String>) -> FfiResult<Arc<Self>> {
        Ok(handle(ExternalProvider::hcvault(&base_url, kv_version.into(), namespace)?))
    }

    /// `onepassword`, `keepass` or `hcvault`.
    pub fn id(&self) -> String {
        self.kind.id().to_string()
    }

    /// KeePass master password (may be empty with `keyfile_path`), the Vault token, or a
    /// 1Password service-account token (empty clears it). `keyfile_path` is for KeePass only.
    pub fn unlock(&self, secret: Option<String>, keyfile_path: Option<String>) -> FfiResult<ProviderCheck> {
        let s = secret.filter(|s| !s.is_empty()).map(Secret::new);
        let keyfile = keyfile_path.filter(|k| !k.is_empty());
        Ok(self.kind.unlock(s, keyfile.as_deref().map(Path::new))?.into())
    }

    /// Forget the unlock (password, key file or token).
    pub fn lock(&self) {
        self.kind.lock();
    }

    pub fn status(&self) -> ProviderStatusView {
        let (status, reason) = self.kind.status();
        ProviderStatusView { id: self.kind.id().to_string(), status: status.to_string(), reason }
    }

    /// KeePass entries without secrets; 1Password and Vault cannot list and give none.
    pub fn items(&self) -> FfiResult<Vec<ProviderItemView>> {
        Ok(self.kind.items()?.into_iter().map(|i| ProviderItemView { id: i.id, title: i.title, username: i.username, group: i.group }).collect())
    }

    /// Whether `item` resolves, without returning the secret.
    pub fn check_item(&self, item: String) -> FfiResult<ProviderCheck> {
        Ok(self.kind.check_item(&item)?.into())
    }

    /// Make `SshLogin::Provider` connects read from this provider under its id. It stays
    /// registered until `lock_all_providers` or another provider with the same id registers.
    pub fn register(&self) {
        ProviderRegistry::global().register(self.kind.clone());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn provider_reference_resolves_inside_the_core_until_locked() {
        let d = tempfile::tempdir().unwrap();
        let op = d.path().join("op");
        std::fs::write(&op, "#!/bin/sh\nprintf 'pw-for-%s' \"$4\"\n").unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = CredentialProviderHandle::open_onepassword(Some(op.to_string_lossy().into_owned()), None).unwrap();
        assert_eq!(p.id(), "onepassword");
        assert_eq!(p.check_item("Prod/db/pw".into()).unwrap(), ProviderCheck::Ok);
        assert!(p.items().unwrap().is_empty(), "1Password cannot list");
        assert!(p.unlock(None, Some("/k".into())).is_err(), "key file is KeePass only");
        assert!(resolve("onepassword:Prod/db/pw").is_err(), "not registered yet");
        p.register();
        assert_eq!(resolve("onepassword:Prod/db/pw").unwrap().expose(), "pw-for-op://Prod/db/pw");
        assert!(resolve("nope:x").is_err());
        assert!(resolve("no-colon").is_err());
        lock_all_providers();
        assert!(resolve("onepassword:Prod/db/pw").is_err(), "lock_all unregisters");
    }

    #[test]
    fn keepass_starts_locked_and_vault_checks_its_arguments() {
        let k = CredentialProviderHandle::open_keepass("/nonexistent/x.kdbx".into());
        assert_eq!(k.id(), "keepass");
        assert_ne!(k.status().status, "available");
        assert!(CredentialProviderHandle::open_hcvault("https://vault.example".into(), 3, None).is_err());
        let v = CredentialProviderHandle::open_hcvault("https://vault.example".into(), 2, None).unwrap();
        assert_eq!(v.status().status, "locked");
        assert!(v.unlock(None, None).is_err(), "a token is required");
        assert_eq!(v.unlock(Some("t".into()), None).unwrap(), ProviderCheck::Ok);
        v.lock();
        assert_eq!(v.status().status, "locked");
    }
}
