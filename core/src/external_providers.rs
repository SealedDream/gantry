//! External credential providers (1Password `op` CLI, KeePass `.kdbx`, HashiCorp Vault KV) as
//! one service both bridges use: opening, unlock dispatch, result classification and the
//! registry that provider logins (`"<provider id>:<item>"`) resolve through.
//!
//! The bridges keep only their boundary work (C pointers and byte buffers, UniFFI lowering).
//! The registry is one explicit process-wide value ([`ProviderRegistry::global`]); tests and
//! embedders can build their own with [`ProviderRegistry::new`].
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};

use crate::hcvault::{HcVaultProvider, KvVersion};
use crate::kdbx::{KeePassEntryInfo, KeePassProvider};
use crate::onepassword::OnePasswordProvider;
use crate::provider::{CredentialProvider, ProviderStatus};
use crate::vault::Secret;
use crate::{CoreError, Result};

/// Outcome of an unlock or an item check that the host shows rather than treats as an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderCheck {
    Ok,
    /// The password, key file or token was refused (or the provider is signed out).
    AuthFailed,
    /// The item does not exist (check only).
    NotFound,
}

/// Map a provider result to a [`ProviderCheck`]; other errors stay errors.
pub fn classify(r: Result<()>) -> Result<ProviderCheck> {
    match r {
        Ok(()) => Ok(ProviderCheck::Ok),
        Err(CoreError::AuthFailed | CoreError::VaultAuth) => Ok(ProviderCheck::AuthFailed),
        Err(CoreError::NotFound(_)) => Ok(ProviderCheck::NotFound),
        Err(e) => Err(e),
    }
}

/// One opened provider.
pub enum ExternalProvider {
    OnePassword(OnePasswordProvider),
    KeePass(KeePassProvider),
    HcVault(HcVaultProvider),
}

impl ExternalProvider {
    /// 1Password through its CLI. Empty strings count as none.
    pub fn onepassword(op_path: Option<String>, account: Option<String>) -> Result<Self> {
        let op = op_path.filter(|s| !s.is_empty()).map(PathBuf::from);
        Ok(Self::OnePassword(OnePasswordProvider::new(op, account.filter(|a| !a.is_empty()))?))
    }

    /// A KeePass file; it starts locked.
    pub fn keepass(path: impl Into<PathBuf>) -> Self {
        Self::KeePass(KeePassProvider::new(path))
    }

    /// A Vault KV mount, `kv_version` 1 or 2; it starts locked.
    pub fn hcvault(base_url: &str, kv_version: i64, namespace: Option<String>) -> Result<Self> {
        let kv = match kv_version {
            1 => KvVersion::V1,
            2 => KvVersion::V2,
            v => return Err(CoreError::Invalid(format!("kv_version must be 1 or 2, not {v}"))),
        };
        Ok(Self::HcVault(HcVaultProvider::new(base_url, kv, namespace.filter(|n| !n.is_empty()))?))
    }

    pub fn provider(&self) -> &dyn CredentialProvider {
        match self {
            Self::OnePassword(p) => p,
            Self::KeePass(p) => p,
            Self::HcVault(p) => p,
        }
    }

    pub fn id(&self) -> &'static str {
        self.provider().id()
    }

    /// KeePass master password (may be none with a key file), the Vault token, or a 1Password
    /// service-account token (none clears it). A key file is for KeePass only.
    pub fn unlock(&self, secret: Option<Secret>, keyfile: Option<&Path>) -> Result<ProviderCheck> {
        match self {
            Self::KeePass(k) => classify(k.unlock(secret, keyfile)),
            _ if keyfile.is_some() => Err(CoreError::Invalid("a key file is for KeePass only".into())),
            Self::OnePassword(o) => {
                o.set_service_token(secret);
                Ok(ProviderCheck::Ok)
            }
            Self::HcVault(v) => {
                v.unlock(secret.ok_or_else(|| CoreError::Invalid("a Vault token is required".into()))?);
                Ok(ProviderCheck::Ok)
            }
        }
    }

    pub fn lock(&self) {
        match self {
            Self::OnePassword(p) => p.lock(),
            Self::KeePass(p) => p.lock(),
            Self::HcVault(p) => p.lock(),
        }
    }

    /// `("available" | "locked" | "unavailable", reason)`.
    pub fn status(&self) -> (&'static str, Option<String>) {
        match self.provider().status() {
            ProviderStatus::Available => ("available", None),
            ProviderStatus::Locked => ("locked", None),
            ProviderStatus::Unavailable(r) => ("unavailable", Some(r)),
        }
    }

    /// KeePass entries without secrets; 1Password and Vault cannot list and give none.
    pub fn items(&self) -> Result<Vec<KeePassEntryInfo>> {
        match self {
            Self::KeePass(k) => k.list(),
            _ => Ok(Vec::new()),
        }
    }

    /// Whether `item` resolves, without returning the secret.
    pub fn check_item(&self, item: &str) -> Result<ProviderCheck> {
        classify(self.provider().fetch(item).map(drop))
    }
}

/// Providers that provider logins read from, one per provider id: registering a second KeePass
/// file replaces the first.
#[derive(Default)]
pub struct ProviderRegistry {
    providers: Mutex<HashMap<&'static str, Arc<ExternalProvider>>>,
}

static GLOBAL: LazyLock<ProviderRegistry> = LazyLock::new(ProviderRegistry::default);

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// The process registry the bridges register into and resolve logins from.
    pub fn global() -> &'static ProviderRegistry {
        &GLOBAL
    }

    fn map(&self) -> MutexGuard<'_, HashMap<&'static str, Arc<ExternalProvider>>> {
        self.providers.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn register(&self, provider: Arc<ExternalProvider>) {
        self.map().insert(provider.id(), provider);
    }

    /// Read the secret for `"<provider id>:<item>"`, inside the core.
    pub fn resolve(&self, reference: &str) -> Result<Secret> {
        let (id, item) = reference.split_once(':').ok_or_else(|| CoreError::Invalid("a provider login is \"<provider>:<item>\"".into()))?;
        let provider = self.map().get(id).cloned().ok_or_else(|| CoreError::NotFound(format!("credential provider `{id}` is not set up")))?;
        provider.provider().fetch(item)
    }

    /// Lock and drop every registered provider. Handles held elsewhere stay usable but locked.
    pub fn lock_all(&self) {
        let drained: Vec<_> = self.map().drain().map(|(_, p)| p).collect();
        drained.iter().for_each(|p| p.lock());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn fake_op(dir: &Path) -> String {
        let op = dir.join("op");
        std::fs::write(&op, "#!/bin/sh\nprintf 'pw-for-%s' \"$4\"\n").unwrap();
        std::fs::set_permissions(&op, std::fs::Permissions::from_mode(0o755)).unwrap();
        op.to_string_lossy().into_owned()
    }

    #[test]
    fn registry_resolves_registered_providers_until_lock_all() {
        let d = tempfile::tempdir().unwrap();
        let reg = ProviderRegistry::new();
        let p = Arc::new(ExternalProvider::onepassword(Some(fake_op(d.path())), Some(String::new())).unwrap());
        assert_eq!(p.check_item("Prod/db/pw").unwrap(), ProviderCheck::Ok);
        assert!(matches!(reg.resolve("onepassword:Prod/db/pw"), Err(CoreError::NotFound(_))), "not registered yet");
        reg.register(p.clone());
        assert_eq!(reg.resolve("onepassword:Prod/db/pw").unwrap().expose(), "pw-for-op://Prod/db/pw");
        assert!(reg.resolve("nope:x").is_err());
        assert!(matches!(reg.resolve("no-colon"), Err(CoreError::Invalid(_))));
        reg.lock_all();
        assert!(reg.resolve("onepassword:Prod/db/pw").is_err(), "lock_all unregisters");
    }

    #[test]
    fn unlock_dispatch_and_classification() {
        let d = tempfile::tempdir().unwrap();
        let op = ExternalProvider::onepassword(Some(fake_op(d.path())), None).unwrap();
        assert!(op.items().unwrap().is_empty(), "1Password cannot list");
        assert!(matches!(op.unlock(None, Some(Path::new("/k"))), Err(CoreError::Invalid(_))), "key file is KeePass only");
        assert_eq!(op.unlock(None, None).unwrap(), ProviderCheck::Ok);

        let k = ExternalProvider::keepass("/nonexistent/x.kdbx");
        assert_eq!(k.id(), "keepass");
        assert_ne!(k.status().0, "available");

        assert!(matches!(ExternalProvider::hcvault("https://vault.example", 3, None), Err(CoreError::Invalid(_))));
        let v = ExternalProvider::hcvault("https://vault.example", 2, Some(String::new())).unwrap();
        assert_eq!(v.status().0, "locked");
        assert!(v.unlock(None, None).is_err(), "a token is required");
        assert_eq!(v.unlock(Some(Secret::new("t")), None).unwrap(), ProviderCheck::Ok);
        v.lock();
        assert_eq!(v.status().0, "locked");

        assert_eq!(classify(Err(CoreError::VaultAuth)).unwrap(), ProviderCheck::AuthFailed);
        assert_eq!(classify(Err(CoreError::NotFound("x".into()))).unwrap(), ProviderCheck::NotFound);
        assert!(classify(Err(CoreError::Timeout)).is_err());
    }
}
