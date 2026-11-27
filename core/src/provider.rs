//! Credential providers: where secrets come from. The broker caches what a provider returns;
//! providers themselves never cache plaintext.
//!
//! - [`LocalVaultProvider`]: the Argon2id/XChaCha20 vault in memory once opened.
//! - [`KeychainProvider`] (macOS): generic-password items in the login Keychain. Its main job
//!   is wrapping the vault key, so the vault can be opened without retyping the master password
//!   and the key is protected by the OS (closes open item O3 on macOS).
//! - [`DpapiProvider`] (Windows, **unverified**): DPAPI-protected blobs in a file.
use std::sync::Mutex;

use rand::RngCore;
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::vault::{CredentialKind, Secret, Vault};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderStatus {
    Available,
    Locked,
    Unavailable(String),
}

pub trait CredentialProvider: Send + Sync {
    /// Stable provider id, part of a credential's identity (`"vault"`, `"keychain"`…).
    fn id(&self) -> &'static str;
    fn status(&self) -> ProviderStatus;
    fn fetch(&self, item: &str) -> Result<Secret>;
    fn store(&self, item: &str, secret: &Secret) -> Result<()>;
    fn delete(&self, item: &str) -> Result<()>;
}

const VAULT_KEY_BYTES: usize = 32;

/// Fetch the vault key from `provider`, creating a random one on first use. The key is a
/// high-entropy secret used in place of a typed master password.
pub fn vault_key(provider: &dyn CredentialProvider, vault_id: &str) -> Result<Secret> {
    let item = format!("vault-key:{vault_id}");
    match provider.fetch(&item) {
        Ok(s) => Ok(s),
        Err(CoreError::NotFound(_)) => {
            let mut raw = zeroize::Zeroizing::new([0u8; VAULT_KEY_BYTES]);
            rand::rngs::OsRng.fill_bytes(raw.as_mut());
            let key = Secret::new(hex::encode(raw.as_ref()));
            provider.store(&item, &key)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// Serves secrets out of an opened vault. `item` is the credential UUID; for SSH keys,
/// `<uuid>#passphrase` returns the passphrase and `<uuid>` the private key.
pub struct LocalVaultProvider {
    vault: Mutex<Option<Vault>>,
}

impl LocalVaultProvider {
    pub fn new(vault: Option<Vault>) -> Self {
        LocalVaultProvider { vault: Mutex::new(vault) }
    }

    pub fn lock(&self) {
        if let Ok(mut v) = self.vault.lock() {
            *v = None;
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Vault) -> Result<T>) -> Result<T> {
        let mut g = self.vault.lock().map_err(|_| CoreError::Invalid("vault state poisoned".into()))?;
        f(g.as_mut().ok_or(CoreError::VaultAuth)?)
    }
}

fn parse_item(item: &str) -> Result<(Uuid, bool)> {
    let (id, passphrase) = match item.strip_suffix("#passphrase") {
        Some(id) => (id, true),
        None => (item, false),
    };
    Ok((Uuid::parse_str(id).map_err(|_| CoreError::Invalid(format!("bad vault item id `{item}`")))?, passphrase))
}

impl CredentialProvider for LocalVaultProvider {
    fn id(&self) -> &'static str {
        "vault"
    }
    fn status(&self) -> ProviderStatus {
        match self.vault.lock() {
            Ok(v) if v.is_some() => ProviderStatus::Available,
            _ => ProviderStatus::Locked,
        }
    }
    fn fetch(&self, item: &str) -> Result<Secret> {
        let (id, want_passphrase) = parse_item(item)?;
        self.with(|v| {
            let c = v.get(id).ok_or_else(|| CoreError::NotFound(item.into()))?;
            match (&c.kind, want_passphrase) {
                (CredentialKind::Password { password, .. }, false) => Ok(password.clone()),
                (CredentialKind::SshKey { private_key, .. }, false) => Ok(private_key.clone()),
                (CredentialKind::SshKey { passphrase: Some(p), .. }, true) => Ok(p.clone()),
                _ => Err(CoreError::NotFound(item.into())),
            }
        })
    }
    fn store(&self, _item: &str, _secret: &Secret) -> Result<()> {
        Err(CoreError::Invalid("add vault credentials through Vault::add".into()))
    }
    fn delete(&self, item: &str) -> Result<()> {
        let (id, _) = parse_item(item)?;
        self.with(|v| v.remove(id).map(|_| ()).ok_or_else(|| CoreError::NotFound(item.into())))
    }
}

#[cfg(target_os = "macos")]
pub use keychain::KeychainProvider;

#[cfg(target_os = "macos")]
mod keychain {
    use security_framework::passwords::{delete_generic_password, get_generic_password, set_generic_password};

    use super::{CredentialProvider, ProviderStatus};
    use crate::error::{CoreError, Result};
    use crate::vault::Secret;

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
    /// errSecUserCanceled (Deny / Cancel on the Keychain prompt) and errSecAuthFailed.
    const ERR_SEC_USER_CANCELED: i32 = -128;
    const ERR_SEC_AUTH_FAILED: i32 = -25293;

    /// Login-Keychain generic passwords under one service name.
    pub struct KeychainProvider {
        service: String,
        legacy: Option<String>,
    }

    impl KeychainProvider {
        pub fn new(service: impl Into<String>) -> Self {
            KeychainProvider { service: service.into(), legacy: None }
        }

        /// `service`, falling back to `legacy` (the service name before the product rename): an
        /// item found only under `legacy` is copied to `service` on first read. The old item is
        /// kept, so an older build still opens.
        pub fn with_legacy(service: impl Into<String>, legacy: impl Into<String>) -> Self {
            KeychainProvider { service: service.into(), legacy: Some(legacy.into()) }
        }

        fn read(service: &str, item: &str) -> Result<Secret> {
            let bytes = zeroize::Zeroizing::new(get_generic_password(service, item).map_err(|e| map(e, item))?);
            let s = std::str::from_utf8(&bytes).map_err(|_| CoreError::Corrupt("Keychain item is not UTF-8".into()))?;
            Ok(Secret::new(s))
        }
    }

    fn map(e: security_framework::base::Error, item: &str) -> CoreError {
        if e.code() == ERR_SEC_ITEM_NOT_FOUND {
            CoreError::NotFound(item.into())
        } else if e.code() == ERR_SEC_USER_CANCELED || e.code() == ERR_SEC_AUTH_FAILED {
            CoreError::Cancelled
        } else {
            CoreError::Invalid(format!("Keychain error {}", e.code()))
        }
    }

    impl CredentialProvider for KeychainProvider {
        fn id(&self) -> &'static str {
            "keychain"
        }
        fn status(&self) -> ProviderStatus {
            ProviderStatus::Available
        }
        fn fetch(&self, item: &str) -> Result<Secret> {
            match (Self::read(&self.service, item), &self.legacy) {
                (Err(CoreError::NotFound(_)), Some(legacy)) => {
                    let secret = Self::read(legacy, item)?;
                    // Best effort: a failed copy still returns the secret and retries next read.
                    let _ = set_generic_password(&self.service, item, secret.expose().as_bytes());
                    Ok(secret)
                }
                (r, _) => r,
            }
        }
        fn store(&self, item: &str, secret: &Secret) -> Result<()> {
            set_generic_password(&self.service, item, secret.expose().as_bytes()).map_err(|e| map(e, item))
        }
        fn delete(&self, item: &str) -> Result<()> {
            let current = delete_generic_password(&self.service, item).map_err(|e| map(e, item));
            let Some(legacy) = &self.legacy else { return current };
            match (current, delete_generic_password(legacy, item).map_err(|e| map(e, item))) {
                (Ok(()), _) | (Err(CoreError::NotFound(_)), Ok(())) => Ok(()),
                (Err(e), _) => Err(e),
            }
        }
    }
}

#[cfg(windows)]
pub use dpapi::DpapiProvider;

/// UNVERIFIED: compiled for Windows targets only and never run on Windows yet.
#[cfg(windows)]
mod dpapi {
    use std::path::PathBuf;

    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptProtectData, CryptUnprotectData, CRYPT_INTEGER_BLOB};

    use super::{CredentialProvider, ProviderStatus};
    use crate::error::{CoreError, Result};
    use crate::vault::Secret;

    /// DPAPI (current-user scope) blobs stored one file per item under `dir`.
    pub struct DpapiProvider {
        dir: PathBuf,
    }

    impl DpapiProvider {
        pub fn new(dir: impl Into<PathBuf>) -> Self {
            DpapiProvider { dir: dir.into() }
        }
        fn path(&self, item: &str) -> PathBuf {
            self.dir.join(hex::encode(item.as_bytes()))
        }
    }

    fn transform(data: &[u8], protect: bool) -> Result<Vec<u8>> {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        // SAFETY: input points to `data` for the duration of the call; on success `out` is a
        // LocalAlloc'd buffer that we copy and free exactly once.
        let ok = unsafe {
            if protect {
                CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out)
            } else {
                CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out)
            }
        };
        if ok == 0 {
            return Err(CoreError::Invalid("DPAPI call failed".into()));
        }
        // The output (plaintext on unprotect) is wiped before it goes back to the OS, on every path.
        let guard = OsBuffer { ptr: out.pbData, len: out.cbData as usize, release: local_free };
        Ok(guard.bytes().to_vec())
    }

    fn local_free(ptr: *mut u8) {
        // SAFETY: `ptr` came from DPAPI's LocalAlloc and is released exactly once, by `OsBuffer::drop`.
        unsafe { LocalFree(ptr as _) };
    }

    /// A buffer the OS allocated for DPAPI output. Dropping it zeroes every byte, then releases it
    /// once (Microsoft's CryptUnprotectData guidance: clear sensitive output before LocalFree).
    struct OsBuffer {
        ptr: *mut u8,
        len: usize,
        release: fn(*mut u8),
    }

    impl OsBuffer {
        fn bytes(&self) -> &[u8] {
            if self.ptr.is_null() {
                return &[];
            }
            // SAFETY: the owner handed over `len` valid bytes at `ptr`, alive until drop.
            unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
        }
    }

    impl Drop for OsBuffer {
        fn drop(&mut self) {
            if self.ptr.is_null() {
                return;
            }
            // SAFETY: as in `bytes`; nothing else references the buffer any more.
            zeroize::Zeroize::zeroize(unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) });
            (self.release)(self.ptr);
        }
    }

    #[cfg(test)]
    mod tests {
        use std::cell::RefCell;

        use super::OsBuffer;

        thread_local! {
            static RELEASED: RefCell<Vec<Vec<u8>>> = const { RefCell::new(Vec::new()) };
        }

        // Records what the buffer held at release time, then frees it the way it was allocated.
        fn record(ptr: *mut u8) {
            // SAFETY: tests allocate 16-byte boxed slices below.
            let held = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, 16)) };
            RELEASED.with(|r| r.borrow_mut().push(held.to_vec()));
        }

        fn sentinel() -> *mut u8 {
            Box::into_raw(vec![0xA5u8; 16].into_boxed_slice()) as *mut u8
        }

        #[test]
        fn dpapi_output_is_zeroed_once_before_release() {
            let guard = OsBuffer { ptr: sentinel(), len: 16, release: record };
            assert_eq!(guard.bytes(), &[0xA5; 16]);
            let copied = guard.bytes().to_vec();
            drop(guard);
            assert_eq!(copied, vec![0xA5; 16], "the caller's copy is untouched");
            RELEASED.with(|r| assert_eq!(*r.borrow(), vec![vec![0u8; 16]], "released once, all zero"));
        }

        #[test]
        fn dpapi_output_is_zeroed_when_the_copy_unwinds() {
            let result = std::panic::catch_unwind(|| {
                let guard = OsBuffer { ptr: sentinel(), len: 16, release: record };
                let _ = guard.bytes();
                panic!("copy failed");
            });
            assert!(result.is_err());
            RELEASED.with(|r| assert_eq!(*r.borrow(), vec![vec![0u8; 16]]));
        }

        #[test]
        fn dpapi_round_trip_still_works() {
            let blob = super::transform(b"sentinel-secret", true).expect("protect");
            assert_eq!(super::transform(&blob, false).expect("unprotect"), b"sentinel-secret");
        }
    }

    impl CredentialProvider for DpapiProvider {
        fn id(&self) -> &'static str {
            "dpapi"
        }
        fn status(&self) -> ProviderStatus {
            ProviderStatus::Available
        }
        fn fetch(&self, item: &str) -> Result<Secret> {
            let blob = std::fs::read(self.path(item)).map_err(|_| CoreError::NotFound(item.into()))?;
            let plain = zeroize::Zeroizing::new(transform(&blob, false)?);
            Ok(Secret::new(std::str::from_utf8(&plain).map_err(|_| CoreError::Corrupt("DPAPI item is not UTF-8".into()))?))
        }
        fn store(&self, item: &str, secret: &Secret) -> Result<()> {
            std::fs::create_dir_all(&self.dir)?;
            std::fs::write(self.path(item), transform(secret.expose().as_bytes(), true)?)?;
            Ok(())
        }
        fn delete(&self, item: &str) -> Result<()> {
            std::fs::remove_file(self.path(item)).map_err(|_| CoreError::NotFound(item.into()))
        }
    }
}
