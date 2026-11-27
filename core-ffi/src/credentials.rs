//! Credential vault bridge: the encrypted `Vault` file next to the library, opened with a random
//! key that the macOS login Keychain (Windows: DPAPI for the current user) wraps (no master
//! password to type). Secrets go *in* through
//! this surface and, with one exception, never come back out: listings are names and usernames
//! only, and SSH connects read the secret inside the core (`SshLogin::Vault`). The exception is
//! `rdp_login_for`: the in-process RDP client takes the password itself (audited per release).
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use bastion_core::vault::{Credential, CredentialKind, Secret, Vault};
use bastion_core::CoreError;
use uuid::Uuid;

use crate::{parse_id, FfiError, FfiResult};

/// Keychain service that holds the vault key (`vault-key:<vault path>`).
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "Gantry";
/// The Keychain service before the product rename; read when an item is missing under the new one.
const LEGACY_KEYCHAIN_SERVICE: &str = "Bastion";

#[derive(uniffi::Record)]
pub struct CredentialView {
    pub id: String,
    pub name: String,
    pub folder: Option<String>,
    pub username: String,
    /// `password` or `ssh-key`.
    pub kind: String,
}

/// A connection's inline secret (no secret fields): who it signs in as and what it is.
#[derive(uniffi::Record)]
pub struct InlineCredentialView {
    pub username: String,
    /// `password` or `ssh-key`.
    pub kind: String,
}

/// The username and password a saved RDP connection signs in with. RDP is the one protocol
/// whose client takes the password itself (the in-process RDP session), so this is the only
/// place a stored secret leaves the vault; every release is audited.
#[derive(uniffi::Record)]
pub struct RdpSavedLogin {
    pub username: String,
    pub password: String,
}

#[derive(uniffi::Object)]
pub struct CredentialVault {
    path: PathBuf,
    key: Secret,
    vault: Mutex<Vault>,
    /// Set for a library's vault (OF-F): saves go into this encrypted document, not `path`.
    document: Option<std::sync::Arc<Mutex<bastion_core::docfile::DocumentFile>>>,
    /// Held for a whole save, so saves write in the order they read the vault; the vault lock is not held while the
    /// key is derived, so reads on the UI thread do not wait for a save (WIN-SSH-OPEN-STALL).
    save_order: Mutex<()>,
}

#[uniffi::export]
impl CredentialVault {
    /// Open (or create) the vault at `path`. The key comes from the login Keychain (Windows: a
    /// DPAPI blob beside the vault) and is generated on first use. The item is per vault path, so
    /// two libraries never share a key. Unsigned dev builds get a Keychain prompt after each
    /// rebuild (the item's access list names the binary); signed app bundles keep a stable
    /// identity and do not.
    #[uniffi::constructor]
    pub fn open(path: String) -> FfiResult<Self> {
        let key = legacy_key(&path)?;
        Self::open_with_key(path, key)
    }

    /// UI tests only: a new vault whose random key lives in memory and never in the Keychain;
    /// the file cannot be reopened once this object is gone.
    #[uniffi::constructor]
    pub fn open_ephemeral(path: String) -> FfiResult<Self> {
        Self::open_with_key(path, Secret::new(format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple())))
    }

    pub fn list(&self) -> Vec<CredentialView> {
        let v = self.lock();
        let mut out: Vec<CredentialView> = v
            .list()
            .into_iter()
            .map(|i| CredentialView {
                kind: match v.get(i.id).map(|c| &c.kind) {
                    Some(CredentialKind::SshKey { .. }) => "ssh-key".into(),
                    _ => "password".into(),
                },
                id: i.id.to_string(),
                name: i.name,
                folder: i.folder,
                username: i.username,
            })
            .chain(v.list_unsupported().into_iter().map(|i| CredentialView {
                kind: "unsupported".into(),
                id: i.id.to_string(),
                name: i.name,
                folder: i.folder,
                username: i.username,
            }))
            .collect();
        out.sort_by_key(|c| c.name.to_lowercase());
        out
    }

    /// Add (`id` = None) or update a password credential. On update an empty `password` keeps
    /// the stored one, so editing a name never requires re-typing the secret.
    pub fn save_password(&self, id: Option<String>, name: String, folder: Option<String>, username: String, password: String) -> FfiResult<String> {
        self.upsert(id, name, folder, |old| {
            let password = match old {
                Some(CredentialKind::Password { password: p, .. }) if password.is_empty() => p.clone(),
                _ if password.is_empty() => return Err(invalid("a password is required")),
                _ => Secret::new(password),
            };
            Ok(CredentialKind::Password { username, password })
        })
    }

    /// Add or update an SSH private key credential (PEM/OpenSSH text). Empty `private_key` on
    /// update keeps the stored key. Passphrase-protected keys are rejected: the connect path
    /// uses the key as-is.
    pub fn save_ssh_key(&self, id: Option<String>, name: String, folder: Option<String>, username: String, private_key: String) -> FfiResult<String> {
        if private_key.contains("ENCRYPTED") {
            return Err(invalid("passphrase-protected keys are not supported in the vault; use a key file instead"));
        }
        self.upsert(id, name, folder, |old| {
            let private_key = match old {
                Some(CredentialKind::SshKey { private_key: k, .. }) if private_key.is_empty() => k.clone(),
                _ if private_key.trim().is_empty() => return Err(invalid("a private key is required")),
                _ => Secret::new(private_key),
            };
            Ok(CredentialKind::SshKey { username, private_key, passphrase: None })
        })
    }

    pub fn remove(&self, id: String) -> FfiResult<()> {
        let id = parse_id(&id)?;
        let mut v = self.lock();
        if v.inline(id).is_some() || v.is_unsupported_inline(id) {
            return Err(invalid("no such credential"));
        }
        let unsupported = v.is_unsupported(id);
        if v.remove(id).is_none() && !unsupported {
            return Err(invalid("no such credential"));
        }
        Ok(())
    }

    /// The id of the saved credential called `name` (case-insensitive), for a connection that
    /// names its credential instead of choosing one. `None` when no or several match.
    pub fn find_by_name(&self, name: String) -> Option<String> {
        let v = self.lock();
        let hits: Vec<_> = v.list().into_iter().filter(|c| c.name.eq_ignore_ascii_case(name.trim())).collect();
        (hits.len() == 1).then(|| hits[0].id.to_string())
    }

    // MARK: Inline secrets
    //
    // A connection's own username and password or private key, typed in its properties for a
    // quick test. They live only in this encrypted vault under the connection's id (never in
    // library.json or an export), connect through `SshLogin::Vault { credential_id: <connection
    // id> }` and so through the broker, and are deleted with the connection (`prune_inline`).
    // Saving and removing them is recorded in the audit log.

    pub fn inline_for(&self, connection_id: String) -> FfiResult<Option<InlineCredentialView>> {
        let v = self.lock();
        Ok(v.inline(parse_id(&connection_id)?).map(|c| match &c.kind {
            CredentialKind::Password { username, .. } => InlineCredentialView { username: username.clone(), kind: "password".into() },
            CredentialKind::SshKey { username, .. } => InlineCredentialView { username: username.clone(), kind: "ssh-key".into() },
        }))
    }

    /// The password login a saved RDP connection uses without asking: its own inline password
    /// first, else the vault credential `credential_id` when the shared login rule gives it to
    /// this connection as its own or inherited login (`may_use_unasked`). Any other
    /// `credential_id` is refused before it is looked up (A1-CORE-01-FU3); a login the user
    /// picks in the connect sheet goes through `release_login`. `None` when neither is a
    /// password (an SSH key of its own, or nothing saved), so the connect sheet asks as before.
    pub fn rdp_login_for(&self, library: Arc<crate::Library>, connection_id: String, credential_id: Option<String>) -> FfiResult<Option<RdpSavedLogin>> {
        let connection = parse_id(&connection_id)?;
        let password_of = |c: Option<&Credential>| match c.map(|c| &c.kind) {
            Some(CredentialKind::Password { username, password }) => Some(RdpSavedLogin { username: username.clone(), password: password.expose().to_string() }),
            _ => None,
        };
        // The inline secret is stored under the connection's id and is private to it.
        let (has_inline, own) = {
            let v = self.lock();
            let inline = v.inline(connection);
            (inline.is_some(), password_of(inline))
        };
        let login = if has_inline {
            own
        } else {
            // An id that is not a UUID names nothing, as before.
            let Some(credential) = credential_id.as_deref().and_then(|id| parse_id(id).ok()) else { return Ok(None) };
            if !self.may_use_unasked(&library, connection, credential, bastion_core::logins::LoginPurpose::Password)? {
                return Err(invalid(crate::credtree::NOT_OFFERED));
            }
            password_of(self.lock().get(credential))
        };
        let Some(login) = login else { return Ok(None) };
        self.audit("credential.release.rdp", &connection_id, "password")?;
        Ok(Some(login))
    }

    /// Store a username and password on the connection. An empty `password` keeps a stored one.
    pub fn set_inline_password(&self, connection_id: String, username: String, password: String) -> FfiResult<()> {
        let id = parse_id(&connection_id)?;
        let mut v = self.lock();
        let password = match v.inline(id).map(|c| &c.kind) {
            Some(CredentialKind::Password { password: p, .. }) if password.is_empty() => p.clone(),
            _ if password.is_empty() => return Err(invalid("a password is required")),
            _ => Secret::new(password),
        };
        v.set_inline(id, CredentialKind::Password { username, password });
        drop(v);
        self.audit("credential.inline.save", &connection_id, "password")
    }

    /// Store a private key (pasted text or a key file's contents) on the connection. An
    /// encrypted key is decrypted with `passphrase` first and stored without one (the vault is
    /// encrypted). An empty `private_key` keeps a stored key and only changes the username.
    pub fn set_inline_key(&self, connection_id: String, username: String, private_key: String, passphrase: Option<String>) -> FfiResult<()> {
        let id = parse_id(&connection_id)?;
        let mut v = self.lock();
        let private_key = match v.inline(id).map(|c| &c.kind) {
            Some(CredentialKind::SshKey { private_key: k, .. }) if private_key.trim().is_empty() => k.clone(),
            _ if private_key.trim().is_empty() => return Err(invalid("a private key is required")),
            _ => bastion_core::ssh_auth::unlock_private_key(&private_key, passphrase.as_deref())?,
        };
        v.set_inline(id, CredentialKind::SshKey { username, private_key, passphrase: None });
        drop(v);
        self.audit("credential.inline.save", &connection_id, "ssh-key")
    }

    pub fn remove_inline(&self, connection_id: String) -> FfiResult<bool> {
        let removed = self.lock().remove_inline(parse_id(&connection_id)?);
        if removed {
            self.audit("credential.inline.remove", &connection_id, "")?;
        }
        Ok(removed)
    }

    /// Delete inline secrets of connections not in `live_connection_ids` (call after deleting
    /// connections, with every id still in the library). Returns how many were removed.
    pub fn prune_inline(&self, live_connection_ids: Vec<String>) -> FfiResult<u32> {
        let live = live_connection_ids.iter().map(|i| parse_id(i)).collect::<FfiResult<std::collections::BTreeSet<_>>>()?;
        let n = self.lock().prune_inline(&live);
        if n > 0 {
            self.audit("credential.inline.prune", "", &n.to_string())?;
        }
        Ok(n as u32)
    }

    /// Seal and write the vault atomically (unpredictable owner-only temp file, fsync, rename).
    /// Saves are serialized by `save_order`, so the file always holds a whole snapshot and the last save wins (F03).
    /// The vault lock covers only the snapshot: the key derivation runs without it, so reads do not wait for a save.
    pub fn save(&self) -> FfiResult<()> {
        // The order lock first: a second save waits here, not while holding the vault lock.
        let _order = self.save_order.lock().unwrap_or_else(|e| e.into_inner());
        let vault = self.lock();
        if let Some(doc) = &self.document {
            let mut f = doc.lock().unwrap_or_else(|e| e.into_inner());
            f.set_vault(&vault)?;
            if f.path().is_some() {
                f.save()?;
            }
            return Ok(());
        }
        let plain = vault.to_plain()?;
        drop(vault);
        let bytes = zeroize::Zeroizing::new(Vault::seal_plain(&plain, self.key.expose())?);
        bastion_core::store::write_atomic(&self.path, &bytes)?;
        Ok(())
    }
}

impl CredentialVault {
    pub fn open_with_key(path: String, key: Secret) -> FfiResult<Self> {
        let path = PathBuf::from(path);
        let vault = match std::fs::read(&path) {
            Ok(bytes) => Vault::open(&bytes, key.expose())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vault::default(),
            Err(e) => return Err(CoreError::from(e).into()),
        };
        Ok(CredentialVault { path, key, vault: Mutex::new(vault), document: None, save_order: Mutex::new(()) })
    }

    /// The vault stored inside an unlocked library document (OF-F).
    pub(crate) fn for_document(doc: std::sync::Arc<Mutex<bastion_core::docfile::DocumentFile>>) -> FfiResult<Self> {
        let (vault, path) = {
            let f = doc.lock().unwrap_or_else(|e| e.into_inner());
            (f.vault()?, f.path().map(PathBuf::from).unwrap_or_default())
        };
        Ok(CredentialVault { path, key: Secret::new(String::new()), vault: Mutex::new(vault), document: Some(doc), save_order: Mutex::new(()) })
    }

    /// The secret and username for a connect. Stays inside Rust.
    pub fn secret_for(&self, id: &str) -> FfiResult<(CredentialKind, String)> {
        let v = self.lock();
        let c = v.get(parse_id(id)?).ok_or_else(|| invalid("the assigned credential is no longer in the vault"))?;
        let user = match &c.kind {
            CredentialKind::Password { username, .. } | CredentialKind::SshKey { username, .. } => username.clone(),
        };
        Ok((c.kind.clone(), user))
    }

    /// The saved credential's own customer scope (never inferred from a connection).
    pub(crate) fn scope_for(&self, id: &str) -> FfiResult<Option<String>> {
        let v = self.lock();
        let c = v.get(parse_id(id)?).ok_or_else(|| invalid("the assigned credential is no longer in the vault"))?;
        Ok(c.scope.clone())
    }

    /// Hash-chained audit entry beside the vault (`audit.jsonl`); never includes a secret.
    /// B13: the connection's own inline password, else its effective vault credential when the
    /// shared login rule offers it unasked (`may_use_unasked`). SSH keys and anything else: `None`.
    /// The caller audits the release.
    pub(crate) fn password_login_for(&self, library: &Arc<crate::Library>, connection: Uuid, credential_id: Option<String>) -> FfiResult<Option<(String, zeroize::Zeroizing<String>)>> {
        let password_of = |c: Option<&Credential>| match c.map(|c| &c.kind) {
            Some(CredentialKind::Password { username, password }) => Some((username.clone(), zeroize::Zeroizing::new(password.expose().to_string()))),
            _ => None,
        };
        let (has_inline, own) = {
            let v = self.lock();
            let inline = v.inline(connection);
            (inline.is_some(), password_of(inline))
        };
        if has_inline {
            return Ok(own);
        }
        let Some(credential) = credential_id.as_deref().and_then(|id| parse_id(id).ok()) else { return Ok(None) };
        if !self.may_use_unasked(library, connection, credential, bastion_core::logins::LoginPurpose::Password)? {
            return Ok(None);
        }
        Ok(password_of(self.lock().get(credential)))
    }

    /// B13 audit record: the page origin and the result code, never a user name or secret.
    pub(crate) fn audit_web(&self, action: &str, connection_id: &str, outcome: bastion_core::audit::Outcome, origin: &str, result: &str) -> FfiResult<()> {
        use bastion_core::audit::{AuditLog, Category};
        let dir = self.path.parent().unwrap_or(std::path::Path::new("."));
        let details = [("origin".to_string(), origin.to_string()), ("result".to_string(), result.to_string())].into_iter().collect();
        AuditLog::open(dir.join("audit.jsonl"))?.record(Category::CredentialAccess, action, Some(connection_id).filter(|c| !c.is_empty()), outcome, details)?;
        Ok(())
    }

    pub(crate) fn audit(&self, action: &str, connection_id: &str, kind: &str) -> FfiResult<()> {
        use bastion_core::audit::{AuditLog, Category, Outcome};
        let dir = self.path.parent().unwrap_or(std::path::Path::new("."));
        let details = [("kind".to_string(), kind.to_string())].into_iter().filter(|(_, v)| !v.is_empty()).collect();
        AuditLog::open(dir.join("audit.jsonl"))?.record(Category::CredentialAccess, action, Some(connection_id).filter(|c| !c.is_empty()), Outcome::Success, details)?;
        Ok(())
    }

    fn upsert(&self, id: Option<String>, name: String, folder: Option<String>, kind: impl FnOnce(Option<&CredentialKind>) -> FfiResult<CredentialKind>) -> FfiResult<String> {
        if name.trim().is_empty() {
            return Err(invalid("a name is required"));
        }
        let mut v = self.lock();
        let id = id.as_deref().map(parse_id).transpose()?.unwrap_or_else(Uuid::new_v4);
        if v.is_unsupported(id) {
            return Err(invalid(bastion_core::vault_unknown::UNSUPPORTED_CREDENTIAL_DETAIL));
        }
        let old = v.get(id).cloned();
        if old.as_ref().is_some_and(|c| c.owner.is_some()) {
            return Err(invalid("no such credential"));
        }
        let kind = kind(old.as_ref().map(|c| &c.kind))?;
        let scope = old.and_then(|c| c.scope);
        let folder = folder.filter(|f| !f.trim().is_empty());
        v.add(Credential { id, name, folder, scope, owner: None, kind });
        Ok(id.to_string())
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Vault> {
        self.vault.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// The old per-path vault key from the login Keychain (Windows: DPAPI). Cancel -> `cancelled`.
pub(crate) fn legacy_key(path: &str) -> FfiResult<Secret> {
    let id = std::fs::canonicalize(PathBuf::from(path).parent().unwrap_or(std::path::Path::new(".")))
        .map(|d| d.join(PathBuf::from(path).file_name().unwrap_or_default()).to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string());
    os_key(&id)
}

fn invalid(m: &str) -> FfiError {
    FfiError::failed(m.into())
}

#[cfg(target_os = "macos")]
fn os_key(id: &str) -> FfiResult<Secret> {
    let provider = bastion_core::provider::KeychainProvider::with_legacy(KEYCHAIN_SERVICE, LEGACY_KEYCHAIN_SERVICE);
    Ok(bastion_core::provider::vault_key(&provider, id)?)
}

/// Windows: the key is a DPAPI blob (current user) in a `vault-key` folder beside the vault,
/// named after the vault file, so only this Windows account can unwrap it and two libraries never
/// share a key. The item is the file name rather than the full path to stay clear of MAX_PATH.
#[cfg(windows)]
fn os_key(id: &str) -> FfiResult<Secret> {
    let path = std::path::Path::new(id);
    let dir = path.parent().unwrap_or(std::path::Path::new(".")).join("vault-key");
    let name = path.file_name().ok_or_else(|| invalid("the vault path has no file name"))?.to_string_lossy();
    let provider = bastion_core::provider::DpapiProvider::new(dir);
    migrate_windows_key(&provider, path, &name)?;
    Ok(bastion_core::provider::vault_key(&provider, &name)?)
}

/// Native Windows builds before this layout kept the key in `credentials.keys\` beside the vault,
/// under the full vault path. Copy such a key to the new place once (still DPAPI-wrapped for this
/// user), so an existing vault keeps opening; the old blob is removed only after the copy is stored.
#[cfg(windows)]
fn migrate_windows_key(provider: &bastion_core::provider::DpapiProvider, path: &std::path::Path, name: &str) -> FfiResult<()> {
    use bastion_core::provider::CredentialProvider;
    let item = format!("vault-key:{name}");
    if provider.fetch(&item).is_ok() {
        return Ok(());
    }
    let old_dir = path.parent().unwrap_or(std::path::Path::new(".")).join("credentials.keys");
    let old = bastion_core::provider::DpapiProvider::new(old_dir);
    let old_item = format!("vault-key:{}", path.to_string_lossy());
    if let Ok(key) = old.fetch(&old_item) {
        provider.store(&item, &key)?;
        let _ = old.delete(&old_item);
    }
    Ok(())
}

#[cfg(not(any(target_os = "macos", windows)))]
fn os_key(_id: &str) -> FfiResult<Secret> {
    Err(invalid("the credential vault needs the macOS Keychain or Windows DPAPI"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_round_trip_without_exposing_secrets() {
        let dir = std::env::temp_dir().join(format!("bastion-cred-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.vault").to_string_lossy().into_owned();
        let v = CredentialVault::open_with_key(path.clone(), Secret::new("k".repeat(64))).unwrap();
        let id = v.save_password(None, "db admin".into(), Some("Acme".into()), "root".into(), "s3cret".into()).unwrap();
        assert!(v.save_password(None, " ".into(), None, "u".into(), "p".into()).is_err());
        // Renaming with an empty password keeps the stored secret.
        v.save_password(Some(id.clone()), "DB admin".into(), None, "root".into(), String::new()).unwrap();
        assert!(v.save_ssh_key(None, "k".into(), None, "u".into(), "-----BEGIN ENCRYPTED PRIVATE KEY-----".into()).is_err());
        v.save().unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("s3cret"));

        let reopened = CredentialVault::open_with_key(path.clone(), Secret::new("k".repeat(64))).unwrap();
        let list = reopened.list();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].name.as_str(), list[0].folder.as_deref(), list[0].kind.as_str()), ("DB admin", None, "password"));
        match reopened.secret_for(&id).unwrap() {
            (CredentialKind::Password { password, .. }, user) => assert_eq!((password.expose(), user.as_str()), ("s3cret", "root")),
            _ => panic!("wrong kind"),
        }
        assert!(CredentialVault::open_with_key(path, Secret::new("wrong")).is_err());
        reopened.remove(id).unwrap();
        assert!(reopened.list().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn rdp_login_prefers_the_inline_password_then_the_assigned_one() {
        let dir = std::env::temp_dir().join(format!("bastion-cred-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.vault").to_string_lossy().into_owned();
        let v = CredentialVault::open_with_key(path, Secret::new("k".repeat(64))).unwrap();
        let lib = std::sync::Arc::new(crate::Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let conn = lib.add_connection(None, "desktop".into(), "rdp".into(), "desk.lab.example".into(), None, None).unwrap();
        assert!(v.rdp_login_for(lib.clone(), conn.clone(), None).unwrap().is_none());
        let assigned = v.save_password(None, "admin".into(), None, "corp\\admin".into(), "a1".into()).unwrap();
        v.add_login(lib.clone(), conn.clone(), assigned.clone()).unwrap();
        let l = v.rdp_login_for(lib.clone(), conn.clone(), Some(assigned.clone())).unwrap().unwrap();
        assert_eq!((l.username.as_str(), l.password.as_str()), ("corp\\admin", "a1"));
        v.set_inline_password(conn.clone(), "mo".into(), "i2".into()).unwrap();
        let l = v.rdp_login_for(lib, conn.clone(), Some(assigned)).unwrap().unwrap();
        assert_eq!((l.username.as_str(), l.password.as_str()), ("mo", "i2"));
        assert!(std::fs::read_to_string(dir.join("audit.jsonl")).unwrap().contains("credential.release.rdp"));
        std::fs::remove_dir_all(dir).ok();
    }

    /// F03: a planted symlink at the old predictable temp name is never followed.
    #[cfg(unix)]
    #[test]
    fn save_never_follows_a_planted_temp_symlink() {
        let dir = std::env::temp_dir().join(format!("bastion-cred-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.vault");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, "untouched").unwrap();
        std::os::unix::fs::symlink(&victim, path.with_extension("vault.tmp")).unwrap();
        let v = CredentialVault::open_with_key(path.to_string_lossy().into_owned(), Secret::new("k".repeat(64))).unwrap();
        v.save_password(None, "db".into(), None, "root".into(), "s3cret".into()).unwrap();
        v.save().unwrap();
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched");
        assert!(!std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
        std::fs::remove_dir_all(dir).ok();
    }

    /// F03: overlapping saves never clobber each other's temp file; every save succeeds.
    #[test]
    fn concurrent_saves_are_serialized() {
        let dir = std::env::temp_dir().join(format!("bastion-cred-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.vault").to_string_lossy().into_owned();
        let v = std::sync::Arc::new(CredentialVault::open_with_key(path.clone(), Secret::new("k".repeat(64))).unwrap());
        let hs: Vec<_> = (0..8).map(|i| {
            let v = v.clone();
            std::thread::spawn(move || {
                v.save_password(None, format!("c{i}"), None, "u".into(), "p".into()).unwrap();
                v.save().unwrap();
            })
        }).collect();
        hs.into_iter().for_each(|h| h.join().unwrap());
        v.save().unwrap();
        let reopened = CredentialVault::open_with_key(path, Secret::new("k".repeat(64))).unwrap();
        assert_eq!(reopened.list().len(), 8);
        std::fs::remove_dir_all(dir).ok();
    }

    /// WIN-SSH-OPEN-STALL: a read does not wait for a save's key derivation (Argon2id, 100-250 ms in release), and
    /// the saved file still holds what was in the vault when the save began.
    #[test]
    fn reads_do_not_wait_for_a_save() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.vault").display().to_string();
        let v = std::sync::Arc::new(CredentialVault::open_with_key(path.clone(), Secret::new("k".repeat(64))).unwrap());
        v.save_password(None, "first".into(), None, "u".into(), "p".into()).unwrap();
        let saver = { let v = v.clone(); std::thread::spawn(move || v.save().unwrap()) };
        // Wait until the save has its snapshot (it holds the order lock and has let the vault lock go).
        while v.save_order.try_lock().is_ok() { std::thread::yield_now(); }
        while v.vault.try_lock().is_err() { std::thread::yield_now(); }
        assert_eq!(v.list().len(), 1, "read during the save");
        assert!(v.save_order.try_lock().is_err(), "the read waited for the whole save");
        saver.join().unwrap();
        let reopened = CredentialVault::open_with_key(path, Secret::new("k".repeat(64))).unwrap();
        assert_eq!(reopened.list().len(), 1);
    }

    /// F10: assign and remove on the same library and vault from two threads finish (no lock cycle).
    #[test]
    fn assign_and_remove_do_not_deadlock() {
        use std::sync::Arc;
        let dir = tempfile::tempdir().unwrap();
        let lib = Arc::new(crate::Library::open(dir.path().join("library.json").display().to_string()).unwrap());
        let host = lib.add_connection(None, "web".into(), "ssh".into(), "web.example".into(), None, None).unwrap();
        let v = Arc::new(CredentialVault::open_with_key(dir.path().join("c.vault").display().to_string(), Secret::new("k".repeat(64))).unwrap());
        let cred = v.save_password(None, "c".into(), None, "u".into(), "p".into()).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        for t in 0..2 {
            let (lib, v, host, cred, tx) = (lib.clone(), v.clone(), host.clone(), cred.clone(), tx.clone());
            std::thread::spawn(move || {
                for _ in 0..2000 {
                    if t == 0 { let _ = v.assign_credential(lib.clone(), host.clone(), Some(cred.clone())); }
                    else { let _ = v.remove_checked(lib.clone(), cred.clone(), false); }
                }
                tx.send(()).unwrap();
            });
        }
        for _ in 0..2 { rx.recv_timeout(std::time::Duration::from_secs(30)).expect("assign/remove deadlocked"); }
    }

    /// Windows: `open` keeps the vault key as a DPAPI blob beside the vault, reads the same key
    /// back on the next open, and gives a second vault in the same folder its own key.
    #[cfg(windows)]
    #[test]
    fn vault_key_is_a_dpapi_blob_beside_the_vault() {
        let dir = std::env::temp_dir().join(format!("bastion-cred-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.vault").to_string_lossy().into_owned();
        let v = CredentialVault::open(path.clone()).unwrap();
        v.save_password(None, "db".into(), None, "root".into(), "s3cret".into()).unwrap();
        v.save().unwrap();
        drop(v);

        let blobs: Vec<_> = std::fs::read_dir(dir.join("vault-key")).unwrap().map(|e| e.unwrap().path()).collect();
        assert_eq!(blobs.len(), 1);
        let blob = std::fs::read(&blobs[0]).unwrap();
        // DPAPI blobs start with the version (1) and the DPAPI provider GUID df9d8cd0-1501-11d1-8c7a-00c04fc297eb.
        assert!(blob.starts_with(&[0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf]));

        let reopened = CredentialVault::open(path).unwrap();
        assert_eq!(reopened.list().len(), 1);
        CredentialVault::open(dir.join("other.vault").to_string_lossy().into_owned()).unwrap();
        assert_eq!(std::fs::read_dir(dir.join("vault-key")).unwrap().count(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    /// A key from the old Native Windows layout (`credentials.keys\`, full-path item) opens the
    /// vault after the move to `vault-key\`, and the old blob is gone afterwards.
    #[cfg(windows)]
    #[test]
    fn old_windows_key_layout_is_migrated() {
        use bastion_core::provider::{vault_key, DpapiProvider};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.vault");
        let id = path.to_string_lossy().into_owned();
        let old_key = vault_key(&DpapiProvider::new(dir.path().join("credentials.keys")), &id).unwrap();
        let migrated = os_key(&id).unwrap();
        assert_eq!(migrated.expose(), old_key.expose(), "the same key, so the existing vault still opens");
        assert_eq!(std::fs::read_dir(dir.path().join("credentials.keys")).unwrap().count(), 0, "old blob removed");
        assert_eq!(os_key(&id).unwrap().expose(), old_key.expose(), "stable on the next open");
    }

    #[test]
    fn an_unsupported_credential_is_listed_kept_and_deletable_but_not_editable() {
        let dir = std::env::temp_dir().join(format!("bastion-cred-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("credentials.vault").to_string_lossy().into_owned();
        let key = || Secret::new("k".repeat(64));
        let id = Uuid::new_v4();
        let newer = serde_json::json!([{"id": id, "name": "cluster cert", "kind": {"ClientCertificate": {"certificate": "C", "private_key": "K"}}}]);
        let v = CredentialVault::open_with_key(path.clone(), key()).unwrap();
        *v.lock() = Vault::from_plain(&serde_json::to_vec(&newer).unwrap()).unwrap();
        let list = v.list();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].kind.as_str(), list[0].username.as_str()), ("unsupported", bastion_core::vault_unknown::UNSUPPORTED_CREDENTIAL));
        assert!(v.save_password(Some(id.to_string()), "x".into(), None, "u".into(), "p".into()).is_err());
        v.save().unwrap();
        let reopened = CredentialVault::open_with_key(path.clone(), key()).unwrap();
        assert_eq!(reopened.list()[0].kind, "unsupported");
        reopened.remove(id.to_string()).unwrap();
        assert!(reopened.list().is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }
}
