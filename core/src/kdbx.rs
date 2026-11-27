//! KeePass `.kdbx` files as a read-only, offline credential provider.
//!
//! `unlock` keeps the composite key (master password and/or key-file bytes) in zeroizing
//! memory; every `fetch` re-opens and decrypts the file, takes one field and drops the
//! database, so no decrypted entries are cached and edits made in KeePass are seen at once.
//! Item format: `<entry uuid>` (password) or `<entry uuid>#<field>` where field is
//! `username`, `url`, `password` or any custom string field. Bastion never writes the file.
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use keepass::db::fields;
use keepass::{Database, DatabaseKey};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};
use crate::kdbx_limits;
use crate::provider::{CredentialProvider, ProviderStatus};
use crate::vault::Secret;

/// Refuse absurd key files instead of reading them whole.
const MAX_KEYFILE: u64 = 1024 * 1024;

struct Key {
    password: Option<Secret>,
    keyfile: Option<Zeroizing<Vec<u8>>>,
}

impl Key {
    fn new(password: Option<Secret>, keyfile: Option<&Path>) -> Result<Key> {
        if password.is_none() && keyfile.is_none() {
            return Err(CoreError::Invalid("KeePass needs a master password or a key file".into()));
        }
        Ok(Key { password, keyfile: keyfile.map(read_keyfile).transpose()? })
    }

    fn database_key(&self) -> Result<DatabaseKey> {
        let mut k = DatabaseKey::new();
        if let Some(p) = &self.password {
            k = k.with_password(p.expose());
        }
        if let Some(f) = &self.keyfile {
            k = k.with_keyfile(&mut f.as_slice()).map_err(CoreError::Io)?;
        }
        Ok(k)
    }
}

/// Non-secret listing for the UI.
#[derive(Debug, Clone, PartialEq)]
pub struct KeePassEntryInfo {
    pub id: String,
    pub title: String,
    pub username: Option<String>,
    /// Group names from the root down, root excluded.
    pub group: Vec<String>,
}

pub struct KeePassProvider {
    path: PathBuf,
    key: Mutex<Option<Key>>,
}

impl KeePassProvider {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        KeePassProvider { path: path.into(), key: Mutex::new(None) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check the key against the file, then keep it in memory. Wrong key → `AuthFailed`.
    pub fn unlock(&self, password: Option<Secret>, keyfile: Option<&Path>) -> Result<()> {
        let key = Key::new(password, keyfile)?;
        open(&self.path, &key)?;
        *self.key.lock().unwrap_or_else(|e| e.into_inner()) = Some(key);
        Ok(())
    }

    pub fn lock(&self) {
        *self.key.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    fn with_db<T>(&self, f: impl FnOnce(&Database) -> Result<T>) -> Result<T> {
        let g = self.key.lock().unwrap_or_else(|e| e.into_inner());
        let key = g.as_ref().ok_or(CoreError::VaultAuth)?;
        f(&open(&self.path, key)?)
    }

    /// Titles, usernames and groups of every entry outside the recycle bin, sorted by title.
    pub fn list(&self) -> Result<Vec<KeePassEntryInfo>> {
        self.with_db(|db| Ok(entries(db).into_iter().map(|(i, _)| i).collect()))
    }
}

/// Open `path` once with this key and visit every entry outside the recycle bin: title,
/// username, groups and the password, borrowed only for the call. The one-time import uses it, so the file is decrypted (and its key derived) once.
pub(crate) fn read_entries<T>(path: &Path, password: Option<Secret>, keyfile: Option<&Path>, f: impl FnMut(&str, &str, &[String], Option<&str>) -> T) -> Result<Vec<T>> {
    let key = Key::new(password, keyfile)?;
    Ok(visit(&open(path, &key)?, f))
}

fn visit<T>(db: &Database, mut f: impl FnMut(&str, &str, &[String], Option<&str>) -> T) -> Vec<T> {
    entries(db).into_iter().map(|(i, e)| f(&i.title, i.username.as_deref().unwrap_or(""), &i.group, e.get(fields::PASSWORD))).collect()
}

/// Every entry outside the recycle bin with its non-secret info, sorted by title.
fn entries(db: &Database) -> Vec<(KeePassEntryInfo, keepass::db::EntryRef<'_>)> {
    let bin = db.meta.recyclebin_uuid;
    let mut out: Vec<_> = db
        .iter_all_entries()
        .filter_map(|e| {
            let mut group = Vec::new();
            let mut g = Some(e.parent().id());
            while let Some(cur) = g.and_then(|id| db.group(id)) {
                if Some(cur.id().uuid()) == bin {
                    return None;
                }
                g = cur.parent().map(|p| p.id());
                if g.is_some() {
                    group.push(cur.name.clone());
                }
            }
            group.reverse();
            let info = KeePassEntryInfo {
                id: e.id().uuid().to_string(),
                title: e.get_title().unwrap_or_default().to_string(),
                username: e.get_username().filter(|u| !u.is_empty()).map(String::from),
                group,
            };
            Some((info, e))
        })
        .collect();
    out.sort_by_key(|(i, _)| i.title.to_lowercase());
    out
}

fn read_keyfile(p: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let len = std::fs::metadata(p).map_err(CoreError::Io)?.len();
    if len > MAX_KEYFILE {
        return Err(CoreError::Invalid("KeePass key file is larger than 1 MiB".into()));
    }
    Ok(Zeroizing::new(std::fs::read(p).map_err(CoreError::Io)?))
}

/// Read the whole file, at most [`kdbx_limits::MAX_FILE_BYTES`].
fn read_capped(path: &Path) -> Result<Vec<u8>> {
    let f = File::open(path).map_err(CoreError::Io)?;
    let mut bytes = Vec::new();
    f.take(kdbx_limits::MAX_FILE_BYTES + 1).read_to_end(&mut bytes).map_err(CoreError::Io)?;
    if bytes.len() as u64 > kdbx_limits::MAX_FILE_BYTES {
        return Err(CoreError::Invalid("KeePass file is larger than 256 MiB".into()));
    }
    Ok(bytes)
}

/// Size and key-derivation limits are checked before the key is derived (SEC-2).
fn open(path: &Path, key: &Key) -> Result<Database> {
    let bytes = read_capped(path)?;
    kdbx_limits::check_header(&bytes)?;
    Database::open(&mut bytes.as_slice(), key.database_key()?).map_err(|e| match e {
        keepass::db::DatabaseOpenError::Key(_) => CoreError::AuthFailed,
        keepass::db::DatabaseOpenError::Io(e) => CoreError::Io(e),
        other => CoreError::Corrupt(format!("KeePass file: {other}")),
    })
}

/// Splits `<uuid>[#field]` and maps the friendly field names to KeePass's.
fn parse_item(item: &str) -> Result<(Uuid, String)> {
    let (id, field) = item.split_once('#').unwrap_or((item, "password"));
    let id = Uuid::parse_str(id.trim()).map_err(|_| CoreError::Invalid(format!("not a KeePass entry id: {id}")))?;
    let field = match field.to_lowercase().as_str() {
        "password" => fields::PASSWORD.to_string(),
        "username" => fields::USERNAME.to_string(),
        "url" => fields::URL.to_string(),
        "title" => fields::TITLE.to_string(),
        _ => field.to_string(),
    };
    Ok((id, field))
}

impl CredentialProvider for KeePassProvider {
    fn id(&self) -> &'static str {
        "keepass"
    }

    fn status(&self) -> ProviderStatus {
        if !self.path.is_file() {
            return ProviderStatus::Unavailable(format!("{} not found", self.path.display()));
        }
        match *self.key.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(_) => ProviderStatus::Available,
            None => ProviderStatus::Locked,
        }
    }

    fn fetch(&self, item: &str) -> Result<Secret> {
        let (id, field) = parse_item(item)?;
        self.with_db(|db| {
            let entry = db.iter_all_entries().find(|e| e.id().uuid() == id).ok_or_else(|| CoreError::NotFound(item.into()))?;
            entry.get(&field).filter(|v| !v.is_empty()).map(Secret::new).ok_or_else(|| CoreError::NotFound(item.into()))
        })
    }

    fn store(&self, _: &str, _: &Secret) -> Result<()> {
        Err(read_only())
    }

    fn delete(&self, _: &str) -> Result<()> {
        Err(read_only())
    }
}

fn read_only() -> CoreError {
    CoreError::PolicyDenied("KeePass files are read-only in Gantry".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes a small KDBX4 file: one entry in "Servers/Lab", returns (path, entry id).
    fn fixture(dir: &Path, password: &str) -> (PathBuf, String) {
        let mut db = Database::new();
        let id;
        {
            let mut root = db.root_mut();
            let mut servers = root.add_group();
            servers.name = "Servers".into();
            let mut lab = servers.add_group();
            lab.name = "Lab".into();
            let mut e = lab.add_entry();
            e.set_unprotected(fields::TITLE, "lab sshd");
            e.set_unprotected(fields::USERNAME, "root");
            e.set_protected(fields::PASSWORD, "kp-s3cret");
            e.set_protected("Enable", "en-pass");
            id = e.id().uuid().to_string();
        }
        let path = dir.join("test.kdbx");
        db.save(&mut File::create(&path).unwrap(), DatabaseKey::new().with_password(password)).unwrap();
        (path, id)
    }

    #[test]
    fn reads_fields_on_demand_and_locks() {
        let d = tempfile::tempdir().unwrap();
        let (path, id) = fixture(d.path(), "master");
        let p = KeePassProvider::new(&path);
        assert_eq!(p.status(), ProviderStatus::Locked);
        assert!(matches!(p.fetch(&id), Err(CoreError::VaultAuth)));
        assert!(matches!(p.unlock(Some(Secret::new("wrong")), None), Err(CoreError::AuthFailed)));
        p.unlock(Some(Secret::new("master")), None).unwrap();
        assert_eq!(p.status(), ProviderStatus::Available);
        assert_eq!(p.fetch(&id).unwrap().expose(), "kp-s3cret");
        assert_eq!(p.fetch(&format!("{id}#username")).unwrap().expose(), "root");
        assert_eq!(p.fetch(&format!("{id}#Enable")).unwrap().expose(), "en-pass");
        assert!(matches!(p.fetch(&format!("{id}#url")), Err(CoreError::NotFound(_))));
        assert!(matches!(p.fetch(&Uuid::new_v4().to_string()), Err(CoreError::NotFound(_))));
        assert!(matches!(p.fetch("nope"), Err(CoreError::Invalid(_))));
        let list = p.list().unwrap();
        assert_eq!(list, vec![KeePassEntryInfo { id: id.clone(), title: "lab sshd".into(), username: Some("root".into()), group: vec!["Servers".into(), "Lab".into()] }]);
        p.lock();
        assert!(matches!(p.fetch(&id), Err(CoreError::VaultAuth)));
    }

    #[test]
    fn huge_argon2_memory_is_refused_before_derivation() {
        let d = tempfile::tempdir().unwrap();
        let (path, _) = fixture(d.path(), "master");
        let mut bytes = std::fs::read(&path).unwrap();
        // The variant-dictionary entry `M` (UInt64): type, key length 1, "M", value length 8.
        let tag = [0x05, 1, 0, 0, 0, b'M', 8, 0, 0, 0];
        let at = bytes.windows(tag.len()).position(|w| w == tag).expect("Argon2 memory field") + tag.len();
        bytes[at..at + 8].copy_from_slice(&(64u64 << 30).to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        let started = std::time::Instant::now();
        let p = KeePassProvider::new(&path);
        assert!(matches!(p.unlock(Some(Secret::new("master")), None), Err(CoreError::Invalid(_))));
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "refused without deriving the key");
    }

    #[test]
    fn an_oversized_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("big.kdbx");
        File::create(&path).unwrap().set_len(kdbx_limits::MAX_FILE_BYTES + 1).unwrap();
        let p = KeePassProvider::new(&path);
        assert!(matches!(p.unlock(Some(Secret::new("x")), None), Err(CoreError::Invalid(_))));
    }

    #[test]
    fn read_entries_opens_once_and_returns_every_entry() {
        let d = tempfile::tempdir().unwrap();
        let (path, _) = fixture(d.path(), "master");
        let got = read_entries(&path, Some(Secret::new("master")), None, |t, u, g, pw| (t.to_string(), u.to_string(), g.to_vec(), pw.map(String::from))).unwrap();
        assert_eq!(got, vec![("lab sshd".into(), "root".into(), vec!["Servers".into(), "Lab".into()], Some("kp-s3cret".into()))]);
        assert!(matches!(read_entries(&path, Some(Secret::new("bad")), None, |_, _, _, _| ()), Err(CoreError::AuthFailed)));
    }

    #[test]
    fn read_only_and_missing_file() {
        let d = tempfile::tempdir().unwrap();
        let p = KeePassProvider::new(d.path().join("none.kdbx"));
        assert!(matches!(p.status(), ProviderStatus::Unavailable(_)));
        assert!(p.unlock(None, None).is_err());
        assert!(matches!(p.store("x", &Secret::new("y")), Err(CoreError::PolicyDenied(_))));
        assert!(matches!(p.delete("x"), Err(CoreError::PolicyDenied(_))));
    }
}
