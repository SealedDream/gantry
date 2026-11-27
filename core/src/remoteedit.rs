//! Remote editor backend: open a remote file into memory with a fingerprint (size, mtime and
//! SHA-256), and save it back only if nobody changed it meanwhile. Saving writes a temporary
//! file, moves the original aside, renames the new one into place and only then deletes the
//! original, so a failure at any step leaves either the old or the new content on the server.
//! Permissions of the original are kept.
use sha2::{Digest, Sha256};

use crate::error::{CoreError, Result};

/// Largest file the editor opens.
pub const MAX_EDIT_BYTES: u64 = 32 * 1024 * 1024;

/// What the editor knows about the server copy it loaded or last saved.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Fingerprint {
    pub size: u64,
    /// Unix seconds, when the server reports it.
    pub mtime: Option<u32>,
    /// Empty when only the size was compared (the file changed size).
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteStat {
    pub size: u64,
    pub mtime: Option<u32>,
    pub permissions: Option<u32>,
    pub is_file: bool,
}

#[derive(Debug, Clone)]
pub struct OpenedFile {
    pub bytes: Vec<u8>,
    pub fingerprint: Fingerprint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveOutcome {
    Saved(Fingerprint),
    /// The server copy changed (or vanished, `None`) since it was opened; nothing was written.
    Conflict(Option<Fingerprint>),
}

/// The few remote operations the editor needs; `Sftp` implements it, tests use a fake.
#[allow(async_fn_in_trait)]
pub trait RemoteFiles {
    /// `None` when the path does not exist.
    async fn stat(&self, path: &str) -> Result<Option<RemoteStat>>;
    async fn read_all(&self, path: &str) -> Result<Vec<u8>>;
    /// Create `path` (must not exist) with `bytes` and, when given, `permissions`.
    async fn create_new(&self, path: &str, bytes: &[u8], permissions: Option<u32>) -> Result<()>;
    /// Rename; fails if `to` exists (SFTP v3).
    async fn rename(&self, from: &str, to: &str) -> Result<()>;
    async fn remove(&self, path: &str) -> Result<()>;
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn fingerprint(bytes: &[u8], mtime: Option<u32>) -> Fingerprint {
    Fingerprint { size: bytes.len() as u64, mtime, sha256: sha256_hex(bytes) }
}

fn size_only(st: &RemoteStat) -> Fingerprint {
    Fingerprint { size: st.size, mtime: st.mtime, sha256: String::new() }
}

fn side_name(path: &str, what: &str) -> String {
    format!("{path}.bastion-{what}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
}

fn too_large(path: &str) -> CoreError {
    CoreError::Invalid(format!("{path} is too large to edit (32 MB limit)"))
}

/// Load `path` for editing. Refuses folders, special files and files over 32 MB.
pub async fn open(fs: &impl RemoteFiles, path: &str) -> Result<OpenedFile> {
    let st = fs.stat(path).await?.ok_or_else(|| CoreError::NotFound(path.to_string()))?;
    if !st.is_file {
        return Err(CoreError::Invalid(format!("{path} is not a regular file")));
    }
    if st.size > MAX_EDIT_BYTES {
        return Err(too_large(path));
    }
    let bytes = fs.read_all(path).await?;
    if bytes.len() as u64 > MAX_EDIT_BYTES {
        return Err(too_large(path));
    }
    let fingerprint = fingerprint(&bytes, st.mtime);
    Ok(OpenedFile { bytes, fingerprint })
}

/// `None` when the server copy still matches `expected`, otherwise the conflict. The content is
/// re-hashed whenever the size matches, so a same-second, same-size edit is still caught.
pub async fn check(fs: &impl RemoteFiles, path: &str, expected: &Fingerprint) -> Result<Option<SaveOutcome>> {
    let Some(st) = fs.stat(path).await? else {
        return Ok(Some(SaveOutcome::Conflict(None)));
    };
    if st.size != expected.size || !st.is_file {
        return Ok(Some(SaveOutcome::Conflict(Some(size_only(&st)))));
    }
    let now = fingerprint(&fs.read_all(path).await?, st.mtime);
    Ok((now.sha256 != expected.sha256).then_some(SaveOutcome::Conflict(Some(now))))
}

/// Save `bytes` to `path`. Unless `force`, returns `Conflict` without writing when the server copy
/// no longer matches `expected`. With `expected` `None` the file must not exist yet (Save As).
pub async fn save(fs: &impl RemoteFiles, path: &str, expected: Option<&Fingerprint>, bytes: &[u8], force: bool) -> Result<SaveOutcome> {
    if bytes.len() as u64 > MAX_EDIT_BYTES {
        return Err(too_large(path));
    }
    let current = fs.stat(path).await?;
    if !force {
        match (expected, &current) {
            (Some(exp), _) => {
                if let Some(conflict) = check(fs, path, exp).await? {
                    return Ok(conflict);
                }
            }
            (None, Some(st)) => return Ok(SaveOutcome::Conflict(Some(size_only(st)))),
            (None, None) => {}
        }
    }
    if current.as_ref().is_some_and(|st| !st.is_file) {
        return Err(CoreError::Invalid(format!("{path} is not a regular file")));
    }
    let tmp = side_name(path, "save");
    fs.create_new(&tmp, bytes, current.as_ref().and_then(|s| s.permissions)).await?;
    if let Err(e) = replace(fs, &tmp, path, current.is_some()).await {
        let _ = fs.remove(&tmp).await;
        return Err(e);
    }
    let mtime = fs.stat(path).await?.and_then(|s| s.mtime);
    Ok(SaveOutcome::Saved(fingerprint(bytes, mtime)))
}

/// Put `tmp` in place of `path`, moving the original aside first and restoring it on failure.
async fn replace(fs: &impl RemoteFiles, tmp: &str, path: &str, exists: bool) -> Result<()> {
    if !exists {
        return fs.rename(tmp, path).await;
    }
    let old = side_name(path, "old");
    fs.rename(path, &old).await?;
    if let Err(e) = fs.rename(tmp, path).await {
        let _ = fs.rename(&old, path).await;
        return Err(e);
    }
    // The new content is in place; a leftover backup would be harmless, but tidy it up.
    let _ = fs.remove(&old).await;
    Ok(())
}

impl RemoteFiles for crate::sftp::Sftp {
    async fn stat(&self, path: &str) -> Result<Option<RemoteStat>> {
        self.stat_path(path).await
    }

    async fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        self.read_capped(path, MAX_EDIT_BYTES).await
    }

    async fn create_new(&self, path: &str, bytes: &[u8], permissions: Option<u32>) -> Result<()> {
        self.write_new(path, bytes, permissions).await
    }

    async fn rename(&self, from: &str, to: &str) -> Result<()> {
        crate::sftp::Sftp::rename(self, from, to).await
    }

    async fn remove(&self, path: &str) -> Result<()> {
        self.remove_file(path).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    /// In-memory server: path → (bytes, mtime, permissions); an optional rename target fails.
    #[derive(Default)]
    struct Fake {
        files: Mutex<BTreeMap<String, (Vec<u8>, u32, Option<u32>)>>,
        fail_rename_to: Option<String>,
    }

    impl Fake {
        fn put(&self, p: &str, b: &[u8], mtime: u32) {
            self.files.lock().unwrap().insert(p.into(), (b.to_vec(), mtime, Some(0o640)));
        }
        fn get(&self, p: &str) -> Option<Vec<u8>> {
            self.files.lock().unwrap().get(p).map(|f| f.0.clone())
        }
        fn names(&self) -> Vec<String> {
            self.files.lock().unwrap().keys().cloned().collect()
        }
    }

    impl RemoteFiles for Fake {
        async fn stat(&self, p: &str) -> Result<Option<RemoteStat>> {
            Ok(self.files.lock().unwrap().get(p).map(|f| RemoteStat { size: f.0.len() as u64, mtime: Some(f.1), permissions: f.2, is_file: true }))
        }
        async fn read_all(&self, p: &str) -> Result<Vec<u8>> {
            self.get(p).ok_or_else(|| CoreError::NotFound(p.into()))
        }
        async fn create_new(&self, p: &str, b: &[u8], perms: Option<u32>) -> Result<()> {
            let mut f = self.files.lock().unwrap();
            if f.contains_key(p) {
                return Err(CoreError::Invalid("exists".into()));
            }
            f.insert(p.into(), (b.to_vec(), 2000, perms));
            Ok(())
        }
        async fn rename(&self, from: &str, to: &str) -> Result<()> {
            if self.fail_rename_to.as_deref() == Some(to) {
                return Err(CoreError::Ssh("rename failed".into()));
            }
            let mut f = self.files.lock().unwrap();
            if f.contains_key(to) {
                return Err(CoreError::Invalid("target exists".into()));
            }
            let v = f.remove(from).ok_or_else(|| CoreError::NotFound(from.into()))?;
            f.insert(to.into(), v);
            Ok(())
        }
        async fn remove(&self, p: &str) -> Result<()> {
            self.files.lock().unwrap().remove(p).map(|_| ()).ok_or_else(|| CoreError::NotFound(p.into()))
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().build().unwrap()
    }

    #[test]
    fn open_then_save_keeps_permissions_and_leaves_no_temp_files() {
        rt().block_on(async {
            let fs = Fake::default();
            fs.put("/etc/app.conf", b"a=1\n", 1000);
            let opened = open(&fs, "/etc/app.conf").await.unwrap();
            assert_eq!(opened.fingerprint.sha256, sha256_hex(b"a=1\n"));
            let out = save(&fs, "/etc/app.conf", Some(&opened.fingerprint), b"a=2\n", false).await.unwrap();
            assert!(matches!(out, SaveOutcome::Saved(ref f) if f.sha256 == sha256_hex(b"a=2\n")));
            assert_eq!(fs.get("/etc/app.conf").unwrap(), b"a=2\n");
            assert_eq!(fs.names(), ["/etc/app.conf"]);
            assert_eq!(fs.files.lock().unwrap()["/etc/app.conf"].2, Some(0o640));
        });
    }

    #[test]
    fn same_size_change_is_a_conflict_and_force_overrides() {
        rt().block_on(async {
            let fs = Fake::default();
            fs.put("/f", b"aaaa", 1000);
            let opened = open(&fs, "/f").await.unwrap();
            fs.put("/f", b"bbbb", 1000); // same size, same second
            let out = save(&fs, "/f", Some(&opened.fingerprint), b"mine", false).await.unwrap();
            assert!(matches!(out, SaveOutcome::Conflict(Some(ref f)) if f.sha256 == sha256_hex(b"bbbb")));
            assert_eq!(fs.get("/f").unwrap(), b"bbbb", "nothing written on conflict");
            assert!(matches!(save(&fs, "/f", Some(&opened.fingerprint), b"mine", true).await.unwrap(), SaveOutcome::Saved(_)));
            assert_eq!(fs.get("/f").unwrap(), b"mine");
        });
    }

    #[test]
    fn deleted_or_resized_file_is_a_conflict() {
        rt().block_on(async {
            let fs = Fake::default();
            fs.put("/f", b"x", 1);
            let opened = open(&fs, "/f").await.unwrap();
            fs.put("/f", b"longer", 1);
            assert!(matches!(save(&fs, "/f", Some(&opened.fingerprint), b"y", false).await.unwrap(), SaveOutcome::Conflict(Some(_))));
            fs.remove("/f").await.unwrap();
            assert_eq!(save(&fs, "/f", Some(&opened.fingerprint), b"y", false).await.unwrap(), SaveOutcome::Conflict(None));
        });
    }

    #[test]
    fn save_as_refuses_existing_file() {
        rt().block_on(async {
            let fs = Fake::default();
            assert!(matches!(save(&fs, "/new", None, b"n", false).await.unwrap(), SaveOutcome::Saved(_)));
            assert!(matches!(save(&fs, "/new", None, b"m", false).await.unwrap(), SaveOutcome::Conflict(Some(_))));
            assert_eq!(fs.get("/new").unwrap(), b"n");
        });
    }

    #[test]
    fn failed_rename_never_loses_the_original() {
        rt().block_on(async {
            let fs = Fake { fail_rename_to: Some("/f".into()), ..Default::default() };
            fs.put("/f", b"orig", 1);
            let opened = open(&fs, "/f").await.unwrap();
            assert!(save(&fs, "/f", Some(&opened.fingerprint), b"new", false).await.is_err());
            // Every rename onto /f fails in this fake, so the original survives under its backup
            // name; the temp file is removed.
            let names = fs.names();
            assert!(names.iter().all(|n| !n.contains("bastion-save")), "{names:?}");
            assert!(names.iter().any(|n| fs.get(n).unwrap() == b"orig"), "original content kept: {names:?}");
        });
    }

    #[test]
    fn refuses_huge_files() {
        rt().block_on(async {
            let fs = Fake::default();
            fs.put("/big", &vec![0u8; MAX_EDIT_BYTES as usize + 1], 1);
            assert!(open(&fs, "/big").await.is_err());
            assert!(save(&fs, "/x", None, &vec![0u8; MAX_EDIT_BYTES as usize + 1], false).await.is_err());
        });
    }
}
