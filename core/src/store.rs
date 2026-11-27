//! Atomic, versioned document persistence with conflict and corruption detection.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{CoreError, Result};
use crate::model::{Document, SCHEMA_VERSION};

const MAX_BACKUPS: usize = 20;

/// A UTF-8 byte-order mark before the JSON, as Notepad and Windows PowerShell 5.1 write one, is
/// skipped: the file is still the user's library. Only a leading one; anything else is JSON's to judge.
pub(crate) fn skip_bom(bytes: &[u8]) -> &[u8] {
    bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes)
}

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Store { path: path.into() }
    }

    pub fn load(&self) -> Result<Document> {
        // No size limit here, as before PLUG-03a: the store has never refused a large
        // library, and it never writes one it would not open. Unknown data is capped while it
        // is read, so a large file costs no more than it always did.
        let bytes = fs::read(&self.path)?;
        let bytes = skip_bom(&bytes);
        let doc: Document = crate::unknown::reading(|| serde_json::from_slice(bytes)).map_err(|e| e.or_else(|e| CoreError::Corrupt(e.to_string())))?;
        if doc.schema > SCHEMA_VERSION {
            return Err(CoreError::Corrupt(format!("schema {} is newer than supported {}", doc.schema, SCHEMA_VERSION)));
        }
        // Connection types and fields this app does not know are kept (PLUG-03a), within caps.
        // Over the caps is a plain refusal, not "corrupt": no backup would read any better.
        // The reader enforces them as it reads; this is the same rule on the result.
        crate::unknown::check(&doc, &Default::default())?;
        Ok(doc)
    }

    /// Save `doc` if the on-disk revision still matches `doc.revision`.
    /// Returns the saved document with its revision incremented.
    /// The check, backup and replace run under [`with_save_lock`], so of several writers (threads
    /// or processes) saving from the same revision exactly one succeeds.
    pub fn save(&self, doc: &Document) -> Result<Document> {
        with_save_lock(&self.path, || self.save_locked(doc))
    }

    fn save_locked(&self, doc: &Document) -> Result<Document> {
        // Never write what `load` would refuse.
        crate::unknown::check(doc, &Default::default())?;
        let on_disk = if self.path.exists() {
            let on_disk = self.load()?;
            if on_disk.revision != doc.revision {
                return Err(CoreError::Conflict { expected: doc.revision, found: on_disk.revision });
            }
            Some(on_disk)
        } else {
            None
        };
        // Everything that can refuse this save comes before the backup: a refused save leaves
        // the file and its backups as they are.
        let next = Document { revision: doc.revision + 1, ..doc.clone() };
        let json = serde_json::to_vec_pretty(&next).map_err(|e| CoreError::Invalid(e.to_string()))?;
        if let Some(on_disk) = &on_disk {
            self.backup(on_disk)?;
        }
        write_atomic(&self.path, &json)?;
        Ok(next)
    }

    pub fn backups_dir(&self) -> PathBuf {
        self.path.with_extension("backups")
    }

    /// Backups, newest first.
    pub fn list_backups(&self) -> Result<Vec<PathBuf>> {
        let dir = self.backups_dir();
        if !dir.exists() {
            return Ok(vec![]);
        }
        let mut entries: Vec<PathBuf> = fs::read_dir(&dir)?.filter_map(|e| e.ok().map(|e| e.path())).collect();
        entries.sort();
        entries.reverse();
        Ok(entries)
    }

    /// Load the newest backup that parses — the recovery path for a corrupt document.
    pub fn recover_latest(&self) -> Result<Document> {
        self.list_backups()?
            .iter()
            .find_map(|p| Store::new(p).load().ok())
            .ok_or_else(|| CoreError::NotFound("no valid backup".into()))
    }

    fn backup(&self, doc: &Document) -> Result<()> {
        let dir = self.backups_dir();
        create_private_dir(&dir)?;
        let json = serde_json::to_vec_pretty(doc).map_err(|e| CoreError::Invalid(e.to_string()))?;
        write_atomic(&dir.join(format!("rev-{:012}.json", doc.revision)), &json)?;
        // Prune only the oldest snapshots beyond the retention limit.
        for stale in self.list_backups()?.into_iter().skip(MAX_BACKUPS) {
            fs::remove_file(stale)?;
        }
        Ok(())
    }
}

/// Create `dir` (and parents) and restrict it to the owner (0700 / owner-only DACL).
/// Runs `f` holding an exclusive lock on `<path>.lock`, a sidecar that is never renamed or
/// removed (unlike `path` itself, which atomic saves replace). OS file locks exclude other
/// handles in this process as well as other processes, so a read-check-write transaction inside
/// `f` cannot interleave with another one. Blocks until the lock is free.
pub fn with_save_lock<T>(path: &Path, f: impl FnOnce() -> Result<T>) -> Result<T> {
    let mut name = path.file_name().ok_or_else(|| CoreError::Invalid(format!("{} has no file name", path.display())))?.to_os_string();
    name.push(".lock");
    let lock_path = path.with_file_name(name);
    if let Some(dir) = lock_path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)?;
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let lock = opts.open(&lock_path)?;
    lock.lock()?;
    let out = f();
    // Closing the handle also releases it; unlocking first just makes that explicit.
    let _ = lock.unlock();
    out
}

pub fn create_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    crate::winacl::restrict_path(dir, true)?;
    Ok(())
}

/// Write via temp file + fsync + rename so readers never see a partial file.
///
/// The temp file is `<file name>.<32 hex>.tmp` — the whole destination name, so `shared.json`
/// and `shared.bastion` never share a namespace — and this writer holds an exclusive advisory
/// lock on it (and keeps it open) from creation until after the rename. Stale-temp cleanup only
/// removes files no writer owns, so a live, even long-paused, writer's file is never unlinked
/// (audit DS-03).
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = temp_path(path);
    // Unpredictable name + create_new: never follows or clobbers a pre-planted file/symlink.
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f: File = opts.open(&tmp)?;
    let written = (|| -> Result<()> {
        f.lock()?;
        // Owner-only before any secret bytes are written; never leave a readable temp file behind.
        #[cfg(windows)]
        crate::winacl::restrict_path(&tmp, false)?;
        kill_mid_write_for_tests(path, &mut f, bytes)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        // Renamed while still open and locked: ownership is held until the name is gone.
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    drop(f);
    written?;
    remove_stale_temps(path);
    Ok(())
}

fn temp_path(path: &Path) -> std::path::PathBuf {
    let name = path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
    let mut tmp = name;
    tmp.push(format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    path.with_file_name(tmp)
}

/// How old an unlocked temp file must be before cleanup removes it. The lock is what protects
/// live writers; the age only spares a writer in the instant between `create_new` and `lock`.
const STALE_TEMP_AGE: std::time::Duration = std::time::Duration::from_secs(60);

/// Whether `name` is a temp file of the destination `file_name`: `<file_name>.<32 hex>.tmp`, or
/// the pre-DS-03 `<stem>.<32 hex>.tmp` a crashed older build may have left behind.
fn is_temp_of(name: &str, file_name: &str, stem: &str) -> bool {
    let hex = |r: &str| r.strip_suffix(".tmp").is_some_and(|m| m.len() == 32 && m.bytes().all(|b| b.is_ascii_hexdigit()));
    [file_name, stem].iter().any(|p| name.strip_prefix(p).and_then(|r| r.strip_prefix('.')).is_some_and(hex))
}

/// Temp files of `path` that an earlier, interrupted write (crash, power loss) left behind. Only
/// a file no writer holds locked, and older than [`STALE_TEMP_AGE`], is removed.
fn remove_stale_temps(path: &Path) {
    let (Some(dir), Some(file_name), Some(stem)) =
        (path.parent(), path.file_name().and_then(|s| s.to_str()), path.file_stem().and_then(|s| s.to_str()))
    else {
        return;
    };
    let dir = if dir.as_os_str().is_empty() { Path::new(".") } else { dir };
    let Ok(entries) = fs::read_dir(dir) else { return };
    let cutoff = std::time::SystemTime::now() - STALE_TEMP_AGE;
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if !is_temp_of(name, file_name, stem) {
            continue;
        }
        // Never follow a planted symlink; only plain files are ours.
        let Ok(meta) = fs::symlink_metadata(e.path()) else { continue };
        if !meta.is_file() || !meta.modified().is_ok_and(|t| t < cutoff) {
            continue;
        }
        remove_if_unowned(&e.path());
    }
}

/// Unix: a writer holds an exclusive `flock` on its temp file, so a lock we can take means no
/// live writer owns it.
#[cfg(unix)]
fn remove_if_unowned(p: &Path) {
    let Ok(candidate) = OpenOptions::new().write(true).open(p) else { return };
    if candidate.try_lock().is_ok() {
        let _ = fs::remove_file(p);
    }
}

/// Windows: a writer keeps its temp file open until the rename, so an open that shares nothing
/// succeeds only when no live writer has it; delete-on-close then removes it atomically.
#[cfg(windows)]
fn remove_if_unowned(p: &Path) {
    use std::os::windows::fs::OpenOptionsExt;
    const DELETE: u32 = 0x0001_0000;
    const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
    let _ = OpenOptions::new().access_mode(DELETE).share_mode(0).custom_flags(FILE_FLAG_DELETE_ON_CLOSE).open(p);
}

/// UI-driver crash test (`BASTION_TEST_KILL_DURING_WRITE=<file name>`): write half the bytes to
/// the temp file, then end the process before the rename, as a crash would. Compiled only with
/// the `test-hooks` feature (never in release bundles); `_exit` so no crash report is filed.
#[cfg(feature = "test-hooks")]
fn kill_mid_write_for_tests(path: &Path, f: &mut File, bytes: &[u8]) -> Result<()> {
    let Ok(target) = std::env::var("BASTION_TEST_KILL_DURING_WRITE") else { return Ok(()) };
    if path.file_name().and_then(|n| n.to_str()) != Some(target.as_str()) {
        return Ok(());
    }
    f.write_all(&bytes[..bytes.len() / 2])?;
    f.sync_all()?;
    eprintln!("bastion: test hook: ending the process mid-write of {}", path.display());
    std::process::exit(86);
}

/// Without `test-hooks` the variable means nothing.
#[cfg(not(feature = "test-hooks"))]
fn kill_mid_write_for_tests(_: &Path, _: &mut File, _: &[u8]) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod bom_tests {
    use super::*;

    #[test]
    fn load_skips_a_leading_utf8_bom() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("library.json");
        let store = Store::new(&path);
        let saved = store.save(&Document::new("Lib")).unwrap();
        let mut bytes = b"\xEF\xBB\xBF".to_vec();
        bytes.extend(fs::read(&path).unwrap());
        fs::write(&path, &bytes).unwrap();
        assert_eq!(store.load().unwrap().revision, saved.revision);
        // Saving over it works and writes no BOM.
        store.save(&saved).unwrap();
        assert!(!fs::read(&path).unwrap().starts_with(b"\xEF\xBB\xBF"));
    }

    #[test]
    fn skip_bom_only_strips_one_leading_mark() {
        assert_eq!(skip_bom(b"\xEF\xBB\xBF{}"), b"{}");
        assert_eq!(skip_bom(b"{}"), b"{}");
        assert_eq!(skip_bom(b" \xEF\xBB\xBF{}"), b" \xEF\xBB\xBF{}");
    }
}
