//! The compiled-code store on disk (spec section 4, "Where code is compiled"; T18.22).
//!
//! Layout, under the app's data folder, with the vault's file protections (folder `0700`, files
//! `0600`, or the single-user DACL on Windows):
//!
//! ```text
//! plugin-code/index.json      key name -> SHA-256 of the code, recorded at compile time
//! plugin-code/<key name>.code compiled code exactly as the compile helper returned it
//! ```
//!
//! The key name is the SHA-256 of the whole [`CacheKey`], so code made for another engine,
//! operating system, CPU type or settings never shares a file. Every load re-hashes the file and
//! compares it with the index; on a mismatch the file and its index line are deleted and the
//! caller writes `plugin.cache.mismatch` and compiles again. No MAC: no helper can reach this
//! folder (spec section 4), so the core's index is enough.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::plugin::broker::cache::{max_compiled_bytes, CacheKey};
use crate::plugin::broker::Failure;

const INDEX_FILE: &str = "index.json";
const SCHEMA: u32 = 1;
/// A stored file is never read past this, whatever the index says.
const MAX_STORED_BYTES: u64 = crate::plugin::broker::cache::COMPILE_OUTPUT_MAX_BYTES;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexFile {
    schema: u32,
    /// Key name -> entry.
    entries: BTreeMap<String, IndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IndexEntry {
    component_sha256: String,
    code_sha256: String,
    size: u64,
}

/// What a load found.
#[derive(Debug, PartialEq, Eq)]
pub enum Stored {
    /// The code, checked against the recorded hash.
    Valid(Vec<u8>),
    /// Nothing stored for this key: compile.
    Missing,
    /// The file differed from the recorded hash. It is deleted; audit `plugin.cache.mismatch`
    /// and compile again.
    Mismatch,
}

/// The compiled-code store of one app data folder.
#[derive(Debug, Clone)]
pub struct CodeStore {
    dir: PathBuf,
}

fn io(e: impl std::fmt::Display) -> Failure {
    Failure::Invalid(format!("Plugin could not be prepared: {e}"))
}

/// The file name of a key: SHA-256 over every field, each with its length, so no two keys
/// collide by moving bytes between fields.
pub fn key_name(key: &CacheKey) -> String {
    let mut h = Sha256::new();
    for part in [&key.component_sha256, &key.wasmtime_version, &key.os, &key.target, &key.settings_hash] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(h.finalize())
}

impl CodeStore {
    /// The store under `data_dir` (`<data_dir>/plugin-code`). Nothing is created until a save.
    pub fn new(data_dir: &Path) -> CodeStore {
        CodeStore { dir: data_dir.join("plugin-code") }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join(INDEX_FILE)
    }

    fn code_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.code"))
    }

    /// The index, or an empty one when there is none. A damaged index is treated as empty:
    /// every key then reads as `Missing` and is compiled again (fail closed: nothing unverified
    /// is loaded).
    fn read_index(&self) -> IndexFile {
        let Ok(bytes) = fs::read(self.index_path()) else { return IndexFile { schema: SCHEMA, ..IndexFile::default() } };
        match serde_json::from_slice::<IndexFile>(&bytes) {
            Ok(index) if index.schema == SCHEMA => index,
            _ => IndexFile { schema: SCHEMA, ..IndexFile::default() },
        }
    }

    fn write_index(&self, index: &IndexFile) -> Result<(), Failure> {
        let bytes = serde_json::to_vec(index).map_err(io)?;
        crate::store::write_atomic(&self.index_path(), &bytes).map_err(io)
    }

    fn locked<T>(&self, f: impl FnOnce() -> Result<T, Failure>) -> Result<T, Failure> {
        crate::store::create_private_dir(&self.dir).map_err(io)?;
        let mut out = None;
        crate::store::with_save_lock(&self.index_path(), || {
            out = Some(f());
            Ok(())
        })
        .map_err(io)?;
        out.unwrap_or_else(|| Err(io("the store lock was not taken")))
    }

    /// Stores what a compile helper returned for `key`, after the output cap. The SHA-256 is
    /// recorded here, at compile time.
    pub fn save(&self, key: &CacheKey, component_bytes: u64, compiled: &[u8]) -> Result<(), Failure> {
        if compiled.len() as u64 > max_compiled_bytes(component_bytes) {
            return Err(Failure::Invalid("Plugin could not be prepared".into()));
        }
        let name = key_name(key);
        self.locked(|| {
            crate::store::write_atomic(&self.code_path(&name), compiled).map_err(io)?;
            let mut index = self.read_index();
            index.entries.insert(
                name.clone(),
                IndexEntry { component_sha256: key.component_sha256.clone(), code_sha256: hex::encode(Sha256::digest(compiled)), size: compiled.len() as u64 },
            );
            self.write_index(&index)
        })
    }

    /// Loads and checks the code for `key`. Checked before every load, never cached in memory.
    pub fn load(&self, key: &CacheKey) -> Result<Stored, Failure> {
        let name = key_name(key);
        let index = self.read_index();
        let Some(entry) = index.entries.get(&name).cloned() else { return Ok(Stored::Missing) };
        let path = self.code_path(&name);
        let bytes = match read_capped(&path, MAX_STORED_BYTES) {
            Ok(Some(bytes)) => bytes,
            // Gone or over the cap: either way it is not the recorded code.
            Ok(None) | Err(_) => return self.drop_entry(&name).map(|_| Stored::Mismatch),
        };
        let matches = entry.component_sha256 == key.component_sha256 && entry.size == bytes.len() as u64 && hex::encode(Sha256::digest(&bytes)) == entry.code_sha256;
        if matches {
            Ok(Stored::Valid(bytes))
        } else {
            self.drop_entry(&name).map(|_| Stored::Mismatch)
        }
    }

    fn drop_entry(&self, name: &str) -> Result<(), Failure> {
        self.locked(|| {
            let _ = fs::remove_file(self.code_path(name));
            let mut index = self.read_index();
            index.entries.remove(name);
            self.write_index(&index)
        })
    }

    /// Deletes every stored code of a component (plugin removed or updated).
    pub fn forget_component(&self, component_sha256: &str) -> Result<(), Failure> {
        if !self.index_path().exists() {
            return Ok(());
        }
        self.locked(|| {
            let mut index = self.read_index();
            let gone: Vec<String> = index.entries.iter().filter(|(_, e)| e.component_sha256 == component_sha256).map(|(n, _)| n.clone()).collect();
            for name in &gone {
                let _ = fs::remove_file(self.code_path(name));
                index.entries.remove(name);
            }
            self.write_index(&index)
        })
    }
}

/// Reads at most `cap` bytes; `None` when the file is larger.
fn read_capped(path: &Path, cap: u64) -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= cap).then_some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(component: &str) -> CacheKey {
        CacheKey { component_sha256: component.into(), wasmtime_version: "48.0.8".into(), os: "macos".into(), target: "aarch64".into(), settings_hash: "s".into() }
    }

    fn temp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn saved_code_loads_back_after_the_hash_check() {
        let dir = temp();
        let store = CodeStore::new(dir.path());
        assert_eq!(store.load(&key("a")).unwrap(), Stored::Missing);
        store.save(&key("a"), 100, b"compiled").unwrap();
        assert_eq!(store.load(&key("a")).unwrap(), Stored::Valid(b"compiled".to_vec()));
        // A new store over the same folder (an app restart) finds it too.
        assert_eq!(CodeStore::new(dir.path()).load(&key("a")).unwrap(), Stored::Valid(b"compiled".to_vec()));
    }

    #[test]
    fn a_tampered_file_is_a_mismatch_and_is_deleted() {
        let dir = temp();
        let store = CodeStore::new(dir.path());
        store.save(&key("a"), 100, b"compiled").unwrap();
        let path = store.code_path(&key_name(&key("a")));
        fs::write(&path, b"COMPILED").unwrap();
        assert_eq!(store.load(&key("a")).unwrap(), Stored::Mismatch);
        assert!(!path.exists(), "the entry is deleted");
        assert_eq!(store.load(&key("a")).unwrap(), Stored::Missing, "and compiled again next time");
    }

    #[test]
    fn a_missing_file_is_a_mismatch() {
        let dir = temp();
        let store = CodeStore::new(dir.path());
        store.save(&key("a"), 100, b"x").unwrap();
        fs::remove_file(store.code_path(&key_name(&key("a")))).unwrap();
        assert_eq!(store.load(&key("a")).unwrap(), Stored::Mismatch);
    }

    #[test]
    fn code_for_another_engine_never_shares_a_file() {
        let a = key("a");
        let other_engine = CacheKey { wasmtime_version: "48.0.9".into(), ..key("a") };
        let other_target = CacheKey { target: "pulley64".into(), ..key("a") };
        assert_ne!(key_name(&a), key_name(&other_engine));
        assert_ne!(key_name(&a), key_name(&other_target));
        // Moving bytes between fields gives another name.
        let shifted = CacheKey { os: "macosa".into(), target: "arch64".into(), ..key("a") };
        assert_ne!(key_name(&a), key_name(&shifted));
    }

    #[test]
    fn code_over_the_output_cap_is_not_stored() {
        let dir = temp();
        let store = CodeStore::new(dir.path());
        let big = vec![0u8; 17];
        assert!(store.save(&key("a"), 1, &big).is_err(), "16 times the component at most");
        assert_eq!(store.load(&key("a")).unwrap(), Stored::Missing);
    }

    #[test]
    fn a_damaged_index_loads_nothing() {
        let dir = temp();
        let store = CodeStore::new(dir.path());
        store.save(&key("a"), 100, b"compiled").unwrap();
        fs::write(store.index_path(), b"{not json").unwrap();
        assert_eq!(store.load(&key("a")).unwrap(), Stored::Missing);
    }

    #[test]
    fn forgetting_a_component_deletes_all_its_code() {
        let dir = temp();
        let store = CodeStore::new(dir.path());
        store.save(&key("a"), 100, b"one").unwrap();
        store.save(&CacheKey { target: "pulley64".into(), ..key("a") }, 100, b"two").unwrap();
        store.save(&key("b"), 100, b"three").unwrap();
        store.forget_component("a").unwrap();
        assert_eq!(store.load(&key("a")).unwrap(), Stored::Missing);
        assert_eq!(store.load(&key("b")).unwrap(), Stored::Valid(b"three".to_vec()));
    }

    #[cfg(unix)]
    #[test]
    fn the_store_has_the_vaults_file_protections() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp();
        let store = CodeStore::new(dir.path());
        store.save(&key("a"), 100, b"compiled").unwrap();
        assert_eq!(fs::metadata(store.dir()).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(store.code_path(&key_name(&key("a")))).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(store.index_path()).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
