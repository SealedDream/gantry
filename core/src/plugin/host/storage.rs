//! A plugin's storage and log file (spec section 5, `storage` row and "Log lines"; T18.15,
//! T18.16, T18.21, T18.24).
//!
//! Layout, inside the plugin's own data folder (`plugin-data/<id>/`, `PluginFolders::data_dir_of`),
//! with the vault's file protections (folders `0700`, files `0600`, or the single-user DACL on
//! Windows). Never in a document, a backup or an export:
//!
//! ```text
//! storage/<part>.json   one entry's key-value store; <part> = SHA-256 of document id and entry id
//! log/plugin.log        the plugin's log ("<unix seconds> <level> <text>" per line), with log/plugin.log.1 before it; 1 MiB for both
//! ```
//!
//! - A helper reaches only its own entry's part: the part is chosen by the core from the
//!   helper's binding, never from anything the helper says.
//! - Every write passes the secret check against the passwords released to that helper first.
//!   A log line that passes it is dropped whole.
//! - 2 MiB per value (`MAX_STORAGE_VALUE_BYTES`), 50 MiB per plugin, over all its parts.
//! - Entries in protected documents get storage that lasts only as long as the view (in memory).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;

use base64::Engine as _;
use sha2::{Digest, Sha256};

use crate::plugin::broker::secret::{log_line_kept, SecretCheck};
use crate::plugin::broker::Failure;

/// Storage per plugin, over every entry's part (spec section 5).
pub const MAX_STORAGE_BYTES_PER_PLUGIN: u64 = 50 * 1024 * 1024;
/// One value is at most this long (2 MiB). Shared with the helper, which refuses a larger one
/// before framing it.
pub use bastion_plugin_host::proto::MAX_STORAGE_VALUE_BYTES;
/// A key is at most this long.
pub const MAX_KEY_BYTES: usize = 256;
/// The log file and the one before it together stay under this.
pub const MAX_LOG_BYTES: u64 = 1024 * 1024;
/// A line is cut to this many bytes.
pub const MAX_LOG_LINE_BYTES: usize = 4 * 1024;
/// Lines a second; more are dropped and counted.
pub const MAX_LOG_LINES_PER_SECOND: u32 = 50;

fn io(e: impl std::fmt::Display) -> Failure {
    Failure::Invalid(format!("plugin storage: {e}"))
}

fn private_dir(dir: &Path) -> Result<(), Failure> {
    crate::store::create_private_dir(dir).map_err(io)
}

/// Where the values of one entry's part live.
enum Backing {
    /// `storage/<part>.json` on disk.
    File(PathBuf),
    /// Protected document: lives only as long as the view.
    Memory(BTreeMap<String, Vec<u8>>),
}

/// One helper's storage: one entry's part of one plugin's store.
pub struct EntryStorage {
    storage_dir: PathBuf,
    backing: Backing,
}

fn part_name(document_id: &str, entry_id: &str) -> String {
    let mut h = Sha256::new();
    for part in [document_id, entry_id] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part.as_bytes());
    }
    hex::encode(h.finalize())
}

fn check_key(key: &str) -> Result<(), Failure> {
    if key.is_empty() || key.len() > MAX_KEY_BYTES {
        return Err(Failure::Invalid(format!("a storage key is 1 to {MAX_KEY_BYTES} bytes")));
    }
    Ok(())
}

/// Stored size of a map: base64 plus JSON framing.
fn stored_size(map: &BTreeMap<String, Vec<u8>>) -> u64 {
    map.iter().map(|(k, v)| k.len() as u64 + (v.len() as u64).div_ceil(3) * 4 + 8).sum::<u64>() + 2
}

impl EntryStorage {
    /// The part of `plugin_data_dir` (`plugin-data/<id>/`) for one document's entry.
    /// `protected` (the entry's document is protected): nothing outlasts the view.
    pub fn open(plugin_data_dir: &Path, document_id: &str, entry_id: &str, protected: bool) -> EntryStorage {
        let storage_dir = plugin_data_dir.join("storage");
        let backing = if protected { Backing::Memory(BTreeMap::new()) } else { Backing::File(storage_dir.join(format!("{}.json", part_name(document_id, entry_id)))) };
        EntryStorage { storage_dir, backing }
    }

    fn read(&self) -> Result<BTreeMap<String, Vec<u8>>, Failure> {
        match &self.backing {
            Backing::Memory(map) => Ok(map.clone()),
            Backing::File(path) => {
                let Ok(bytes) = fs::read(path) else { return Ok(BTreeMap::new()) };
                let stored: BTreeMap<String, String> = serde_json::from_slice(&bytes).map_err(io)?;
                stored.into_iter().map(|(k, v)| base64::engine::general_purpose::STANDARD.decode(v).map(|v| (k, v)).map_err(io)).collect()
            }
        }
    }

    fn write(&mut self, map: BTreeMap<String, Vec<u8>>) -> Result<(), Failure> {
        match &mut self.backing {
            Backing::Memory(held) => {
                *held = map;
                Ok(())
            }
            Backing::File(path) => {
                private_dir(&self.storage_dir)?;
                let encoded: BTreeMap<&String, String> = map.iter().map(|(k, v)| (k, base64::engine::general_purpose::STANDARD.encode(v))).collect();
                let bytes = serde_json::to_vec(&encoded).map_err(io)?;
                crate::store::write_atomic(path, &bytes).map_err(io)
            }
        }
    }

    /// Bytes on disk for the whole plugin, every part, except this part's own file.
    fn other_parts_bytes(&self) -> u64 {
        let own = match &self.backing {
            Backing::File(path) => Some(path.clone()),
            Backing::Memory(_) => None,
        };
        let Ok(dir) = fs::read_dir(&self.storage_dir) else { return 0 };
        dir.flatten()
            .filter(|e| own.as_ref() != Some(&e.path()))
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum()
    }

    pub fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Failure> {
        check_key(key)?;
        Ok(self.read()?.remove(key))
    }

    /// Writes `value` under `key`. Refused when the key or the value passes the secret check
    /// against `released`, or when the plugin's storage would pass 50 MiB.
    pub fn set(&mut self, key: &str, value: &[u8], released: &SecretCheck) -> Result<(), Failure> {
        check_key(key)?;
        if value.len() > MAX_STORAGE_VALUE_BYTES {
            return Err(Failure::Invalid(format!("a storage value is at most {MAX_STORAGE_VALUE_BYTES} bytes")));
        }
        released.refuse(key.as_bytes())?;
        released.refuse(value)?;
        let mut map = self.read()?;
        map.insert(key.to_string(), value.to_vec());
        if self.other_parts_bytes() + stored_size(&map) > MAX_STORAGE_BYTES_PER_PLUGIN {
            return Err(Failure::Invalid("plugin storage is full (50 MiB)".into()));
        }
        self.write(map)
    }

    pub fn delete(&mut self, key: &str) -> Result<(), Failure> {
        check_key(key)?;
        let mut map = self.read()?;
        if map.remove(key).is_some() {
            self.write(map)?;
        }
        Ok(())
    }

    /// The keys that start with `prefix`, sorted.
    pub fn keys(&self, prefix: &str) -> Result<Vec<String>, Failure> {
        Ok(self.read()?.into_keys().filter(|k| k.starts_with(prefix)).collect())
    }
}

/// The log file of one plugin.
pub struct PluginLog {
    dir: PathBuf,
    window_start: Option<Instant>,
    in_window: u32,
    /// Lines dropped by the rate or the secret check, since the last line written.
    dropped: u64,
}

/// What happened to a log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogOutcome {
    Written,
    /// It passed the secret check: dropped whole.
    DroppedSecret,
    /// Over the rate.
    DroppedRate,
}

impl PluginLog {
    pub fn open(plugin_data_dir: &Path) -> PluginLog {
        PluginLog { dir: plugin_data_dir.join("log"), window_start: None, in_window: 0, dropped: 0 }
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join("plugin.log")
    }

    /// Writes one line at `level`. `now` is passed in for the rate.
    pub fn line(&mut self, level: &str, text: &str, released: &SecretCheck, now: Instant) -> Result<LogOutcome, Failure> {
        if !log_line_kept(released, text) {
            self.dropped += 1;
            return Ok(LogOutcome::DroppedSecret);
        }
        match self.window_start {
            Some(start) if now.saturating_duration_since(start).as_secs() < 1 => {
                if self.in_window >= MAX_LOG_LINES_PER_SECOND {
                    self.dropped += 1;
                    return Ok(LogOutcome::DroppedRate);
                }
            }
            _ => {
                self.window_start = Some(now);
                self.in_window = 0;
            }
        }
        self.in_window += 1;
        let mut line = String::with_capacity(text.len().min(MAX_LOG_LINE_BYTES) + 64);
        if self.dropped > 0 {
            line.push_str(&format!("[core] {} lines dropped\n", self.dropped));
            self.dropped = 0;
        }
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let mut cut = text.len().min(MAX_LOG_LINE_BYTES);
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        // One record per line: a plugin cannot forge the next line's level or time.
        let body: String = text[..cut].chars().map(|c| if c == '\n' || c == '\r' { ' ' } else { c }).collect();
        line.push_str(&format!("{stamp} {level} {body}\n"));
        self.append(line.as_bytes())?;
        Ok(LogOutcome::Written)
    }

    fn append(&self, bytes: &[u8]) -> Result<(), Failure> {
        private_dir(&self.dir)?;
        let path = self.path();
        let size = fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if size + bytes.len() as u64 > MAX_LOG_BYTES / 2 {
            match fs::rename(&path, self.dir.join("plugin.log.1")) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(io(e)),
            }
        }
        let mut opts = fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
        let mut file = opts.open(&path).map_err(io)?;
        #[cfg(windows)]
        crate::winacl::restrict_path(&path, false).map_err(io)?;
        file.write_all(bytes).map_err(io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn released() -> SecretCheck {
        let mut c = SecretCheck::new();
        c.add(b"hunter22-secret");
        c
    }

    #[test]
    fn values_round_trip_and_keys_filter_by_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = EntryStorage::open(dir.path(), "doc", "e1", false);
        s.set("query/1", b"select 1", &released()).unwrap();
        s.set("query/2", b"select 2", &released()).unwrap();
        s.set("other", b"x", &released()).unwrap();
        assert_eq!(s.get("query/1").unwrap(), Some(b"select 1".to_vec()));
        assert_eq!(s.keys("query/").unwrap(), ["query/1", "query/2"]);
        s.delete("query/1").unwrap();
        assert_eq!(s.get("query/1").unwrap(), None);
        // Survives a reopen.
        assert_eq!(EntryStorage::open(dir.path(), "doc", "e1", false).get("other").unwrap(), Some(b"x".to_vec()));
    }

    #[test]
    fn a_write_holding_a_released_password_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = EntryStorage::open(dir.path(), "doc", "e1", false);
        assert!(matches!(s.set("k", b"pw=hunter22-secret", &released()), Err(Failure::Denied(_))));
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hunter22-secret");
        assert!(matches!(s.set("k", encoded.as_bytes(), &released()), Err(Failure::Denied(_))), "encoded forms too");
        assert!(matches!(s.set("hunter22-secret", b"v", &released()), Err(Failure::Denied(_))), "and in the key");
        assert_eq!(s.get("k").unwrap(), None);
    }

    #[test]
    fn one_entry_never_sees_another_entrys_part() {
        let dir = tempfile::tempdir().unwrap();
        EntryStorage::open(dir.path(), "doc", "e1", false).set("k", b"one", &released()).unwrap();
        assert_eq!(EntryStorage::open(dir.path(), "doc", "e2", false).get("k").unwrap(), None);
        assert_eq!(EntryStorage::open(dir.path(), "doc2", "e1", false).get("k").unwrap(), None, "same entry id, other document");
    }

    #[test]
    fn protected_documents_keep_nothing_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = EntryStorage::open(dir.path(), "doc", "e1", true);
        s.set("k", b"v", &released()).unwrap();
        assert_eq!(s.get("k").unwrap(), Some(b"v".to_vec()));
        assert!(!dir.path().join("storage").exists());
        assert_eq!(EntryStorage::open(dir.path(), "doc", "e1", true).get("k").unwrap(), None);
    }

    #[test]
    fn storage_stops_at_fifty_mib_per_plugin() {
        let dir = tempfile::tempdir().unwrap();
        let big = vec![b'a'; MAX_STORAGE_VALUE_BYTES];
        // 2 MiB values take 2.67 MiB each in base64: 9 per part, two parts fill about 48 MiB.
        let mut a = EntryStorage::open(dir.path(), "doc", "e1", false);
        let mut b = EntryStorage::open(dir.path(), "doc", "e2", false);
        for i in 0..9 {
            a.set(&format!("k{i}"), &big, &SecretCheck::new()).unwrap();
            b.set(&format!("k{i}"), &big, &SecretCheck::new()).unwrap();
        }
        assert!(matches!(b.set("k9", &big, &SecretCheck::new()), Err(Failure::Invalid(_))), "the cap is per plugin, over every part");
        // Replacing a value does not count the old one twice.
        a.set("k0", &big, &SecretCheck::new()).unwrap();
    }

    #[test]
    fn a_value_over_the_cap_is_refused_and_nothing_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = EntryStorage::open(dir.path(), "doc", "e1", false);
        s.set("k", &vec![0; MAX_STORAGE_VALUE_BYTES], &SecretCheck::new()).unwrap();
        let err = s.set("k", &vec![1; MAX_STORAGE_VALUE_BYTES + 1], &SecretCheck::new()).unwrap_err();
        assert!(matches!(err, Failure::Invalid(ref m) if m.contains("at most")), "{err:?}");
        assert_eq!(s.get("k").unwrap().unwrap().len(), MAX_STORAGE_VALUE_BYTES, "the old value stays");
    }

    #[test]
    fn bad_keys_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = EntryStorage::open(dir.path(), "doc", "e1", false);
        assert!(s.set("", b"v", &released()).is_err());
        assert!(s.set(&"k".repeat(MAX_KEY_BYTES + 1), b"v", &released()).is_err());
        assert!(s.set(&"k".repeat(MAX_KEY_BYTES), b"v", &released()).is_ok());
    }

    #[test]
    fn a_log_line_holding_a_released_password_is_dropped_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = PluginLog::open(dir.path());
        let now = Instant::now();
        assert_eq!(log.line("info", "connected", &released(), now).unwrap(), LogOutcome::Written);
        assert_eq!(log.line("info", "password hunter22-secret", &released(), now).unwrap(), LogOutcome::DroppedSecret);
        let text = fs::read_to_string(log.path()).unwrap();
        assert!(text.contains("connected"));
        assert!(!text.contains("hunter22"));
    }

    #[test]
    fn log_lines_past_the_rate_are_dropped_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = PluginLog::open(dir.path());
        let now = Instant::now();
        for _ in 0..MAX_LOG_LINES_PER_SECOND {
            assert_eq!(log.line("info", "x", &SecretCheck::new(), now).unwrap(), LogOutcome::Written);
        }
        assert_eq!(log.line("info", "x", &SecretCheck::new(), now).unwrap(), LogOutcome::DroppedRate);
        log.line("info", "later", &SecretCheck::new(), now + Duration::from_secs(1)).unwrap();
        assert!(fs::read_to_string(log.path()).unwrap().contains("[core] 1 lines dropped"));
    }

    #[test]
    fn a_plugin_cannot_forge_log_lines_and_the_log_stays_under_one_mib() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = PluginLog::open(dir.path());
        let t = Instant::now();
        log.line("info", "a\n1700000000 error forged", &SecretCheck::new(), t).unwrap();
        assert_eq!(fs::read_to_string(log.path()).unwrap().lines().count(), 1);
        let long = "y".repeat(MAX_LOG_LINE_BYTES * 2);
        for i in 0..2_000u64 {
            log.line("info", &long, &SecretCheck::new(), t + Duration::from_secs(i)).unwrap();
        }
        let total: u64 = ["plugin.log", "plugin.log.1"].iter().map(|n| fs::metadata(dir.path().join("log").join(n)).map(|m| m.len()).unwrap_or(0)).sum();
        assert!(total <= MAX_LOG_BYTES, "{total}");
    }

    #[cfg(unix)]
    #[test]
    fn storage_and_log_have_the_vaults_file_protections() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        EntryStorage::open(dir.path(), "doc", "e1", false).set("k", b"v", &released()).unwrap();
        let mut log = PluginLog::open(dir.path());
        log.line("info", "x", &released(), Instant::now()).unwrap();
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir.path().join("storage")), 0o700);
        assert_eq!(mode(&dir.path().join("log")), 0o700);
        assert_eq!(mode(&log.path()), 0o600);
        for f in fs::read_dir(dir.path().join("storage")).unwrap() {
            assert_eq!(mode(&f.unwrap().path()), 0o600);
        }
    }
}
