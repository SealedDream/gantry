//! The libraries this device knows (A1-CORE-01-FU5).
//!
//! A library opened by path could be one the user made or one somebody sent. The file cannot
//! say which: everything in it, the confirmation marks on its login references included, is
//! whatever its writer put there. So the app asks once per device, "Did you make this
//! library?", and remembers the answer here by **document id**. Paths are not used for trust:
//! a sender's file put at the path of a known library has another id and is asked about, and
//! a known library that is moved, renamed, copied or restored keeps its id and is not.
//!
//! The record is `known-documents.json` in the app data folder: a JSON list of document ids
//! (lower-case UUID strings), oldest first, and nothing else. No name, path, time or secret.
//! It is owner-only, written atomically, never part of a document, an export or diagnostics.
//!
//! It fails towards asking. A missing, unreadable or malformed record knows no library; a
//! record that is full drops its oldest ids, which are then asked about once more.
//!
//! What it cannot tell apart (accepted, owner decision 2026-11-13): a file that carries the id
//! of one of the user's own libraries, which takes a copy of that library to make.
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::docfile::DocumentFile;
use crate::store::write_atomic;
use crate::{CoreError, Result};

pub const KNOWN_FILE: &str = "known-documents.json";
/// The most ids kept. When full, the oldest go.
pub const MAX_KNOWN: usize = 10_000;
/// A full record is under 400 KB; anything much larger is not this record.
const MAX_RECORD_BYTES: u64 = 1024 * 1024;

/// The record as found on disk.
enum Record {
    /// No file yet: the migration has not run.
    Missing,
    /// A file that is not a list of ids, or cannot be read. It knows nothing.
    Damaged,
    Ids(Vec<Uuid>),
}

pub struct KnownDocuments {
    path: PathBuf,
}

impl KnownDocuments {
    pub fn in_dir(data_dir: &Path) -> Self {
        KnownDocuments { path: data_dir.join(KNOWN_FILE) }
    }

    fn read(&self) -> Record {
        let too_large = match std::fs::metadata(&self.path) {
            Ok(m) => !m.is_file() || m.len() > MAX_RECORD_BYTES,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Record::Missing,
            Err(_) => true,
        };
        if too_large {
            return Record::Damaged;
        }
        // Every entry must be an id: one bad entry makes the whole record damaged.
        match std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice::<Vec<Uuid>>(&b).ok()) {
            Some(ids) => Record::Ids(newest(ids)),
            None => Record::Damaged,
        }
    }

    fn write(&self, ids: &[Uuid]) -> Result<()> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        // `Uuid` serialises as its lower-case hyphenated text.
        write_atomic(&self.path, &serde_json::to_vec(ids).map_err(|e| CoreError::Invalid(e.to_string()))?)
    }

    /// Whether the user has answered for this library on this device (or it was recorded by
    /// the migration, or made here). False whenever the record cannot be trusted.
    pub fn is_known(&self, id: Uuid) -> bool {
        matches!(self.read(), Record::Ids(ids) if ids.contains(&id))
    }

    /// Remember `id`. A damaged record is replaced by one that holds only `id`: every other
    /// library is asked about again.
    pub fn add(&self, id: Uuid) -> Result<()> {
        let mut ids = match self.read() {
            Record::Ids(ids) => ids,
            Record::Missing | Record::Damaged => Vec::new(),
        };
        if ids.contains(&id) {
            return Ok(());
        }
        ids.push(id);
        self.write(&newest(ids))
    }

    /// Once, on the first start of a build with this record: write it with the Personal
    /// library's id and the id of every document in `candidates` that can be read (the id is
    /// in the clear envelope, so a locked document needs no password). Returns true when it
    /// ran. It does nothing when a record exists, damaged or not, and it writes the record
    /// even when it is empty so that it never runs again.
    pub fn migrate(&self, personal: Option<Uuid>, candidates: &[PathBuf]) -> Result<bool> {
        if !matches!(self.read(), Record::Missing) {
            return Ok(false);
        }
        let mut ids: Vec<Uuid> = Vec::new();
        let found = candidates.iter().filter_map(|p| DocumentFile::open(p).ok().map(|d| d.id()));
        for id in personal.into_iter().chain(found) {
            if !ids.contains(&id) {
                ids.push(id);
            }
        }
        self.write(&newest(ids))?;
        Ok(true)
    }
}

/// The newest `MAX_KNOWN` ids (the list is oldest first).
fn newest(mut ids: Vec<Uuid>) -> Vec<Uuid> {
    let extra = ids.len().saturating_sub(MAX_KNOWN);
    ids.drain(..extra);
    ids
}

#[cfg(test)]
#[path = "known_docs_tests.rs"]
mod tests;
