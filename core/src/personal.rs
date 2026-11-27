//! The Personal library as an encrypted `.bastion` document (owner point 20, OF-F).
//!
//! Every library on this Mac is a device-keyed document ([`docfile::DEVICE_KDF`]): its random
//! document key is wrapped by ONE device key (kept by the platform key store, read once per
//! launch) and the wrapped blob sits in `<data dir>/document-keys/<doc id>.key`. Secrets live in
//! the document's sealed payload (`Contents::vault`), so there is no separate credential vault.
//!
//! [`open_or_migrate`] creates `Personal.bastion` on first launch and moves an older
//! `library.json` + `credentials.vault` into it once: the new file is re-read from disk and
//! compared with the source before the old files are moved to a `pre-unified-<time>` backup.
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::docfile::{DocumentFile, DocumentKey};
use crate::error::{CoreError, Result};
use crate::model::{Document, Folder, Node};
use crate::store::{create_private_dir, write_atomic, Store};
use crate::vault::{Secret, Vault};

pub const LEGACY_LIBRARY: &str = "library.json";
pub const LEGACY_VAULT: &str = "credentials.vault";
pub const MARKER: &str = "unified.json";
const KEYS_DIR: &str = "document-keys";

/// What a migration moved (shown once, and kept in `unified.json`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    pub document_id: Uuid,
    pub path: PathBuf,
    pub folders: u32,
    pub connections: u32,
    pub credentials: u32,
    /// Where the old files were moved (`None` when there was nothing to move).
    pub backup: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Opened {
    Existing,
    Created,
    Migrated(MigrationReport),
}

fn key_path(data_dir: &Path, id: Uuid) -> PathBuf {
    data_dir.join(KEYS_DIR).join(format!("{id}.key"))
}

/// Keep `doc`'s key wrapped under the device key, so the device key alone reopens it.
pub fn store_document_key(data_dir: &Path, doc: &DocumentFile, device: &DocumentKey) -> Result<()> {
    let dir = data_dir.join(KEYS_DIR);
    create_private_dir(&dir)?;
    write_atomic(&key_path(data_dir, doc.id()), doc.export_wrapped_key(device)?.as_bytes())
}

/// Forget the device copy of a document key (a master password now protects it).
pub fn forget_document_key(data_dir: &Path, id: Uuid) -> Result<()> {
    match fs::remove_file(key_path(data_dir, id)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

pub fn has_document_key(data_dir: &Path, id: Uuid) -> bool {
    key_path(data_dir, id).is_file()
}

/// Unlock with the device key. `NotFound` when this device keeps no key for the document.
pub fn unlock_with_device(data_dir: &Path, doc: &mut DocumentFile, device: &DocumentKey) -> Result<()> {
    if !doc.is_locked() {
        return Ok(());
    }
    let blob = match fs::read_to_string(key_path(data_dir, doc.id())) {
        Ok(b) => zeroize::Zeroizing::new(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(CoreError::NotFound(format!("no device key for {}", doc.id()))),
        Err(e) => return Err(e.into()),
    };
    doc.unlock_with_wrapped_key(&blob, device)
}

fn count(f: &Folder) -> (u32, u32) {
    f.children.iter().fold((0, 0), |(fo, co), n| match n {
        Node::Folder(sub) => {
            let (a, b) = count(sub);
            (fo + 1 + a, co + b)
        }
        Node::Connection(_) => (fo, co + 1),
    })
}

/// Tree equality ignoring the revision counter (it advances on save).
fn same_tree(a: &Document, b: &Document) -> bool {
    Document { revision: 0, ..a.clone() } == Document { revision: 0, ..b.clone() }
}

fn stamp() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// Open `personal` (unlocked with `device`), creating it on first launch and migrating the old
/// Personal library once. `legacy_vault_key` is asked only when an old `credentials.vault`
/// exists; when it fails (for example the Keychain prompt was cancelled) nothing is migrated
/// and the error is returned, so the old files stay the source of truth until the next try.
pub fn open_or_migrate(data_dir: &Path, personal: &Path, device: &DocumentKey, legacy_vault_key: &dyn Fn() -> Result<Secret>) -> Result<(DocumentFile, Opened)> {
    if personal.exists() {
        let mut doc = DocumentFile::open(personal)?;
        if doc.is_device_keyed() || has_document_key(data_dir, doc.id()) {
            unlock_with_device(data_dir, &mut doc, device)?;
        }
        return Ok((doc, Opened::Existing));
    }
    let legacy_lib = data_dir.join(LEGACY_LIBRARY);
    let legacy_vault = data_dir.join(LEGACY_VAULT);
    let tree = if legacy_lib.is_file() { Some(Store::new(&legacy_lib).load()?) } else { None };
    let vault = if legacy_vault.is_file() {
        let key = legacy_vault_key()?;
        Some(Vault::open(&fs::read(&legacy_vault)?, key.expose())?)
    } else {
        None
    };
    let migrating = tree.is_some() || vault.is_some();
    let source = tree.clone().unwrap_or_else(|| Document::new("Personal".to_string()));
    let mut doc = DocumentFile::new_device(Document { name: "Personal".into(), ..source.clone() });
    if let Some(v) = &vault {
        doc.set_vault(v)?;
    }
    if let Some(dir) = personal.parent() {
        fs::create_dir_all(dir)?;
    }
    store_document_key(data_dir, &doc, device)?;
    doc.save_as(personal)?;
    if !migrating {
        return Ok((doc, Opened::Created));
    }
    if let Err(e) = verify(data_dir, personal, device, &source, vault.as_ref()) {
        let _ = fs::remove_file(personal);
        let _ = fs::remove_dir_all(crate::docfile::backups_dir(personal));
        let _ = forget_document_key(data_dir, doc.id());
        return Err(CoreError::Corrupt(format!("the Personal library could not be moved safely, so nothing was changed: {e}")));
    }
    let backup = data_dir.join(format!("pre-unified-{}", stamp()));
    create_private_dir(&backup)?;
    for f in [&legacy_lib, &legacy_vault] {
        if f.is_file() {
            let to = backup.join(f.file_name().unwrap_or_default());
            fs::copy(f, &to)?;
            fs::remove_file(f)?;
        }
    }
    let (folders, connections) = count(&source.root);
    let report = MigrationReport { document_id: doc.id(), path: personal.to_path_buf(), folders, connections, credentials: vault.as_ref().map(|v| v.len() as u32).unwrap_or(0), backup: Some(backup) };
    let json = serde_json::to_vec_pretty(&report).map_err(|e| CoreError::Invalid(e.to_string()))?;
    write_atomic(&data_dir.join(MARKER), &json)?;
    Ok((doc, Opened::Migrated(report)))
}

/// Re-read the new file from disk and prove it holds exactly the source tree and secrets.
fn verify(data_dir: &Path, personal: &Path, device: &DocumentKey, tree: &Document, vault: Option<&Vault>) -> Result<()> {
    let mut back = DocumentFile::open(personal)?;
    unlock_with_device(data_dir, &mut back, device)?;
    let doc = back.document()?;
    if !same_tree(&Document { name: tree.name.clone(), ..doc.clone() }, tree) {
        return Err(CoreError::Corrupt("the connection tree differs after saving".into()));
    }
    let stored = back.vault()?;
    let expected = vault.map(|v| v.to_plain()).transpose()?;
    let found = stored.to_plain()?;
    match expected {
        Some(e) if *e != *found => Err(CoreError::Corrupt("the saved credentials differ after saving".into())),
        None if !stored.is_empty() => Err(CoreError::Corrupt("unexpected credentials after saving".into())),
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "personal_tests.rs"]
mod tests;
