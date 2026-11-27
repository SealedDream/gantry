//! One-time import of a KeePass `.kdbx` file into Bastion's own vault (AUDIT B8).
//!
//! The file is read and decrypted in memory only (no temp files); passwords are held as
//! [`Secret`] (zeroized on drop) until they are sealed in the vault. The preview carries titles,
//! usernames and groups, never a password. KeePass groups become Credentials-section folders
//! under one top folder (named after the file). Entries without a password and the recycle bin
//! are skipped. A duplicate is a credential already in the same target folder with the same
//! name and username (case-insensitive); [`DuplicateRule`] decides what happens to it.
use std::path::Path;

use uuid::Uuid;

use crate::credtree::{MAX_DEPTH, MAX_NAME_LEN};
use crate::error::{CoreError, Result};
use crate::vault::{Credential, CredentialKind, Secret, Vault};

/// What to do with an entry that matches an existing credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicateRule {
    /// Leave the existing credential as it is.
    Skip,
    /// Overwrite the existing credential's username and password, keeping its id and references.
    Replace,
    /// Add the entry as a second credential beside the existing one.
    KeepBoth,
}

impl DuplicateRule {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "skip" => Ok(Self::Skip),
            "replace" => Ok(Self::Replace),
            "keep-both" => Ok(Self::KeepBoth),
            other => Err(CoreError::Invalid(format!("unknown duplicate rule: {other}"))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowStatus {
    New,
    Duplicate,
    /// No password in the entry: never imported.
    NoPassword,
}

impl RowStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::New => "new",
            Self::Duplicate => "duplicate",
            Self::NoPassword => "no-password",
        }
    }
}

/// One entry as the preview shows it: no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewRow {
    pub title: String,
    pub username: String,
    /// Target folder path, `/`-joined, top folder first.
    pub folder: String,
    pub status: RowStatus,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportOutcome {
    pub added: usize,
    pub replaced: usize,
    pub skipped_duplicates: usize,
    pub skipped_no_password: usize,
    /// Top folder the entries went into (`None` when nothing was added or replaced).
    pub folder: Option<Uuid>,
}

/// An entry read from the file. The password leaves this module only into the vault.
struct Entry {
    title: String,
    username: String,
    group: Vec<String>,
    password: Option<Secret>,
}

fn safe_name(s: &str, fallback: &str) -> String {
    let s: String = s.chars().map(|c| if c.is_control() || c == '/' { ' ' } else { c }).collect();
    let s = s.trim();
    let s = if s.is_empty() { fallback } else { s };
    s.chars().take(MAX_NAME_LEN).collect()
}

/// Name for the top folder: "KeePass <file stem>".
pub fn top_folder_name(path: &Path) -> String {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let stem = safe_name(&stem, "");
    safe_name(&if stem.is_empty() { "KeePass".into() } else { format!("KeePass {stem}") }, "KeePass")
}

fn read(path: &Path, password: Option<Secret>, keyfile: Option<&Path>) -> Result<Vec<Entry>> {
    crate::kdbx::read_entries(path, password, keyfile, |title, username, group, pw| Entry {
        title: safe_name(title, "Untitled"),
        username: username.to_string(),
        group: group.iter().map(|g| safe_name(g, "Group")).take(MAX_DEPTH - 1).collect(),
        password: pw.filter(|p| !p.is_empty()).map(Secret::new),
    })
}

fn child(v: &Vault, parent: Option<Uuid>, name: &str) -> Option<Uuid> {
    v.folders().into_iter().find(|f| f.parent == parent && f.name.eq_ignore_ascii_case(name)).map(|f| f.id)
}

/// The folder at `names` below the root, without creating anything.
fn find_path(v: &Vault, names: &[String]) -> Option<Uuid> {
    names.iter().try_fold(None, |parent, n| child(v, parent, n).map(Some)).flatten()
}

fn ensure_path(v: &mut Vault, names: &[String]) -> Result<Option<Uuid>> {
    let mut parent = None;
    for n in names {
        parent = Some(match child(v, parent, n) {
            Some(id) => id,
            None => v.add_folder(n, parent)?,
        });
    }
    Ok(parent)
}

/// The existing credential in `folder` with this name and username, if any.
fn duplicate_of(v: &Vault, folder: Uuid, e: &Entry) -> Option<Uuid> {
    v.list()
        .into_iter()
        .find(|c| v.folder_of(c.id) == Some(folder) && c.name.eq_ignore_ascii_case(&e.title) && c.username.eq_ignore_ascii_case(&e.username))
        .map(|c| c.id)
}

fn target_names(top: &str, e: &Entry) -> Vec<String> {
    std::iter::once(top.to_string()).chain(e.group.iter().cloned()).collect()
}

fn existing(v: &Vault, names: &[String], e: &Entry) -> Option<Uuid> {
    find_path(v, names).and_then(|f| duplicate_of(v, f, e))
}

/// Read the file and say what an import would do. No secret is returned.
pub fn preview(vault: &Vault, path: &Path, password: Option<Secret>, keyfile: Option<&Path>) -> Result<Vec<PreviewRow>> {
    let top = top_folder_name(path);
    Ok(read(path, password, keyfile)?
        .iter()
        .map(|e| {
            let names = target_names(&top, e);
            let status = match (&e.password, existing(vault, &names, e)) {
                (None, _) => RowStatus::NoPassword,
                (Some(_), Some(_)) => RowStatus::Duplicate,
                (Some(_), None) => RowStatus::New,
            };
            PreviewRow { title: e.title.clone(), username: e.username.clone(), folder: names.join("/"), status }
        })
        .collect())
}

/// Import every entry with a password into `vault`. The caller saves the vault.
pub fn import(vault: &mut Vault, path: &Path, password: Option<Secret>, keyfile: Option<&Path>, rule: DuplicateRule) -> Result<ImportOutcome> {
    let top = top_folder_name(path);
    let mut out = ImportOutcome::default();
    for e in read(path, password, keyfile)? {
        let Some(pw) = e.password.clone() else {
            out.skipped_no_password += 1;
            continue;
        };
        let names = target_names(&top, &e);
        let kind = CredentialKind::Password { username: e.username.clone(), password: pw };
        match (existing(vault, &names, &e), rule) {
            (Some(_), DuplicateRule::Skip) => {
                out.skipped_duplicates += 1;
                continue;
            }
            (Some(id), DuplicateRule::Replace) => {
                if let Some(c) = vault.entries.get_mut(&id) {
                    c.kind = kind;
                }
                out.replaced += 1;
            }
            _ => {
                let folder = ensure_path(vault, &names)?;
                let id = vault.add(Credential { id: Uuid::new_v4(), name: e.title.clone(), folder: None, scope: None, owner: None, kind });
                vault.move_credential(id, folder)?;
                out.added += 1;
            }
        }
        out.folder = find_path(vault, &names[..1]);
    }
    Ok(out)
}

#[cfg(test)]
#[path = "kdbx_import_tests.rs"]
mod tests;
