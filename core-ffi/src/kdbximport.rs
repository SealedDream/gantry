//! KeePass `.kdbx` import into the credential vault (AUDIT B8). The preview carries no secret;
//! the import seals the passwords in the vault and saves it. The master password is zeroized
//! after use; nothing is written to disk except the encrypted vault.
use std::path::Path;

use bastion_core::kdbx_import::{self, DuplicateRule};
use bastion_core::vault::Secret;
use zeroize::Zeroizing;

use crate::credentials::CredentialVault;
use crate::FfiResult;

/// One KeePass entry as the import preview shows it: no secret.
#[derive(uniffi::Record)]
pub struct KeePassImportRow {
    pub title: String,
    pub username: String,
    /// Target Credentials folder, `/`-joined.
    pub folder: String,
    /// `new`, `duplicate` or `no-password`.
    pub status: String,
}

#[derive(uniffi::Record)]
pub struct KeePassImportResult {
    pub added: u32,
    pub replaced: u32,
    pub skipped_duplicates: u32,
    pub skipped_no_password: u32,
    /// Top Credentials folder the entries went into.
    pub folder: Option<String>,
}

fn key(password: String, keyfile_path: Option<String>) -> (Option<Secret>, Option<String>) {
    let password = Zeroizing::new(password);
    let password = (!password.is_empty()).then(|| Secret::new(password.as_str()));
    (password, keyfile_path.filter(|k| !k.trim().is_empty()))
}

fn count(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[uniffi::export]
impl CredentialVault {
    /// What importing `path` would do: one row per entry, no secrets. `password` may be empty
    /// when `keyfile_path` is given.
    pub fn keepass_import_preview(&self, path: String, password: String, keyfile_path: Option<String>) -> FfiResult<Vec<KeePassImportRow>> {
        let (password, keyfile) = key(password, keyfile_path);
        let rows = kdbx_import::preview(&self.lock(), Path::new(&path), password, keyfile.as_deref().map(Path::new))?;
        Ok(rows
            .into_iter()
            .map(|r| KeePassImportRow { title: r.title, username: r.username, folder: r.folder, status: r.status.as_str().into() })
            .collect())
    }

    /// Import every entry with a password, then save the vault. `duplicates`: `skip`,
    /// `replace` or `keep-both`.
    pub fn keepass_import(&self, path: String, password: String, keyfile_path: Option<String>, duplicates: String) -> FfiResult<KeePassImportResult> {
        let rule = DuplicateRule::parse(&duplicates)?;
        let (password, keyfile) = key(password, keyfile_path);
        let r = kdbx_import::import(&mut self.lock(), Path::new(&path), password, keyfile.as_deref().map(Path::new), rule)?;
        self.save()?;
        Ok(KeePassImportResult {
            added: count(r.added),
            replaced: count(r.replaced),
            skipped_duplicates: count(r.skipped_duplicates),
            skipped_no_password: count(r.skipped_no_password),
            folder: r.folder.map(|f| f.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use keepass::db::fields;
    use keepass::{Database, DatabaseKey};

    use super::*;

    /// Synthetic KDBX4 file: one entry in "Lab", one without a password.
    fn fixture(dir: &Path) -> String {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut lab = root.add_group();
            lab.name = "Lab".into();
            let mut e = lab.add_entry();
            e.set_unprotected(fields::TITLE, "lab sshd");
            e.set_unprotected(fields::USERNAME, "root");
            e.set_protected(fields::PASSWORD, "kp-s3cret");
            let mut e = lab.add_entry();
            e.set_unprotected(fields::TITLE, "notes");
        }
        let path = dir.join("Lab.kdbx");
        db.save(&mut std::fs::File::create(&path).unwrap(), DatabaseKey::new().with_password("master")).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn preview_then_import_into_the_sealed_vault() {
        let d = tempfile::tempdir().unwrap();
        let kdbx = fixture(d.path());
        let vault_path = d.path().join("credentials.vault");
        let v = CredentialVault::open_ephemeral(vault_path.to_string_lossy().into_owned()).unwrap();

        assert!(v.keepass_import_preview(kdbx.clone(), "wrong".into(), None).is_err());
        let rows = v.keepass_import_preview(kdbx.clone(), "master".into(), None).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.title != "kp-s3cret" && r.username != "kp-s3cret" && r.folder != "kp-s3cret"));
        assert_eq!(rows.iter().find(|r| r.title == "lab sshd").unwrap().status, "new");
        assert!(v.keepass_import(kdbx.clone(), "master".into(), None, "merge".into()).is_err());

        let r = v.keepass_import(kdbx.clone(), "master".into(), None, "skip".into()).unwrap();
        assert_eq!((r.added, r.skipped_no_password), (1, 1));
        assert!(r.folder.is_some());
        let list = v.list();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].folder.as_deref(), Some("KeePass Lab/Lab"));
        let raw = std::fs::read(&vault_path).unwrap();
        assert!(!raw.windows(9).any(|w| w == b"kp-s3cret"), "password stored in clear text");

        let r = v.keepass_import(kdbx, "master".into(), None, "skip".into()).unwrap();
        assert_eq!((r.added, r.skipped_duplicates), (0, 1));
    }
}
