//! The Personal library as one encrypted `.bastion` document (OF-F, owner point 20). The tree
//! and the credential vault both live in the document; the frontend supplies the device key it
//! read ONCE from the Keychain, and this object hands out the ordinary `Library` and
//! `CredentialVault` handles the rest of the app already uses, both saving into the document.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bastion_core::audit::Category;
use bastion_core::docfile::{self, DocumentFile};
use bastion_core::personal::{self, Opened};
use zeroize::Zeroizing;

use crate::credentials::{legacy_key, CredentialVault};
use crate::documents::{audit, outcome};
use crate::{FfiError, FfiResult, Library};

/// What the one-time move from `library.json` + `credentials.vault` did.
#[derive(uniffi::Record)]
pub struct PersonalMigrationView {
    pub folders: u32,
    pub connections: u32,
    pub credentials: u32,
    pub backup: Option<String>,
}

#[derive(uniffi::Record)]
pub struct PersonalInfoView {
    pub id: String,
    pub path: String,
    pub locked: bool,
    pub has_master_password: bool,
    /// The display name stored inside the document (owner point 33); the file keeps its name.
    pub name: String,
}

#[derive(uniffi::Object)]
pub struct PersonalLibrary {
    file: Arc<Mutex<DocumentFile>>,
    data_dir: PathBuf,
    device_key: docfile::DocumentKey,
    migration: Option<PersonalMigrationView>,
    library: Mutex<Option<Arc<Library>>>,
    vault: Mutex<Option<Arc<CredentialVault>>>,
}

/// A fresh device key (hex) for the frontend to keep in its one Keychain item.
#[uniffi::export]
pub fn personal_new_device_key() -> String {
    docfile::key_to_hex(&docfile::new_wrapping_key()).to_string()
}

impl PersonalLibrary {
    fn file(&self) -> std::sync::MutexGuard<'_, DocumentFile> {
        self.file.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn drop_handles(&self) {
        *self.library.lock().unwrap_or_else(|e| e.into_inner()) = None;
        *self.vault.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
}

#[uniffi::export]
impl PersonalLibrary {
    /// Open `path` (creating it, or migrating the old Personal files in `data_dir`, once).
    /// Errors with code `cancelled` when the one-time legacy Keychain read was dismissed; the old
    /// files are then untouched and the next launch tries again.
    #[uniffi::constructor]
    pub fn open(data_dir: String, path: String, device_key_hex: String) -> FfiResult<Arc<Self>> {
        let device = docfile::key_from_hex(&Zeroizing::new(device_key_hex))?;
        let dir = PathBuf::from(&data_dir);
        let legacy_vault = dir.join(personal::LEGACY_VAULT).display().to_string();
        let legacy = || legacy_key(&legacy_vault).map_err(|e| match e {
            FfiError::Failed { code, .. } if code == "cancelled" => bastion_core::CoreError::Cancelled,
            other => bastion_core::CoreError::Invalid(other.to_string()),
        });
        let r = personal::open_or_migrate(&dir, Path::new(&path), &device, &legacy);
        audit(&dir, Category::ImportExport, "personal.open", &path, outcome(&r), &[]);
        let (file, how) = r?;
        let migration = match how {
            Opened::Migrated(m) => Some(PersonalMigrationView { folders: m.folders, connections: m.connections, credentials: m.credentials, backup: m.backup.map(|b| b.display().to_string()) }),
            _ => None,
        };
        Ok(Arc::new(PersonalLibrary { file: Arc::new(Mutex::new(file)), data_dir: dir, device_key: device, migration, library: Mutex::new(None), vault: Mutex::new(None) }))
    }

    pub fn info(&self) -> PersonalInfoView {
        let f = self.file();
        PersonalInfoView { id: f.id().to_string(), path: f.path().map(|p| p.display().to_string()).unwrap_or_default(), locked: f.is_locked(), has_master_password: f.has_password(), name: f.name().to_string() }
    }

    /// Set only when this launch moved the old Personal files.
    pub fn migration(&self) -> Option<PersonalMigrationView> {
        self.migration.as_ref().map(|m| PersonalMigrationView { folders: m.folders, connections: m.connections, credentials: m.credentials, backup: m.backup.clone() })
    }

    /// The tree as a `Library` that saves into the document.
    pub fn library(&self) -> FfiResult<Arc<Library>> {
        let mut slot = self.library.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(l) = slot.as_ref() {
            return Ok(l.clone());
        }
        let doc = self.file().document()?.clone();
        let lib = Arc::new(Library::for_document(doc, self.file.clone(), &self.data_dir));
        *slot = Some(lib.clone());
        Ok(lib)
    }

    /// The credential vault inside the document (no Keychain read: the key is already here).
    pub fn vault(&self) -> FfiResult<Arc<CredentialVault>> {
        let mut slot = self.vault.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(v) = slot.as_ref() {
            return Ok(v.clone());
        }
        let v = Arc::new(CredentialVault::for_document(self.file.clone())?);
        *slot = Some(v.clone());
        Ok(v)
    }

    /// Set (or change) the optional master password. The device copy of the key is removed, so
    /// the library then opens only with the password.
    pub fn set_master_password(&self, password: String) -> FfiResult<()> {
        let password = Zeroizing::new(password);
        let mut f = self.file();
        f.set_password(Some(&password))?;
        f.save()?;
        personal::forget_document_key(&self.data_dir, f.id())?;
        audit(&self.data_dir, Category::Authentication, "personal.master_password.set", &f.id().to_string(), bastion_core::audit::Outcome::Success, &[]);
        Ok(())
    }

    /// Remove the master password: the device key alone opens the library again.
    pub fn remove_master_password(&self) -> FfiResult<()> {
        let mut f = self.file();
        f.remove_master_password()?;
        personal::store_document_key(&self.data_dir, &f, &self.device_key)?;
        f.save()?;
        audit(&self.data_dir, Category::Authentication, "personal.master_password.remove", &f.id().to_string(), bastion_core::audit::Outcome::Success, &[]);
        Ok(())
    }

    /// Rename the library: only the name inside the document changes, never the file, so the
    /// device key and recent-file links keep working. Saved at once, like every Personal change.
    pub fn rename(&self, name: String) -> FfiResult<()> {
        let lib = self.library.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let mut f = self.file();
        if let Some(lib) = &lib {
            let doc = lib.lock().clone();
            f.set_document(doc)?;
        }
        f.rename(&name)?;
        f.save()?;
        if let Some(lib) = &lib {
            *lib.lock() = f.document()?.clone();
        }
        audit(&self.data_dir, Category::ImportExport, "personal.rename", &f.id().to_string(), bastion_core::audit::Outcome::Success, &[]);
        Ok(())
    }

    /// The user showed Personal by hand (Documents › Show Personal): it becomes the last library in
    /// Recents, so the next launch opens it (LIB-01). Locks never call this.
    pub fn note_shown(&self) {
        if let Some(p) = self.file().path().map(Path::to_path_buf) {
            crate::documents::remember_recent(&self.data_dir, &p);
        }
    }

    /// Unlock a master-password library.
    pub fn unlock(&self, password: String) -> FfiResult<()> {
        let password = Zeroizing::new(password);
        let r = self.file().unlock(&password);
        audit(&self.data_dir, Category::Authentication, "personal.unlock", "Personal", outcome(&r), &[]);
        self.drop_handles();
        r.map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(dir: &Path) -> Arc<PersonalLibrary> {
        PersonalLibrary::open(dir.display().to_string(), dir.join("Personal.bastion").display().to_string(), KEY.into()).unwrap()
    }
    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    #[test]
    fn vault_saves_into_the_document_and_survives_reopen() {
        let t = tempfile::tempdir().unwrap();
        let p = open(t.path());
        let v = p.vault().unwrap();
        let id = v.save_password(None, "ops".into(), None, "ops".into(), "s3cret-pw".into()).unwrap();
        v.save().unwrap();
        assert!(!t.path().join("credentials.vault").exists());
        let raw = std::fs::read_to_string(t.path().join("Personal.bastion")).unwrap();
        assert!(!raw.contains("s3cret-pw"));
        drop(p);
        let again = open(t.path());
        assert!(again.vault().unwrap().list().iter().any(|c| c.id == id));
    }

    #[test]
    fn library_and_vault_saves_do_not_clobber_each_other() {
        let t = tempfile::tempdir().unwrap();
        let p = open(t.path());
        let lib = p.library().unwrap();
        let v = p.vault().unwrap();
        v.save_password(None, "a".into(), None, "u".into(), "pw-one".into()).unwrap();
        v.save().unwrap();
        lib.save().unwrap();
        v.save_password(None, "b".into(), None, "u".into(), "pw-two".into()).unwrap();
        v.save().unwrap();
        drop((lib, v, p));
        let again = open(t.path());
        assert_eq!(again.vault().unwrap().list().len(), 2);
    }

    #[test]
    fn rename_changes_the_inner_name_not_the_file_and_survives_reopen() {
        let t = tempfile::tempdir().unwrap();
        let p = open(t.path());
        let lib = p.library().unwrap();
        p.rename("Home Lab".into()).unwrap();
        lib.save().unwrap();
        assert_eq!(p.info().name, "Home Lab");
        assert!(p.rename("   ".into()).is_err());
        drop((lib, p));
        assert!(t.path().join("Personal.bastion").exists());
        assert_eq!(open(t.path()).info().name, "Home Lab");
    }

    #[test]
    fn wrong_device_key_is_vault_locked() {
        let t = tempfile::tempdir().unwrap();
        drop(open(t.path()));
        let other = "ff".repeat(32);
        let e = PersonalLibrary::open(t.path().display().to_string(), t.path().join("Personal.bastion").display().to_string(), other).err().unwrap();
        assert!(matches!(e, FfiError::Failed { ref code, .. } if code == "vault_locked"), "{e:?}");
    }
    #[test]
    fn note_shown_puts_personal_first_in_recents() {
        // LIB-01: after Show Personal, the next launch opens Personal, not the document used before it.
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().display().to_string();
        let p = open(t.path());
        let other = crate::documents::BastionDocument::create("Testing-New".into(), dir.clone()).unwrap();
        other.save_as(t.path().join("Testing-New.bastion").display().to_string()).unwrap();
        assert!(crate::documents::recent_documents(dir.clone())[0].ends_with("Testing-New.bastion"));
        p.note_shown();
        let recents = crate::documents::recent_documents(dir.clone());
        assert_eq!(recents[0], p.info().path);
        assert_eq!(recents.len(), 2);
        other.note_opened();
        assert!(crate::documents::recent_documents(dir)[0].ends_with("Testing-New.bastion"));
    }
}
