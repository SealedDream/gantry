//! Royal TS-style documents (`core::docfile`) for the native frontends: several `.bastion`
//! files open at once, each a top-level node with its own tree, lock state and (when password
//! protected) its own encrypted credentials. A document hands out an ordinary [`Library`] for
//! its tree, so every existing tree, property and connect path works on it unchanged; that
//! library saves back into the document instead of a `library.json`.
//!
//! Secrets go in (passwords, credential values) and never come back out. Biometric unlock keeps
//! the random document key in the login Keychain (Windows: a DPAPI blob for the current user);
//! the frontend shows Touch ID / Windows Hello first and only then calls
//! [`BastionDocument::unlock_biometric`], and the password always remains a fallback.
//!
//! Every open, unlock, failed unlock, lock, save, export and import is written to the audit
//! log; exporting secrets is refused when the managed policy sets `forbid_secret_export`.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use bastion_core::audit::{AuditLog, Category, Outcome};
use bastion_core::docfile::{self, DocumentFile, RecentDocuments};
use bastion_core::known_docs::KnownDocuments;
use bastion_core::model::Document;
use bastion_core::vault::{Credential, CredentialKind, Secret};
use bastion_core::CoreError;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::libio::selection;
use crate::{parse_id, CredentialView, FfiError, FfiResult, Library};

pub(crate) const RECENT_FILE: &str = "recent-documents.json";
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "Gantry";
/// The Keychain service before the product rename; read when an item is missing under the new one.
const LEGACY_KEYCHAIN_SERVICE: &str = "Bastion";

fn failed(message: impl Into<String>) -> FfiError {
    FfiError::failed(message.into())
}

fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

pub(crate) fn outcome<T, E>(r: &Result<T, E>) -> Outcome {
    if r.is_ok() {
        Outcome::Success
    } else {
        Outcome::Failure
    }
}

pub(crate) fn audit(data_dir: &Path, category: Category, action: &str, target: &str, outcome: Outcome, details: &[(&str, String)]) {
    let details: BTreeMap<String, String> = details.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect();
    if let Err(e) = AuditLog::open(data_dir.join("audit.jsonl")).and_then(|mut log| log.record(category, action, Some(target), outcome, details)) {
        eprintln!("bastion: audit log write failed for {action}: {e}");
    }
}

fn wrong_password(e: CoreError) -> FfiError {
    match e {
        CoreError::VaultAuth => FfiError::Failed { message: "the password is wrong or the document is damaged".into(), code: "vault_locked".into() },
        e => e.into(),
    }
}

/// Open `path` and unlock it with `password` when it is protected.
fn open_unlocked(path: &str, password: Option<&str>) -> FfiResult<DocumentFile> {
    let mut src = DocumentFile::open(Path::new(path))?;
    if src.is_locked() {
        let pw = password.ok_or_else(|| FfiError::Failed { message: "this document is password protected".into(), code: "vault_locked".into() })?;
        src.unlock(pw).map_err(wrong_password)?;
    }
    Ok(src)
}

#[derive(uniffi::Record)]
pub struct DocumentInfoView {
    pub id: String,
    pub name: String,
    /// `None` until the first Save As.
    pub path: Option<String>,
    pub protected: bool,
    pub locked: bool,
    /// Touch ID / Windows Hello unlock is set up for this document.
    pub biometric: bool,
    /// Changes not yet written (an untitled document, or a failed save).
    pub dirty: bool,
    /// Format version the file was read in; 0 means an old `library.json`.
    pub loaded_version: u32,
    /// Credentials stored in the document (0 while locked).
    pub credentials: u32,
}

#[derive(uniffi::Record)]
pub struct DocumentExportView {
    pub folders: u32,
    pub connections: u32,
    /// Credentials written into the file (0 when secrets are stripped).
    pub credentials: u32,
    pub credential_refs: u32,
    pub stripped_fields: Vec<String>,
    pub protected: bool,
}

#[derive(uniffi::Record)]
pub struct DocumentImportView {
    pub source_name: String,
    pub connections: u32,
    /// Names of connections skipped as duplicates (same protocol, host, port and user).
    pub duplicates: Vec<String>,
    pub credentials: u32,
    /// Credentials left out because the target has no password.
    pub credentials_dropped: u32,
    /// The new top-level folder (set once applied).
    pub folder: Option<String>,
}

fn export_view(s: &docfile::ExportSummary, protected: bool) -> DocumentExportView {
    DocumentExportView {
        folders: to_u32(s.folders),
        connections: to_u32(s.connections),
        credentials: to_u32(s.credentials),
        credential_refs: to_u32(s.credential_refs),
        stripped_fields: s.stripped_fields.clone(),
        protected,
    }
}

fn import_view(plan: docfile::ImportPlan, folder: Option<Uuid>) -> DocumentImportView {
    DocumentImportView {
        source_name: plan.source_name,
        connections: to_u32(plan.connections),
        duplicates: plan.duplicates,
        credentials: to_u32(plan.credentials),
        credentials_dropped: to_u32(plan.credentials_dropped),
        folder: folder.map(|f| f.to_string()),
    }
}

/// Whether this device knows a library (A1-CORE-01-FU5, `bastion_core::known_docs`).
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentOrigin {
    /// Made here, answered for before, or opened before this rule existed. Nothing to ask.
    Known,
    /// Opened by path and never answered for on this device: ask "Did you make this
    /// library?" before the tree is shown, and send the answer with `answer_origin`. Until
    /// then every login the file names is offered, not used.
    Unknown,
}

/// What the handle remembers about an unanswered library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    Known,
    Unknown {
        /// The revision the file was read at. A later revision was saved by this handle,
        /// so the file (and the sealed copy kept for unlock) already carries the marks.
        opened_revision: u64,
        /// The contents in memory carry the marks. False while a protected document is
        /// locked with contents that were never marked: the next unlock marks them.
        marked: bool,
    },
}

/// One open `.bastion` document.
#[derive(uniffi::Object)]
pub struct BastionDocument {
    file: Arc<Mutex<DocumentFile>>,
    pub(crate) data_dir: PathBuf,
    library: Mutex<Option<Arc<Library>>>,
    origin: Mutex<Origin>,
}

/// The library was closed while the question was still open: asked again next time.
impl Drop for BastionDocument {
    fn drop(&mut self) {
        if matches!(self.origin_state(), Origin::Unknown { .. }) {
            self.record_origin("asked-closed");
        }
    }
}

/// The libraries this device knows. When the record does not exist yet (an app that has not
/// called `migrate_known_documents`), it is first written from Recents, before the document
/// being opened is added there: what was opened before this rule existed stays as it was.
fn known_documents(data_dir: &Path) -> KnownDocuments {
    let known = KnownDocuments::in_dir(data_dir);
    if let Err(e) = known.migrate(None, &RecentDocuments::new(data_dir.join(RECENT_FILE)).list()) {
        eprintln!("bastion: could not write the known-libraries record: {e}");
    }
    known
}

impl BastionDocument {
    fn wrap(file: DocumentFile, data_dir: String) -> Self {
        BastionDocument { file: Arc::new(Mutex::new(file)), data_dir: PathBuf::from(data_dir), library: Mutex::new(None), origin: Mutex::new(Origin::Known) }
    }

    /// A document read from a path. Unless this device knows its id (or it is device-keyed,
    /// which only this device's key store can unlock), every login reference in it is marked
    /// as a sender's at once, in memory, so nothing uses one before the user has answered. A
    /// locked document is marked when it unlocks (`after_unlock`).
    fn wrap_opened(mut file: DocumentFile, data_dir: String) -> Self {
        let known = file.is_device_keyed() || known_documents(Path::new(&data_dir)).is_known(file.id());
        let origin = if known {
            Origin::Known
        } else {
            // Unlocked here means unprotected, so the mark cannot fail on a lock.
            let marked = !file.is_locked() && file.mark_as_received(false).is_ok();
            Origin::Unknown { opened_revision: file.revision(), marked }
        };
        let d = Self::wrap(file, data_dir);
        d.set_origin(origin);
        if known {
            d.record_origin("known");
        }
        d
    }

    fn origin_state(&self) -> Origin {
        *self.origin.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn set_origin(&self, origin: Origin) {
        *self.origin.lock().unwrap_or_else(|e| e.into_inner()) = origin;
    }

    /// `document.origin` in the audit log: `known`, `asked-made`, `asked-sent` or
    /// `asked-closed`. The target is what `document.open` already logs; no document id.
    fn record_origin(&self, answer: &str) {
        audit(&self.data_dir, Category::ImportExport, "document.origin", &self.target(), Outcome::Success, &[("origin", answer.into())]);
    }

    /// Mark an unanswered library's contents once they are readable.
    fn mark_if_unanswered(&self) {
        let Origin::Unknown { opened_revision, marked: false } = self.origin_state() else { return };
        let mut f = self.file();
        if !f.is_locked() && f.mark_as_received(false).is_ok() {
            drop(f);
            self.set_origin(Origin::Unknown { opened_revision, marked: true });
        }
    }

    /// The document locked. Contents that were never saved by this handle come back unmarked
    /// from the sealed copy at the next unlock, so they are marked again then.
    fn note_locked(&self) {
        if let Origin::Unknown { opened_revision, .. } = self.origin_state() {
            let (locked, revision) = {
                let f = self.file();
                (f.is_locked(), f.revision())
            };
            if locked {
                self.set_origin(Origin::Unknown { opened_revision, marked: revision != opened_revision });
            }
        }
    }

    /// "I made it" reads the file again, so it is refused once that would lose an edit (still
    /// in the library's working copy, or pending in the file) or bring back marks that were
    /// saved since the library was opened.
    fn unchanged_since_open(&self, opened_revision: u64) -> FfiResult<()> {
        let working = self.open_library().map(|lib| lib.lock().clone());
        let f = self.file();
        let edited = working.is_some_and(|w| f.document().is_ok_and(|d| *d != w));
        if edited || f.is_dirty() || f.revision() != opened_revision {
            return Err(failed("this library was changed before the question was answered; its logins stay to be confirmed one by one"));
        }
        Ok(())
    }

    /// The contents as the file holds them, without the in-memory marks ("I made it").
    fn reload_unmarked(&self, opened_revision: u64) -> FfiResult<()> {
        let mut f = self.file();
        if f.is_protected() {
            // The sealed copy is what was read from the file: decrypt it again.
            let key = f.key()?;
            if !f.lock() {
                return Err(failed("the library could not be read again"));
            }
            f.unlock_with_key(key)?;
            return Ok(());
        }
        let path = f.path().map(Path::to_path_buf).ok_or_else(|| failed("the library has no file"))?;
        let fresh = DocumentFile::open(&path)?;
        if fresh.id() != f.id() || fresh.revision() != opened_revision || fresh.is_protected() {
            return Err(failed("the file changed on disk; close the library and open it again"));
        }
        *f = fresh;
        Ok(())
    }

    pub(crate) fn file(&self) -> MutexGuard<'_, DocumentFile> {
        self.file.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn open_library(&self) -> Option<Arc<Library>> {
        self.library.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn target(&self) -> String {
        let f = self.file();
        f.path().map(|p| p.display().to_string()).unwrap_or_else(|| f.name().to_string())
    }

    fn record(&self, category: Category, action: &str, outcome: Outcome) {
        audit(&self.data_dir, category, action, &self.target(), outcome, &[]);
    }

    /// Push the open library's tree into the file (the library edits a working copy).
    fn sync_from_library(&self) -> FfiResult<()> {
        if let Some(lib) = self.open_library() {
            let doc = lib.lock().clone();
            let mut f = self.file();
            // An unchanged tree is not a change: a lock must not save the in-memory marks of a
            // library that is still unanswered (A1-CORE-01-FU5).
            if f.document().map_or(true, |d| *d != doc) {
                f.set_document(doc)?;
            }
        }
        Ok(())
    }

    /// After the file's tree changed underneath the library (import), refresh the library.
    fn sync_to_library(&self) -> FfiResult<()> {
        if let Some(lib) = self.open_library() {
            *lib.lock() = self.file().document()?.clone();
        }
        Ok(())
    }

    /// Store this document's connection count for the start window's Recents row. Only while the
    /// tree is open (never decrypts to count).
    fn note_connection_count(&self) {
        let f = self.file();
        if let (Some(p), Ok(doc)) = (f.path().map(Path::to_path_buf), f.document()) {
            note_connection_count(&self.data_dir, &p, doc);
        }
    }

    fn remember(&self) {
        let Some(p) = self.file().path().map(Path::to_path_buf) else { return };
        remember_recent(&self.data_dir, &p);
    }

    pub(crate) fn after_unlock(&self, how: &str, r: bastion_core::Result<()>) -> FfiResult<()> {
        // Before anything can read the tree: an unanswered library's logins are a sender's.
        self.mark_if_unanswered();
        audit(&self.data_dir, Category::Authentication, "document.unlock", &self.target(), outcome(&r), &[("method", how.into())]);
        r.map_err(wrong_password)
    }
}

#[uniffi::export]
impl BastionDocument {
    /// A new untitled, unprotected document; Save As gives it a file.
    #[uniffi::constructor]
    pub fn create(name: String, data_dir: String) -> FfiResult<Arc<Self>> {
        Ok(Arc::new(Self::wrap(DocumentFile::new(&name)?, data_dir)))
    }

    /// Reopen a document that was open at the last quit (protected ones locked) without touching
    /// Recents: restoring several must not reorder which one was last.
    #[uniffi::constructor]
    pub fn reopen(path: String, data_dir: String) -> FfiResult<Arc<Self>> {
        let r = DocumentFile::open(Path::new(&path));
        audit(Path::new(&data_dir), Category::ImportExport, "document.open", &path, outcome(&r), &[]);
        Ok(Arc::new(Self::wrap_opened(r?, data_dir)))
    }

    /// The user brought this document to the front (opened, unlocked or switched to): it becomes
    /// the last document in Recents.
    pub fn note_opened(&self) {
        self.remember();
    }

    /// Open a `.bastion` file (or an old `library.json`). Protected documents open locked.
    #[uniffi::constructor]
    pub fn open(path: String, data_dir: String) -> FfiResult<Arc<Self>> {
        let r = DocumentFile::open(Path::new(&path));
        audit(Path::new(&data_dir), Category::ImportExport, "document.open", &path, outcome(&r), &[]);
        let d = Arc::new(Self::wrap_opened(r?, data_dir));
        d.remember();
        Ok(d)
    }

    /// Whether to ask "Did you make this library?" (A1-CORE-01-FU5). `Unknown` for a library
    /// opened by path that this device has no answer for; a locked one is asked about after
    /// it is unlocked, when the tree is first shown.
    pub fn origin(&self) -> DocumentOrigin {
        match self.origin_state() {
            Origin::Known => DocumentOrigin::Known,
            Origin::Unknown { .. } => DocumentOrigin::Unknown,
        }
    }

    /// The user's answer, for an unlocked library. `true` ("I made it"): the id is recorded
    /// and the contents are read again from the file without the marks. `false` ("Someone
    /// sent it"): the id is recorded and the marks become a change, kept with the next save.
    /// Closing the question sends nothing: the marks hold for this session and the library is
    /// asked about again next time. A known library takes no answer.
    pub fn answer_origin(&self, made_by_me: bool) -> FfiResult<()> {
        let Origin::Unknown { opened_revision, .. } = self.origin_state() else { return Ok(()) };
        let id = {
            let f = self.file();
            if f.is_locked() {
                return Err(failed("unlock the library before answering"));
            }
            f.id()
        };
        let known = KnownDocuments::in_dir(&self.data_dir);
        if made_by_me {
            self.unchanged_since_open(opened_revision)?;
            // Recorded first: if that fails the marks stay and the question is asked again.
            known.add(id)?;
            self.reload_unmarked(opened_revision)?;
            self.sync_to_library()?;
        } else {
            // The marks are already in memory (and in the library's working copy, which may
            // hold logins the user confirmed since): they only become a change to save.
            self.mark_if_unanswered();
            self.sync_from_library()?;
            self.file().document_mut()?;
            known.add(id)?;
        }
        self.set_origin(Origin::Known);
        self.record_origin(if made_by_me { "asked-made" } else { "asked-sent" });
        Ok(())
    }

    pub fn info(&self) -> DocumentInfoView {
        let f = self.file();
        DocumentInfoView {
            id: f.id().to_string(),
            name: f.name().to_string(),
            path: f.path().map(|p| p.display().to_string()),
            protected: f.is_protected(),
            locked: f.is_locked(),
            biometric: f.biometric(),
            dirty: f.is_dirty(),
            loaded_version: f.loaded_version(),
            credentials: f.credentials().map(|c| to_u32(c.len())).unwrap_or(0),
        }
    }

    /// Unlock with the password. Five wrong passwords start a 30 s wait that doubles with each
    /// further one (kept across relaunches); while waiting, this fails without trying.
    pub fn unlock(&self, password: String) -> FfiResult<()> {
        let password = Zeroizing::new(password);
        let id = self.file().id();
        let backoff = bastion_core::docunlock::UnlockBackoff::in_dir(&self.data_dir);
        backoff.check(id, crate::docunlock::now())?;
        let r = self.file().unlock(&password);
        match &r {
            Ok(()) => backoff.record_success(id)?,
            Err(CoreError::VaultAuth) => {
                backoff.record_failure(id, crate::docunlock::now())?;
            }
            Err(_) => {}
        }
        self.after_unlock("password", r)
    }

    /// Unlock with the key kept in the platform key store. Call only after the frontend's
    /// Touch ID / Windows Hello check succeeded.
    pub fn unlock_biometric(&self) -> FfiResult<()> {
        let id = self.file().id();
        let r = crate::policy::effective_for_documents().and_then(|p| bastion_core::docunlock::check_biometric_allowed(&p)).and_then(|()| os_key_fetch(id)).and_then(|hex| docfile::key_from_hex(hex.expose())).and_then(|k| self.file().unlock_with_key(k));
        self.after_unlock("biometric", r)
    }

    /// Close the document's secrets: save pending changes (when it has a file), forget the key,
    /// the credentials and the tree. Returns false for an unprotected document (nothing to lock).
    pub fn lock(&self) -> FfiResult<bool> {
        {
            let f = self.file();
            if !f.is_protected() || f.is_locked() {
                return Ok(false);
            }
        }
        // A failed save never blocks the lock (F07): the changes are re-sealed in memory and
        // saved after the next unlock; the save error is returned once the document is locked.
        let persisted = self.sync_from_library().and_then(|()| {
            let mut f = self.file();
            if f.path().is_some() && f.is_dirty() {
                f.save()?;
            }
            Ok(())
        });
        if persisted.is_ok() {
            self.note_connection_count();
        }
        if let Some(lib) = self.library.lock().unwrap_or_else(|e| e.into_inner()).take() {
            lib.revoke();
        }
        let locked = match &persisted {
            Ok(()) => self.file().lock(),
            Err(_) => self.file().lock_keeping_changes()?,
        };
        self.note_locked();
        self.record(Category::AppLock, "document.lock", Outcome::Success);
        match persisted {
            Ok(()) => Ok(locked),
            Err(e) => Err(FfiError::failed(format!("locked, but unsaved changes could not be written; they are kept encrypted and will be saved after unlock: {e}"))),
        }
    }

    /// The document's tree as a [`Library`]; every saved mutation of it goes into this document.
    pub fn library(&self) -> FfiResult<Arc<Library>> {
        let mut slot = self.library.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(lib) = slot.as_ref() {
            return Ok(lib.clone());
        }
        let doc = self.file().document()?.clone();
        let lib = Arc::new(Library::for_document(doc, self.file.clone(), &self.data_dir));
        *slot = Some(lib.clone());
        Ok(lib)
    }

    pub fn save(&self) -> FfiResult<()> {
        self.sync_from_library()?;
        let r = self.file().save();
        self.record(Category::ImportExport, "document.save", outcome(&r));
        r?;
        self.note_connection_count();
        Ok(())
    }

    pub fn save_as(&self, path: String) -> FfiResult<()> {
        self.sync_from_library()?;
        let had_file = self.file().path().is_some();
        let r = self.file().save_as(Path::new(&path));
        self.record(Category::ImportExport, "document.save-as", outcome(&r));
        r?;
        if !had_file {
            // A document made here gets its first file: it is never asked about.
            if let Err(e) = known_documents(&self.data_dir).add(self.file().id()) {
                eprintln!("bastion: could not record the new library as known: {e}");
            }
        }
        if let Some(lib) = self.open_library() {
            lib.lock().revision = self.file().revision();
        }
        self.remember();
        self.note_connection_count();
        Ok(())
    }

    pub fn rename(&self, name: String) -> FfiResult<()> {
        self.sync_from_library()?;
        self.file().rename(&name)?;
        self.sync_to_library()
    }

    /// Set or change (`Some`) or remove (`None`) the document password. Takes effect on the next
    /// save. Removing it also removes the biometric key.
    pub fn set_password(&self, password: Option<String>) -> FfiResult<()> {
        let password = password.map(Zeroizing::new);
        self.sync_from_library()?;
        let (had, id) = {
            let f = self.file();
            (f.is_protected(), f.id())
        };
        self.file().set_password(password.as_ref().map(|p| p.as_str()))?;
        if password.is_none() && had {
            let _ = os_key_delete(id);
        }
        let action = match (had, password.is_some()) {
            (false, true) => "document.password-set",
            (true, true) => "document.password-change",
            _ => "document.password-remove",
        };
        self.record(Category::CredentialAccess, action, Outcome::Success);
        Ok(())
    }

    /// Turn Touch ID / Windows Hello unlock on or off. Needs an unlocked, protected document.
    pub fn set_biometric(&self, on: bool) -> FfiResult<()> {
        let id = self.file().id();
        if on {
            let key = self.file().key()?;
            if !self.file().is_protected() {
                return Err(failed("set a document password before turning on Touch ID"));
            }
            os_key_store(id, &Secret::new(docfile::key_to_hex(&key).as_str()))?;
        } else {
            let _ = os_key_delete(id);
        }
        self.file().set_biometric(on)?;
        self.record(Category::CredentialAccess, if on { "document.biometric-on" } else { "document.biometric-off" }, Outcome::Success);
        Ok(())
    }

    /// Credentials stored in this document: names and usernames only.
    pub fn credentials(&self) -> FfiResult<Vec<CredentialView>> {
        let f = self.file();
        let mut out: Vec<CredentialView> = f
            .credentials()?
            .iter()
            .map(|c| {
                let (username, kind) = match &c.kind {
                    CredentialKind::Password { username, .. } => (username.clone(), "password"),
                    CredentialKind::SshKey { username, .. } => (username.clone(), "ssh-key"),
                };
                CredentialView { id: c.id.to_string(), name: c.name.clone(), folder: c.folder.clone(), username, kind: kind.into() }
            })
            .chain(f.unsupported_credentials()?.iter().filter(|c| c.owner.is_none()).map(|c| CredentialView {
                id: c.id.to_string(),
                name: c.name.clone(),
                folder: c.folder.clone(),
                username: bastion_core::vault_unknown::UNSUPPORTED_CREDENTIAL.into(),
                kind: "unsupported".into(),
            }))
            .collect();
        out.sort_by_key(|c| c.name.to_lowercase());
        Ok(out)
    }

    /// Add (`id` = None) or update a password credential in the document. An empty `password`
    /// on update keeps the stored one.
    pub fn save_password_credential(&self, id: Option<String>, name: String, username: String, password: String) -> FfiResult<String> {
        let password = Zeroizing::new(password);
        if name.trim().is_empty() {
            return Err(failed("a credential needs a name"));
        }
        let id = id.as_deref().map(parse_id).transpose()?.unwrap_or_else(Uuid::new_v4);
        {
            let mut f = self.file();
            let old = f.credentials()?.iter().find(|c| c.id == id).cloned();
            let secret = match old.as_ref().map(|c| &c.kind) {
                Some(CredentialKind::Password { password: p, .. }) if password.is_empty() => p.clone(),
                _ if password.is_empty() => return Err(failed("a password is required")),
                _ => Secret::new(password.as_str()),
            };
            let scope = old.and_then(|c| c.scope.clone());
            f.put_credential(Credential { id, name, folder: None, scope, owner: None, kind: CredentialKind::Password { username, password: secret } })?;
        }
        self.record(Category::CredentialAccess, "document.credential-save", Outcome::Success);
        Ok(id.to_string())
    }

    pub fn remove_credential(&self, id: String) -> FfiResult<()> {
        if !self.file().remove_credential(parse_id(&id)?)? {
            return Err(failed("no such credential"));
        }
        self.record(Category::CredentialAccess, "document.credential-remove", Outcome::Success);
        Ok(())
    }

    /// Export all of the document (`ids` = None) or the selected folders/connections to a new
    /// `.bastion` file at `path`. Secrets are stripped unless `include_secrets`, which needs a
    /// `password` for the new file. Callers confirm first (`ExportConfiguration`).
    pub fn export_to(&self, path: String, ids: Option<Vec<String>>, name: String, include_secrets: bool, password: Option<String>) -> FfiResult<DocumentExportView> {
        let password = password.map(Zeroizing::new);
        if include_secrets && crate::policy::effective()?.forbid_secret_export {
            return Err(CoreError::PolicyDenied("exporting secrets is turned off by your administrator".into()).into());
        }
        self.sync_from_library()?;
        let sel = selection(ids)?;
        let (mut out, s) = docfile::export(&self.file(), &sel, &name, include_secrets, password.as_ref().map(|p| p.as_str()))?;
        let r = out.save_as(Path::new(&path));
        let details = [("connections", s.connections.to_string()), ("credentials", s.credentials.to_string()), ("from", self.target())];
        audit(&self.data_dir, Category::ImportExport, "document.export", &path, outcome(&r), &details);
        r?;
        Ok(export_view(&s, out.is_protected()))
    }

    /// Preview (`apply` false) or perform importing the `.bastion` file at `path` into this
    /// document as a new folder. A protected source needs its `password`.
    pub fn import_document(&self, path: String, password: Option<String>, apply: bool) -> FfiResult<DocumentImportView> {
        let password = password.map(Zeroizing::new);
        let src = open_unlocked(&path, password.as_ref().map(|p| p.as_str()))?;
        self.sync_from_library()?;
        let (plan, folder) = docfile::import_into(&mut self.file(), &src, apply)?;
        if apply {
            self.sync_to_library()?;
            let saved = {
                let mut f = self.file();
                if f.path().is_some() { f.save() } else { Ok(()) }
            };
            if let (Ok(()), Some(lib)) = (&saved, self.open_library()) {
                lib.lock().revision = self.file().revision();
            }
            let details = [("source", path.clone()), ("connections", plan.connections.to_string()), ("duplicates", plan.duplicates.len().to_string())];
            audit(&self.data_dir, Category::ImportExport, "document.import", &self.target(), outcome(&saved), &details);
            saved?;
        }
        Ok(import_view(plan, folder))
    }
}

impl Library {
    /// A library whose saves go into `file` rather than a `library.json`. An untitled
    /// document only takes the tree; it is written on Save As.
    pub(crate) fn for_document(doc: Document, file: Arc<Mutex<DocumentFile>>, data_dir: &Path) -> Self {
        Library { store: None, doc: Mutex::new(doc), document: Some(file), counts_dir: Some(data_dir.to_path_buf()), revoked: Default::default() }
    }

    /// Lock: this handle is revoked permanently and its tree emptied.
    pub(crate) fn revoke(&self) {
        self.revoked.store(true, std::sync::atomic::Ordering::SeqCst);
        *self.lock() = Document::new("Locked");
    }

    pub(crate) fn save_into_document(&self, file: &Mutex<DocumentFile>) -> FfiResult<()> {
        let mut f = file.lock().unwrap_or_else(|e| e.into_inner());
        // Checked under the file lock, before anything changes, so a revoked handle never commits.
        if self.revoked.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(FfiError::failed("this view of the document was closed when it locked; reopen it".into()));
        }
        f.set_document(self.lock().clone())?;
        if f.path().is_some() {
            f.save()?;
            self.lock().revision = f.revision();
            if let (Some(dir), Some(p)) = (&self.counts_dir, f.path().map(Path::to_path_buf)) {
                note_connection_count(dir, &p, &self.lock());
            }
        }
        Ok(())
    }
}

/// Export the Personal library (or a selection of it) to a shareable `.bastion` document. The
/// Personal library keeps its credentials in the app vault, so the export never has secrets.
#[uniffi::export]
pub fn export_library_document(library: Arc<Library>, path: String, ids: Option<Vec<String>>, name: String, password: Option<String>, data_dir: String) -> FfiResult<DocumentExportView> {
    let password = password.map(Zeroizing::new);
    let source = DocumentFile::from_document(library.lock().clone());
    let (mut out, s) = docfile::export(&source, &selection(ids)?, &name, false, password.as_ref().map(|p| p.as_str()))?;
    let r = out.save_as(Path::new(&path));
    audit(Path::new(&data_dir), Category::ImportExport, "document.export", &path, outcome(&r), &[("connections", s.connections.to_string()), ("from", "Personal".into())]);
    r?;
    Ok(export_view(&s, out.is_protected()))
}

/// Import a `.bastion` document into the Personal library as a new folder (secrets never come
/// along; the Personal library references credentials only). Preview with `apply` false.
#[uniffi::export]
pub fn import_document_into_library(library: Arc<Library>, path: String, password: Option<String>, apply: bool, data_dir: String) -> FfiResult<DocumentImportView> {
    let password = password.map(Zeroizing::new);
    let src = open_unlocked(&path, password.as_ref().map(|p| p.as_str()))?;
    let mut target = DocumentFile::from_document(library.lock().clone());
    let (plan, folder) = docfile::import_into(&mut target, &src, apply)?;
    if apply {
        *library.lock() = target.document()?.clone();
        let r = library.save();
        audit(Path::new(&data_dir), Category::ImportExport, "document.import", "Personal", outcome(&r), &[("source", path), ("connections", plan.connections.to_string())]);
        r?;
    }
    Ok(import_view(plan, folder))
}

/// Put `doc` at the head of Recents with its open time: the library the next launch opens.
/// Record `doc`'s connection count beside Recents (only while it is listed there). Counting walks
/// the open tree; a failure is logged, never fatal.
pub(crate) fn note_connection_count(data_dir: &Path, path: &Path, doc: &Document) {
    let list = RecentDocuments::new(data_dir.join(RECENT_FILE)).list();
    if !list.iter().any(|p| p == path) {
        return;
    }
    let mut n: u32 = 0;
    doc.resolve_where(|_, _| {
        n = n.saturating_add(1);
        false
    });
    if let Err(e) = bastion_core::docunlock::record_connection_count(data_dir, path, &list, n) {
        eprintln!("bastion: could not record the connection count: {e}");
    }
}

pub(crate) fn remember_recent(data_dir: &Path, doc: &Path) {
    let r = RecentDocuments::new(data_dir.join(RECENT_FILE))
        .add(doc)
        .and_then(|list| bastion_core::docunlock::record_opened(data_dir, doc, &list, crate::docunlock::now()));
    if let Err(e) = r {
        eprintln!("bastion: could not update recent documents: {e}");
    }
}

/// Recent documents, newest first (files that no longer exist are left out).
#[uniffi::export]
pub fn recent_documents(data_dir: String) -> Vec<String> {
    RecentDocuments::new(Path::new(&data_dir).join(RECENT_FILE)).list().into_iter().filter(|p| p.exists()).map(|p| p.display().to_string()).collect()
}

#[uniffi::export]
pub fn forget_recent_document(data_dir: String, path: String) -> FfiResult<()> {
    RecentDocuments::new(Path::new(&data_dir).join(RECENT_FILE)).remove(Path::new(&path))?;
    Ok(())
}

/// Once at launch, before any document is opened or restored (A1-CORE-01-FU5): when this
/// device has no known-libraries record yet, write it with the Personal library, every
/// document in Recents and every document about to be restored (`restore_paths`), so that
/// nothing opened before this rule existed is asked about. Returns true when it ran. A record
/// that exists, damaged or not, is left alone. On an error nothing is waved through: unknown
/// libraries are asked about and the migration runs again at the next start.
#[uniffi::export]
pub fn migrate_known_documents(data_dir: String, personal_id: Option<String>, restore_paths: Vec<String>) -> FfiResult<bool> {
    let dir = Path::new(&data_dir);
    let personal = personal_id.as_deref().map(parse_id).transpose()?;
    let mut candidates = RecentDocuments::new(dir.join(RECENT_FILE)).list();
    candidates.extend(restore_paths.into_iter().map(PathBuf::from));
    Ok(KnownDocuments::in_dir(dir).migrate(personal, &candidates)?)
}

/// The document file extension (`gantry`), for save panels and new documents.
#[uniffi::export]
pub fn document_extension() -> String {
    docfile::EXTENSION.into()
}

/// The extension of documents made before the product rename (`bastion`); open panels accept it.
#[uniffi::export]
pub fn legacy_document_extension() -> String {
    docfile::LEGACY_EXTENSION.into()
}

fn key_item(id: Uuid) -> String {
    format!("document-key:{id}")
}

#[cfg(target_os = "macos")]
pub(crate) fn provider() -> bastion_core::provider::KeychainProvider {
    bastion_core::provider::KeychainProvider::with_legacy(KEYCHAIN_SERVICE, LEGACY_KEYCHAIN_SERVICE)
}

/// Windows: DPAPI blobs (current user) under `%APPDATA%\Gantry\document-keys`.
#[cfg(windows)]
pub(crate) fn provider() -> bastion_core::provider::DpapiProvider {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    bastion_core::provider::DpapiProvider::new(base.join("Gantry").join("document-keys"))
}

#[cfg(any(target_os = "macos", windows))]
fn os_key_fetch(id: Uuid) -> bastion_core::Result<Secret> {
    use bastion_core::provider::CredentialProvider;
    provider().fetch(&key_item(id)).map_err(|_| CoreError::Invalid("biometric unlock is not set up here; use the document password".into()))
}

#[cfg(any(target_os = "macos", windows))]
fn os_key_store(id: Uuid, key: &Secret) -> bastion_core::Result<()> {
    use bastion_core::provider::CredentialProvider;
    provider().store(&key_item(id), key)
}

#[cfg(any(target_os = "macos", windows))]
fn os_key_delete(id: Uuid) -> bastion_core::Result<()> {
    use bastion_core::provider::CredentialProvider;
    provider().delete(&key_item(id))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn os_key_fetch(id: Uuid) -> bastion_core::Result<Secret> {
    Err(CoreError::NotFound(key_item(id)))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn os_key_store(_id: Uuid, _key: &Secret) -> bastion_core::Result<()> {
    Err(CoreError::Invalid("biometric unlock needs the macOS Keychain or Windows DPAPI".into()))
}

#[cfg(not(any(target_os = "macos", windows)))]
fn os_key_delete(_id: Uuid) -> bastion_core::Result<()> {
    Ok(())
}

#[cfg(test)]
#[path = "a1_fu5_tests.rs"]
mod a1_fu5_tests;

#[cfg(test)]
mod tests {
    use super::*;

    const PW: &str = "document password";

    #[test]
    fn library_edits_save_into_the_document_and_lock_clears_the_tree() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_string_lossy().into_owned();
        let path = dir.path().join("Team.bastion").to_string_lossy().into_owned();
        let d = BastionDocument::create("Team".into(), data.clone()).unwrap();
        let lib = d.library().unwrap();
        lib.add_connection(None, "web".into(), "ssh".into(), "web.example".into(), None, None).unwrap();
        lib.save().unwrap(); // untitled: only taken into the document
        assert!(d.info().dirty);
        d.set_password(Some(PW.into())).unwrap();
        d.save_password_credential(None, "ops".into(), "ops".into(), "s3cret-value".into()).unwrap();
        d.save_as(path.clone()).unwrap();
        lib.add_connection(None, "db".into(), "ssh".into(), "db.example".into(), None, None).unwrap();
        lib.save().unwrap(); // has a file now: written
        assert!(!std::fs::read_to_string(&path).unwrap().contains("s3cret-value"));

        assert!(d.lock().unwrap());
        assert!(lib.tree().connections.is_empty(), "locking drops the tree from memory");
        assert!(d.library().is_err() && d.credentials().is_err());

        let reopened = BastionDocument::open(path.clone(), data.clone()).unwrap();
        assert!(reopened.info().locked);
        assert!(reopened.unlock("wrong one!".into()).is_err());
        reopened.unlock(PW.into()).unwrap();
        assert_eq!(reopened.library().unwrap().tree().connections.len(), 2);
        assert_eq!(reopened.credentials().unwrap()[0].name, "ops");
        assert_eq!(recent_documents(data.clone()), vec![path]);
        let log = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(log.contains("document.unlock"));
        assert!(!log.contains("s3cret-value") && !log.contains(PW));
    }

    /// START-WINDOW: Recents carry the connection count from the last save or lock, read without
    /// unlocking; an untitled document records nothing.
    #[test]
    fn saves_and_locks_record_the_connection_count_for_recents() {
        let dir = tempfile::tempdir().unwrap();
        let (d, path, data) = protected_doc_with_one_host(&dir);
        let count = |data: &str| -> Option<u64> {
            let rows: serde_json::Value = serde_json::from_str(&crate::docunlock::recent_document_details(data.into()).unwrap()).unwrap();
            rows.as_array().unwrap().iter().find(|r| r["path"] == path.as_str()).and_then(|r| r["connectionCount"].as_u64())
        };
        assert_eq!(count(&data), Some(1), "Save As records it");
        let lib = d.library().unwrap();
        lib.add_connection(None, "db".into(), "ssh".into(), "db.example".into(), None, None).unwrap();
        lib.save().unwrap();
        assert_eq!(count(&data), Some(2), "each library save records it");
        assert!(d.lock().unwrap());
        assert_eq!(count(&data), Some(2), "still known while locked");
        forget_recent_document(data.clone(), path.clone()).unwrap();
        assert!(count(&data).is_none());
    }

    fn protected_doc_with_one_host(dir: &tempfile::TempDir) -> (Arc<BastionDocument>, String, String) {
        let data = dir.path().to_string_lossy().into_owned();
        let path = dir.path().join("Team.bastion").to_string_lossy().into_owned();
        let d = BastionDocument::create("Team".into(), data.clone()).unwrap();
        d.library().unwrap().add_connection(None, "web".into(), "ssh".into(), "web.example".into(), None, None).unwrap();
        d.set_password(Some(PW.into())).unwrap();
        d.save_as(path.clone()).unwrap();
        (d, path, data)
    }

    /// Single unlock sheet: a key wrapped by a caller-held key reopens the document, a wrong
    /// wrapping key or a blob from another document is refused, and the blob never holds the
    /// password or the raw document key.
    #[test]
    fn key_wrapped_by_a_caller_key_unlocks_only_with_that_key() {
        let dir = tempfile::tempdir().unwrap();
        let (d, path, data) = protected_doc_with_one_host(&dir);
        let k = docfile::new_wrapping_key().to_vec();
        let wrapped = d.export_key_wrapped_by(k.clone()).unwrap();
        assert!(!wrapped.contains(&docfile::key_to_hex(&d.file().key().unwrap()).to_string()));
        assert!(d.lock().unwrap());
        let other = docfile::new_wrapping_key().to_vec();
        assert!(d.unlock_key_wrapped_by(wrapped.clone(), other).is_err());
        assert!(d.unlock_key_wrapped_by(wrapped.clone(), vec![1, 2, 3]).is_err());
        assert!(d.info().locked);
        d.unlock_key_wrapped_by(wrapped.clone(), k.clone()).unwrap();
        assert_eq!(d.library().unwrap().tree().connections.len(), 1);
        // Another document cannot be opened with this blob.
        let dir2 = tempfile::tempdir().unwrap();
        let (e, _, _) = protected_doc_with_one_host(&dir2);
        assert!(e.lock().unwrap());
        assert!(e.unlock_key_wrapped_by(wrapped, k).is_err());
        let _ = (path, data);
    }

    /// F04: a Library handed out before lock can never save its emptied copy after unlock.
    #[test]
    fn stale_library_from_before_lock_cannot_erase_the_tree() {
        let dir = tempfile::tempdir().unwrap();
        let (d, path, data) = protected_doc_with_one_host(&dir);
        let stale = d.library().unwrap();
        assert!(d.lock().unwrap());
        d.unlock(PW.into()).unwrap();
        assert_eq!(d.library().unwrap().tree().connections.len(), 1);
        assert!(stale.save().is_err(), "a pre-lock handle must stay revoked");
        let reopened = BastionDocument::open(path, data).unwrap();
        reopened.unlock(PW.into()).unwrap();
        assert_eq!(reopened.library().unwrap().tree().connections.len(), 1);
    }

    /// F07: a save failure during lock still locks, and the unsaved edit survives to the next unlock.
    #[test]
    fn lock_completes_when_the_save_fails() {
        let dir = tempfile::tempdir().unwrap();
        let (d, path, _) = protected_doc_with_one_host(&dir);
        d.library().unwrap().add_connection(None, "db".into(), "ssh".into(), "db.example".into(), None, None).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap(); // the destination can no longer be written as a file
        assert!(d.lock().is_err(), "the save failure is still reported");
        assert!(d.info().locked);
        assert!(d.library().is_err() && d.credentials().is_err());
        d.unlock(PW.into()).unwrap();
        assert_eq!(d.library().unwrap().tree().connections.len(), 2, "unsaved change kept");
        assert!(d.info().dirty);
    }

    #[test]
    fn export_and_import_through_the_bridge() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().to_string_lossy().into_owned();
        let d = BastionDocument::create("Source".into(), data.clone()).unwrap();
        d.library().unwrap().add_connection(None, "web".into(), "ssh".into(), "web.example".into(), None, Some("ops".into())).unwrap();
        let out = dir.path().join("Share.bastion").to_string_lossy().into_owned();
        assert!(d.export_to(out.clone(), None, "Share".into(), true, None).is_err());
        let v = d.export_to(out.clone(), None, "Share".into(), false, None).unwrap();
        assert_eq!((v.connections, v.credentials, v.protected), (1, 0, false));

        let personal = Arc::new(Library::open(dir.path().join("library.json").to_string_lossy().into_owned()).unwrap());
        let preview = import_document_into_library(personal.clone(), out.clone(), None, false, data.clone()).unwrap();
        assert_eq!(preview.connections, 1);
        assert!(personal.tree().folders.is_empty(), "a preview changes nothing");
        import_document_into_library(personal.clone(), out.clone(), None, true, data.clone()).unwrap();
        assert_eq!(personal.tree().folders[0].name, "Imported Share");
        let again = import_document_into_library(personal, out, None, false, data).unwrap();
        assert_eq!((again.connections, again.duplicates.len()), (0, 1), "dedupe");
    }
}
