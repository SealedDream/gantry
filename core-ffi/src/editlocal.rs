//! Edit-locally bridge over core `filepanel` (#149): an owner-only copy folder per session and a
//! watcher that reports saved copies so the app queues an upload. Change is by size + SHA-256.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bastion_core::filepanel::{self, EditWatcher};

use crate::{FfiError, FfiResult};

/// One watched copy: where it lives locally and the remote file it uploads to.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct EditCopyView {
    pub local: String,
    pub remote: String,
}

/// Result of one poll: copies saved since the last poll, and copies deleted or unreadable
/// (no longer watched).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct EditPollView {
    pub changed: Vec<EditCopyView>,
    pub gone: Vec<EditCopyView>,
}

#[derive(uniffi::Object)]
pub struct EditLocalModel {
    dir: PathBuf,
    watcher: Mutex<EditWatcher>,
}

fn view(c: &filepanel::EditCopy) -> EditCopyView {
    EditCopyView { local: c.local.to_string_lossy().into_owned(), remote: c.remote.clone() }
}

impl EditLocalModel {
    fn lock(&self) -> FfiResult<std::sync::MutexGuard<'_, EditWatcher>> {
        self.watcher.lock().map_err(|_| FfiError::failed("edit watcher poisoned".into()))
    }
}

#[uniffi::export]
impl EditLocalModel {
    /// Copies for `session` (letters, digits, `-`) live in `<base>/edit-locally/<session>`, mode 0700.
    #[uniffi::constructor]
    pub fn new(base: String, session: String) -> FfiResult<Arc<Self>> {
        let dir = filepanel::edit_dir(Path::new(&base), &session)?;
        Ok(Arc::new(Self { dir, watcher: Mutex::new(EditWatcher::new()) }))
    }

    /// Local path a remote file is downloaded to (file name only; never escapes the folder).
    pub fn local_path(&self, remote: String) -> FfiResult<String> {
        Ok(filepanel::edit_path(&self.dir, &remote)?.to_string_lossy().into_owned())
    }

    /// Start watching a freshly downloaded copy. Files over the edit size limit are refused.
    pub fn watch(&self, local: String, remote: String) -> FfiResult<()> {
        Ok(self.lock()?.watch(Path::new(&local), &remote)?)
    }

    pub fn unwatch(&self, local: String) -> bool {
        self.lock().map(|mut w| w.unwatch(Path::new(&local))).unwrap_or(false)
    }

    pub fn watched(&self) -> Vec<EditCopyView> {
        self.lock().map(|w| w.watched().map(view).collect()).unwrap_or_default()
    }

    pub fn poll(&self) -> EditPollView {
        match self.lock() {
            Ok(mut w) => {
                let (changed, gone) = w.poll();
                EditPollView { changed: changed.iter().map(view).collect(), gone: gone.iter().map(view).collect() }
            }
            Err(_) => EditPollView { changed: vec![], gone: vec![] },
        }
    }
}

/// Remote folder from an OSC 7 payload, `None` unless it is a plain absolute path.
#[uniffi::export]
pub fn parse_osc7_path(payload: String) -> Option<String> {
    filepanel::parse_osc7(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_copy_reports_saves_and_deletes() {
        let base = tempfile::tempdir().unwrap();
        let m = EditLocalModel::new(base.path().to_string_lossy().into(), "s-1".into()).unwrap();
        let local = m.local_path("/etc/../srv/app.conf".into()).unwrap();
        assert!(std::path::Path::new(&local).ends_with(std::path::Path::new("edit-locally").join("s-1").join("app.conf")), "{local}");
        std::fs::write(&local, "a").unwrap();
        m.watch(local.clone(), "/srv/app.conf".into()).unwrap();
        assert!(m.poll().changed.is_empty());
        std::fs::write(&local, "b").unwrap();
        let p = m.poll();
        assert_eq!(p.changed, vec![EditCopyView { local: local.clone(), remote: "/srv/app.conf".into() }]);
        assert!(m.poll().changed.is_empty());
        std::fs::remove_file(&local).unwrap();
        assert_eq!(m.poll().gone.len(), 1);
        assert!(m.watched().is_empty());
    }

    #[test]
    fn bad_session_and_names_are_refused() {
        let base = tempfile::tempdir().unwrap();
        assert!(EditLocalModel::new(base.path().to_string_lossy().into(), "../x".into()).is_err());
        let m = EditLocalModel::new(base.path().to_string_lossy().into(), "ok".into()).unwrap();
        assert!(m.local_path("/srv/..".into()).is_err());
        assert!(m.local_path("/srv/".into()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn folder_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let base = tempfile::tempdir().unwrap();
        let m = EditLocalModel::new(base.path().to_string_lossy().into(), "p".into()).unwrap();
        let mode = std::fs::metadata(&m.dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn osc7_paths() {
        assert_eq!(parse_osc7_path("file://h/home/me%20x".into()).as_deref(), Some("/home/me x"));
        assert_eq!(parse_osc7_path("http://h/x".into()), None);
    }
}
