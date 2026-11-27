//! Files bridge: one `FilesBrowser` per files tab, over SFTP, SCP (SSH servers without the SFTP
//! subsystem) or FTPS. Calls block on the shared runtime, so the UI calls them off the main
//! thread. With "Reconnect automatically" on, an SSH browser whose connection dropped dials again
//! (brokered leases only, strict host keys) on its next call.
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use bastion_core::ftps::Ftps;
use bastion_core::scp::Scp;
use bastion_core::sftp::{EntryKind, RemoteEntry, Sftp};
use bastion_core::ssh::SshSession;

use crate::terminal::RUNTIME;
use crate::{FfiError, FfiResult};

/// Dials the browser's connection again (the session manager's orchestrator path).
pub(crate) type Redial = Box<dyn Fn() -> FfiResult<SshSession> + Send + Sync>;

/// Called once when the browser goes away, with whether its link was still up and how often
/// it reconnected: the session manager writes the disconnect event and the session's end.
pub(crate) type Closed = Box<dyn FnOnce(bool, u32) + Send + Sync>;

#[derive(uniffi::Record)]
pub struct RemoteFile {
    pub name: String,
    /// `file`, `dir`, `symlink` or `other`.
    pub kind: String,
    pub size: u64,
    pub modified: Option<u32>,
    pub permissions: Option<u32>,
}

/// How files move over an SSH connection.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum SshFiles {
    Sftp,
    Scp,
}

enum Proto {
    Sftp(Sftp),
    Scp,
}

struct Link {
    proto: Proto,
    /// Shared with the terminal when the browser opens on a terminal's connection (Windows).
    ssh: Arc<SshSession>,
}

impl Link {
    fn open(ssh: impl Into<Arc<SshSession>>, kind: SshFiles) -> FfiResult<Link> {
        let ssh = ssh.into();
        let proto = match kind {
            SshFiles::Sftp => Proto::Sftp(RUNTIME.block_on(ssh.open_sftp())?),
            SshFiles::Scp => Proto::Scp,
        };
        Ok(Link { proto, ssh })
    }
}

/// One call's view of the backend.
enum Target<'a> {
    Sftp(&'a Sftp),
    Scp(Scp<'a>),
    Ftps(&'a mut Ftps),
}

impl Target<'_> {
    fn home(&mut self) -> FfiResult<String> {
        Ok(match self {
            Target::Sftp(s) => RUNTIME.block_on(s.canonicalize("."))?,
            Target::Scp(s) => RUNTIME.block_on(s.home())?,
            Target::Ftps(f) => RUNTIME.block_on(f.home())?,
        })
    }

    fn list(&mut self, path: &str) -> FfiResult<Vec<RemoteEntry>> {
        Ok(match self {
            Target::Sftp(s) => RUNTIME.block_on(s.list(path))?,
            Target::Scp(s) => RUNTIME.block_on(s.list(path))?,
            Target::Ftps(f) => RUNTIME.block_on(f.list(path))?,
        })
    }

    fn upload(&mut self, local: &Path, remote: &str, overwrite: bool) -> FfiResult<u64> {
        Ok(match self {
            Target::Sftp(s) => RUNTIME.block_on(s.upload(local, remote, overwrite))?,
            Target::Scp(s) => RUNTIME.block_on(s.upload(local, remote, overwrite))?,
            Target::Ftps(f) => RUNTIME.block_on(f.upload(local, remote, overwrite))?,
        })
    }

    /// `upload`, reporting the bytes sent so far. SFTP reports after every chunk; SCP and FTPS
    /// copy in one call, so they report once, at the end.
    fn upload_progress(&mut self, local: &Path, remote: &str, overwrite: bool, progress: &(dyn Fn(u64) + Sync)) -> FfiResult<u64> {
        if let Target::Sftp(s) = self {
            return Ok(RUNTIME.block_on(s.upload_with_progress(local, remote, overwrite, progress))?);
        }
        let n = self.upload(local, remote, overwrite)?;
        progress(n);
        Ok(n)
    }

    /// `download`, reporting the bytes received so far (per chunk over SFTP, once otherwise).
    fn download_progress(&mut self, remote: &str, local: &Path, overwrite: bool, progress: &(dyn Fn(u64) + Sync)) -> FfiResult<u64> {
        if let Target::Sftp(s) = self {
            return Ok(RUNTIME.block_on(s.download_with_progress(remote, local, overwrite, progress))?);
        }
        let n = self.download(remote, local, overwrite)?;
        progress(n);
        Ok(n)
    }

    fn download(&mut self, remote: &str, local: &Path, overwrite: bool) -> FfiResult<u64> {
        Ok(match self {
            Target::Sftp(s) => RUNTIME.block_on(s.download(remote, local, overwrite))?,
            Target::Scp(s) => RUNTIME.block_on(s.download(remote, local, overwrite))?,
            Target::Ftps(f) => RUNTIME.block_on(f.download(remote, local, overwrite))?,
        })
    }

    fn rename(&mut self, from: &str, to: &str) -> FfiResult<()> {
        Ok(match self {
            Target::Sftp(s) => RUNTIME.block_on(s.rename(from, to))?,
            Target::Scp(s) => RUNTIME.block_on(s.rename(from, to))?,
            Target::Ftps(f) => RUNTIME.block_on(f.rename(from, to))?,
        })
    }

    fn remove(&mut self, path: &str, is_dir: bool) -> FfiResult<u64> {
        Ok(match self {
            Target::Sftp(s) => RUNTIME.block_on(s.remove_tree(path, is_dir))?,
            Target::Scp(s) => {
                RUNTIME.block_on(s.remove(path, is_dir))?;
                1
            }
            Target::Ftps(_) if is_dir => return Err(FfiError::failed("Deleting folders over FTPS is not supported; delete the files inside first.".into())),
            Target::Ftps(f) => {
                bastion_core::sftp::check_removable(path)?;
                RUNTIME.block_on(f.remove_file(path))?;
                1
            }
        })
    }

    fn mkdir(&mut self, path: &str) -> FfiResult<()> {
        Ok(match self {
            Target::Sftp(s) => RUNTIME.block_on(s.mkdir(path))?,
            Target::Scp(s) => RUNTIME.block_on(s.mkdir(path))?,
            Target::Ftps(f) => RUNTIME.block_on(f.mkdir(path))?,
        })
    }
}

enum Backend {
    Ssh { link: Mutex<Link>, kind: SshFiles, redial: Option<Redial> },
    Ftps(Mutex<Ftps>),
}

#[derive(uniffi::Object)]
pub struct FilesBrowser {
    backend: Backend,
    reconnects: AtomicU32,
    closed: Mutex<Option<Closed>>,
}

impl Drop for FilesBrowser {
    fn drop(&mut self) {
        if let Some(closed) = lock(&self.closed).take() {
            closed(self.is_connected(), self.reconnects());
        }
    }
}

impl FilesBrowser {
    #[cfg(test)]
    pub(crate) fn with_sftp_for_tests<T>(&self, f: impl FnOnce(&Sftp) -> T) -> T {
        let Backend::Ssh { link, .. } = &self.backend else { panic!("not SFTP") };
        let link = lock(link);
        let Proto::Sftp(s) = &link.proto else { panic!("not SFTP") };
        f(s)
    }

    /// `redial` is set when the connection reconnects automatically.
    pub(crate) fn open(ssh: impl Into<Arc<SshSession>>, kind: SshFiles, redial: Option<Redial>) -> FfiResult<Arc<Self>> {
        let link = Link::open(ssh, kind)?;
        Ok(Arc::new(FilesBrowser { backend: Backend::Ssh { link: Mutex::new(link), kind, redial }, reconnects: AtomicU32::new(0), closed: Mutex::new(None) }))
    }

    pub(crate) fn ftps(ftps: Ftps) -> Arc<Self> {
        Arc::new(FilesBrowser { backend: Backend::Ftps(Mutex::new(ftps)), reconnects: AtomicU32::new(0), closed: Mutex::new(None) })
    }

    /// What to do when the browser goes away (once).
    pub(crate) fn on_close(&self, closed: Closed) {
        *lock(&self.closed) = Some(closed);
    }

    /// Replace a dropped SSH connection, when allowed. A refused redial (expired lease, changed
    /// host key) is returned as the error, so the user knows to open the browser again.
    fn ensure(&self, link: &mut Link, kind: SshFiles, redial: &Option<Redial>) -> FfiResult<()> {
        let Some(redial) = redial else { return Ok(()) };
        if !link.ssh.is_closed() {
            return Ok(());
        }
        *link = Link::open(redial()?, kind)?;
        self.reconnects.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    /// Run a call; `repeat` says whether it may run again after the link dropped during it (reads
    /// may; a write may already have taken effect, so it is reported instead).
    fn call<T>(&self, repeat: bool, mut f: impl FnMut(&mut Target<'_>) -> FfiResult<T>) -> FfiResult<T> {
        match &self.backend {
            Backend::Ftps(ftps) => f(&mut Target::Ftps(&mut lock(ftps))),
            Backend::Ssh { link, kind, redial } => {
                let mut link = lock(link);
                self.ensure(&mut link, *kind, redial)?;
                let first = f(&mut target(&link));
                match first {
                    Err(e) if redial.is_some() && link.ssh.is_closed() => {
                        self.ensure(&mut link, *kind, redial)?;
                        if repeat {
                            f(&mut target(&link))
                        } else {
                            Err(FfiError::failed(format!("The connection dropped during the operation and was reconnected; check the folder and try again ({e}).")))
                        }
                    }
                    r => r,
                }
            }
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn target(link: &Link) -> Target<'_> {
    match &link.proto {
        Proto::Sftp(s) => Target::Sftp(s),
        Proto::Scp => Target::Scp(Scp::new(&link.ssh)),
    }
}

#[uniffi::export]
impl FilesBrowser {
    /// `sftp`, `scp` or `ftps`, for the tab's title.
    pub fn protocol(&self) -> String {
        match &self.backend {
            Backend::Ssh { kind: SshFiles::Sftp, .. } => "sftp",
            Backend::Ssh { kind: SshFiles::Scp, .. } => "scp",
            Backend::Ftps(_) => "ftps",
        }
        .into()
    }

    pub fn home(&self) -> FfiResult<String> {
        self.call(true, |t| t.home())
    }

    /// How many times the browser reconnected after a drop.
    pub fn reconnects(&self) -> u32 {
        self.reconnects.load(Ordering::SeqCst)
    }

    /// False while an SSH connection is down (it reconnects on the next call when allowed).
    pub fn is_connected(&self) -> bool {
        match &self.backend {
            Backend::Ssh { link, .. } => !lock(link).ssh.is_closed(),
            Backend::Ftps(_) => true,
        }
    }

    pub fn list(&self, path: String) -> FfiResult<Vec<RemoteFile>> {
        let entries = self.call(true, |t| t.list(&path))?;
        Ok(entries
            .into_iter()
            .map(|e| RemoteFile {
                kind: match e.kind {
                    EntryKind::File => "file",
                    EntryKind::Dir => "dir",
                    EntryKind::Symlink => "symlink",
                    EntryKind::Other => "other",
                }
                .into(),
                name: e.name,
                size: e.size,
                modified: e.modified,
                permissions: e.permissions,
            })
            .collect())
    }

    /// Open a remote text file for the editor: JSON `{text, fingerprint: {size, mtime, sha256}}`.
    /// SFTP only; refuses folders, files over 32 MB and files that are not UTF-8.
    pub fn edit_open(&self, path: String) -> FfiResult<String> {
        self.call(true, |t| match t {
            Target::Sftp(s) => {
                let opened = RUNTIME.block_on(bastion_core::remoteedit::open(*s, &path))?;
                let text = String::from_utf8(opened.bytes).map_err(|_| FfiError::failed(format!("{path} is not a text file")))?;
                Ok(serde_json::json!({ "text": text, "fingerprint": opened.fingerprint }).to_string())
            }
            _ => Err(FfiError::failed("Editing remote files needs SFTP on this server.".into())),
        })
    }

    /// Save `text` to `path`. `fingerprint_json` is the one from `edit_open` or the last save
    /// (None for a new file). JSON `{saved: true, fingerprint}` or, when the server copy changed
    /// and `force` is false, `{saved: false, current: fingerprint | null}` with nothing written.
    pub fn edit_save(&self, path: String, text: String, fingerprint_json: Option<String>, force: bool) -> FfiResult<String> {
        use bastion_core::remoteedit::{Fingerprint, SaveOutcome};
        let expected: Option<Fingerprint> = match fingerprint_json {
            Some(j) => Some(serde_json::from_str(&j).map_err(|e| FfiError::failed(format!("bad fingerprint: {e}")))?),
            None => None,
        };
        self.call(false, |t| match t {
            Target::Sftp(s) => Ok(match RUNTIME.block_on(bastion_core::remoteedit::save(*s, &path, expected.as_ref(), text.as_bytes(), force))? {
                SaveOutcome::Saved(f) => serde_json::json!({ "saved": true, "fingerprint": f }),
                SaveOutcome::Conflict(c) => serde_json::json!({ "saved": false, "current": c }),
            }
            .to_string()),
            _ => Err(FfiError::failed("Editing remote files needs SFTP on this server.".into())),
        })
    }

    pub fn upload(&self, local: String, remote: String, overwrite: bool) -> FfiResult<u64> {
        self.call(false, |t| t.upload(Path::new(&local), &remote, overwrite))
    }

    pub fn download(&self, remote: String, local: String, overwrite: bool) -> FfiResult<u64> {
        self.call(false, |t| t.download(&remote, Path::new(&local), overwrite))
    }

    pub fn rename(&self, from: String, to: String) -> FfiResult<()> {
        self.call(false, |t| t.rename(&from, &to))
    }

    pub fn mkdir(&self, path: String) -> FfiResult<()> {
        self.call(false, |t| t.mkdir(&path))
    }

    /// Delete a file or link, or (`is_dir`) a folder with everything in it. Returns the entries
    /// removed (1 for SCP/FTPS). Refuses the root and `.`/`..`; never retried after a drop.
    pub fn remove(&self, path: String, is_dir: bool) -> FfiResult<u64> {
        self.call(false, |t| t.remove(&path, is_dir))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use bastion_core::model::{Connection, Node, Protocol};
    use uuid::Uuid;

    use crate::{FfiError, Library, SessionManager, SshLogin};

    fn library(dir: &std::path::Path, c: Connection) -> (std::sync::Arc<Library>, String) {
        std::fs::create_dir_all(dir).unwrap();
        let lib = std::sync::Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let id = c.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Connection(c))).unwrap();
        (lib, id)
    }

    /// Live: an SCP connection to bastion-sshd browses and transfers over scp (`BASTION_SSH_TEST=1`).
    #[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn scp_connections_get_an_scp_browser() {
        assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
        if std::env::var("BASTION_SSH_TEST").is_err() {
            return eprintln!("SKIPPED scp_connections_get_an_scp_browser: set BASTION_SSH_TEST=1");
        }
        let dir = std::env::temp_dir().join(format!("bastion-ffi-scp-{}", Uuid::new_v4()));
        let mut c = Connection::new("scp-host", Protocol::Scp, "127.0.0.1");
        c.settings.port = Some(2222);
        let (lib, id) = library(&dir, c);
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        let pw = || SshLogin::Password { password: "test-pass-123".into() };
        let fp = match mgr.connect_sftp(lib.clone(), id.clone(), "tester".into(), pw(), None, HashMap::new(), HashMap::new()) {
            Err(FfiError::HostKeyUnknown { fingerprint }) => fingerprint,
            Err(e) => panic!("expected a host-key prompt, got {e}"),
            Ok(_) => panic!("unknown key accepted"),
        };
        let b = mgr.connect_sftp(lib, id, "tester".into(), pw(), Some(fp), HashMap::new(), HashMap::new()).unwrap();
        assert_eq!(b.protocol(), "scp");
        let home = b.home().unwrap();
        let folder = format!("{home}/ffi-scp-{}", Uuid::new_v4().simple());
        b.mkdir(folder.clone()).unwrap();
        let local = dir.join("up.txt");
        std::fs::write(&local, "over scp").unwrap();
        b.upload(local.to_string_lossy().into_owned(), format!("{folder}/up.txt"), false).unwrap();
        assert!(b.list(folder.clone()).unwrap().iter().any(|f| f.name == "up.txt" && f.size == 8));
        let down = dir.join("down.txt");
        b.download(format!("{folder}/up.txt"), down.to_string_lossy().into_owned(), false).unwrap();
        assert_eq!(std::fs::read_to_string(down).unwrap(), "over scp");
        b.rename(format!("{folder}/up.txt"), format!("{folder}/moved.txt")).unwrap();
        std::fs::remove_dir_all(dir).ok();
    }

    /// Live: FTPS through the session manager, certificate pinned on first use
    /// (`BASTION_FTPS_TEST=host:port`, `BASTION_FTPS_PASSWORD`).
    #[ignore = "live: needs BASTION_FTPS_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn ftps_connections_pin_and_browse() {
        assert!(std::env::var_os("BASTION_FTPS_TEST").is_some(), "live test run without BASTION_FTPS_TEST: start the fixture (docs/TESTING.md)");
        let Ok(addr) = std::env::var("BASTION_FTPS_TEST") else {
            return eprintln!("SKIPPED ftps_connections_pin_and_browse: set BASTION_FTPS_TEST");
        };
        let (host, port) = addr.rsplit_once(':').unwrap();
        let dir = std::env::temp_dir().join(format!("bastion-ffi-ftps-{}", Uuid::new_v4()));
        let mut c = Connection::new("ftps-host", Protocol::Ftps, host);
        c.settings.port = port.parse().ok();
        c.settings.username = Some("ftptest".into());
        let (lib, id) = library(&dir, c);
        let mgr = SessionManager::new(dir.to_string_lossy().into_owned()).unwrap();
        let pw = std::env::var("BASTION_FTPS_PASSWORD").unwrap();
        let fp = match mgr.connect_ftps(lib.clone(), id.clone(), String::new(), pw.clone(), None) {
            Err(FfiError::HostKeyUnknown { fingerprint }) => fingerprint,
            Err(e) => panic!("expected a certificate prompt, got {e}"),
            Ok(_) => panic!("unpinned certificate accepted"),
        };
        let b = mgr.connect_ftps(lib, id, String::new(), pw, Some(fp)).unwrap();
        assert_eq!(b.protocol(), "ftps");
        let home = b.home().unwrap();
        assert!(b.list(home).unwrap().iter().any(|f| f.name == "server-file.txt"));
        let audit = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap();
        assert!(audit.contains("ftps.connect"), "sign-ins are audited");
        std::fs::remove_dir_all(dir).ok();
    }
}

/// Transfers with byte progress, for the C ABI (not exported through UniFFI: a Rust closure).
impl FilesBrowser {
    pub fn upload_progress(&self, local: &str, remote: &str, overwrite: bool, progress: &(dyn Fn(u64) + Sync)) -> FfiResult<u64> {
        self.call(false, |t| t.upload_progress(Path::new(local), remote, overwrite, progress))
    }

    pub fn download_progress(&self, remote: &str, local: &str, overwrite: bool, progress: &(dyn Fn(u64) + Sync)) -> FfiResult<u64> {
        self.call(false, |t| t.download_progress(remote, Path::new(local), overwrite, progress))
    }
}
