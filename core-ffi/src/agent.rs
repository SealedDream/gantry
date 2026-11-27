//! Bastion's own SSH agent for the Mac app (`bastion_core::keyagent`): the user adds key files,
//! the agent serves them to `ssh`, `git` and local shells on an owner-only socket, and the app
//! lists them by comment and fingerprint. Private keys stay in Rust; clients cannot add or remove
//! keys. With a confirm handler, every signature asks the app first.
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bastion_core::keyagent::{self, ConfirmFn, KeyAgent};
use bastion_core::keymanager::{self, KeyInfo};
use russh::keys::PrivateKey;
use zeroize::Zeroizing;

use crate::terminal::RUNTIME;
use crate::{FfiError, FfiResult};

/// A private key file larger than this is not a key.
const MAX_KEY_FILE: u64 = 64 * 1024;

/// Asked before each signature on a background thread; may block while a dialog is open.
#[uniffi::export(with_foreign)]
pub trait AgentConfirm: Send + Sync {
    fn allow(&self, comment: String, fingerprint: String) -> bool;
}

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct AgentKeyView {
    pub comment: String,
    /// `SHA256:…`
    pub fingerprint: String,
    pub algorithm: String,
    pub file: String,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct AgentStatus {
    pub running: bool,
    /// For `SSH_AUTH_SOCK`, while running.
    pub socket: Option<String>,
    pub confirm: bool,
    pub keys: Vec<AgentKeyView>,
}

struct Loaded {
    key: PrivateKey,
    info: KeyInfo,
    file: String,
}

#[derive(Default)]
struct Inner {
    keys: Vec<Loaded>,
    running: Option<KeyAgent>,
    confirm: Option<Arc<dyn AgentConfirm>>,
}

/// The app's one agent. It serves only while it holds keys.
#[derive(uniffi::Object)]
pub struct KeyAgentService {
    socket: PathBuf,
    inner: Mutex<Inner>,
}

fn failed(message: impl Into<String>) -> FfiError {
    FfiError::failed(message.into())
}

impl KeyAgentService {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn view(i: &Inner) -> AgentStatus {
        AgentStatus {
            running: i.running.is_some(),
            socket: i.running.as_ref().map(|a| a.socket().display().to_string()),
            confirm: i.confirm.is_some(),
            keys: i.keys.iter().map(|k| AgentKeyView { comment: k.info.comment.clone(), fingerprint: k.info.fingerprint.clone(), algorithm: k.info.algorithm.clone(), file: k.file.clone() }).collect(),
        }
    }

    /// (Re)start with the current keys; stopped when there are none.
    fn restart(&self) -> FfiResult<AgentStatus> {
        let (keys, confirm) = {
            let mut i = self.lock();
            i.running = None;
            if i.keys.is_empty() {
                return Ok(Self::view(&i));
            }
            (i.keys.iter().map(|k| k.key.clone()).collect::<Vec<_>>(), i.confirm.clone())
        };
        #[cfg(unix)]
        if self.socket.exists() {
            // A socket left by a crashed run would block the bind; only this app writes here.
            std::fs::remove_file(&self.socket).map_err(|e| failed(e.to_string()))?;
        }
        let ask: Option<ConfirmFn> = confirm.map(|c| Arc::new(move |comment: &str, fp: &str| c.allow(comment.to_string(), fp.to_string())) as ConfirmFn);
        let running = RUNTIME.block_on(keyagent::start(&self.socket, &keys, ask))?;
        let mut i = self.lock();
        i.running = Some(running);
        Ok(Self::view(&i))
    }
}

fn load_key(path: &Path, passphrase: Option<&str>) -> FfiResult<(PrivateKey, KeyInfo)> {
    if std::fs::metadata(path).map_err(|e| failed(e.to_string()))?.len() > MAX_KEY_FILE {
        return Err(failed("Not a private key file (too large)"));
    }
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|_| failed("Not a private key file"))?);
    let info = keymanager::inspect(&text, passphrase)?;
    Ok((keymanager::load(&text, passphrase)?, info))
}

#[uniffi::export]
impl KeyAgentService {
    /// `<data_dir>/agent/agent.sock`, its folder mode 700. Nothing is served until a key is added.
    #[uniffi::constructor]
    pub fn new(data_dir: String) -> FfiResult<Arc<Self>> {
        let dir = Path::new(&data_dir).join("agent");
        std::fs::create_dir_all(&dir).map_err(|e| failed(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| failed(e.to_string()))?;
        }
        Ok(Arc::new(KeyAgentService { socket: dir.join("agent.sock"), inner: Mutex::new(Inner::default()) }))
    }

    pub fn status(&self) -> AgentStatus {
        Self::view(&self.lock())
    }

    /// Whether the key file needs a passphrase (so the app can ask before `add_key_file`).
    pub fn needs_passphrase(&self, path: String) -> bool {
        std::fs::read_to_string(&path).is_ok_and(|t| keymanager::inspect(&t, None).is_err_and(|e| e.to_string().contains("encrypted")))
    }

    /// Add a key file (OpenSSH, PEM or `.ppk`) and (re)start serving. Security-key `sk-` keys and
    /// a key already added are refused.
    pub fn add_key_file(&self, path: String, passphrase: Option<String>) -> FfiResult<AgentStatus> {
        let pass = passphrase.filter(|p| !p.is_empty()).map(Zeroizing::new);
        let (key, info) = load_key(Path::new(&path), pass.as_deref().map(String::as_str))?;
        if info.hardware {
            return Err(failed("Security-key (sk-) keys sign through the system agent, not Gantry's"));
        }
        {
            let mut i = self.lock();
            if i.keys.iter().any(|k| k.info.fingerprint == info.fingerprint) {
                return Err(failed(format!("{} is already in the agent", info.comment)));
            }
            i.keys.push(Loaded { key, info, file: path });
        }
        self.restart()
    }

    pub fn remove_key(&self, fingerprint: String) -> FfiResult<AgentStatus> {
        self.lock().keys.retain(|k| k.info.fingerprint != fingerprint);
        self.restart()
    }

    /// `Some` asks the handler before every signature ("Confirm each use"); `None` signs freely.
    pub fn set_confirm(&self, handler: Option<Arc<dyn AgentConfirm>>) -> FfiResult<AgentStatus> {
        self.lock().confirm = handler;
        self.restart()
    }

    /// Stop serving and forget every key.
    pub fn stop(&self) -> AgentStatus {
        let mut i = self.lock();
        i.keys.clear();
        i.running = None;
        Self::view(&i)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn write_key(dir: &Path) -> String {
        let k = keymanager::generate_ed25519("agent-test", None).unwrap();
        let path = dir.join("id_test");
        std::fs::write(&path, k.private_openssh.as_bytes()).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn lists_added_keys_serves_while_it_has_them_and_refuses_duplicates() {
        let d = tempfile::tempdir().unwrap();
        let a = KeyAgentService::new(d.path().to_string_lossy().into_owned()).unwrap();
        assert!(!a.status().running);
        let key = write_key(d.path());
        assert!(!a.needs_passphrase(key.clone()));
        let s = a.add_key_file(key.clone(), None).unwrap();
        assert!(s.running && s.socket.is_some());
        assert_eq!(s.keys.len(), 1);
        assert!(s.keys[0].fingerprint.starts_with("SHA256:"));
        assert!(a.add_key_file(key, None).is_err(), "duplicate");
        let fp = s.keys[0].fingerprint.clone();
        let s = a.remove_key(fp).unwrap();
        assert!(!s.running && s.keys.is_empty());
        assert!(a.add_key_file(d.path().join("nope").to_string_lossy().into_owned(), None).is_err());
        assert!(a.stop().keys.is_empty());
    }
}
