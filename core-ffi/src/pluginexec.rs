//! `exec` (plugin API 1.5; `docs/specs/plugins.md`, section 19), app side.
//!
//! The core's view sends `exec-go`, `exec-cancel` and `exec-terminal` updates with a command it
//! built from a manifest template and checked arguments (`core/src/plugin/host/view_exec.rs`).
//! The app runs that command here, on the plugin entry it opened the view on, over the entry's
//! own SSH login and route, through the same dialer as a terminal (policy, broker, strict host
//! keys, audit), and answers the view with `{"type":"exec",...}`.
//!
//! For `exec-terminal` the app gets a one-connection library ([`Library::plugin_exec_terminal_library`])
//! and opens it like any SSH connection. The command to run in the PTY is held in a registry in
//! this process, keyed by that connection's fresh id: it is never a saved setting, so no library
//! file or import can make a connection run a command on connect.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bastion_core::model::{Connection, Document, Node, Protocol};
use bastion_core::plugin::broker::exec::{MAX_OUTPUT_BYTES, MAX_TIMEOUT};
use bastion_core::pluginentry::plugin_entry_settings;
use uuid::Uuid;

use crate::terminal::{SessionManager, RUNTIME};
use crate::{parse_id, FfiError, FfiResult, Library, SshLogin};

const CANCEL_POLL: Duration = Duration::from_millis(100);
/// Terminal commands waiting for their tab; old ones go first.
const MAX_TERMINAL_COMMANDS: usize = 64;

/// The result of one command, for the app's `{"type":"exec",...}` answer.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct PluginExecResult {
    /// `None` when the command ended without a status, timed out or was cancelled.
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// The app's own words when the command could not run (no login, host key, network).
    pub error: Option<String>,
}

/// A cancel switch for one running command.
#[derive(uniffi::Object, Default)]
pub struct PluginExecCancel {
    flag: AtomicBool,
}

#[uniffi::export]
impl PluginExecCancel {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

/// The SSH connection a plugin entry stands for: the entry's own host, port, login and
/// (inherited) gateway, as an SSH connection. Keeps the entry's id, so the vault rule checks
/// the login against the entry itself.
fn ssh_of_entry(doc: &Document, entry_id: &str) -> FfiResult<Connection> {
    let id = parse_id(entry_id)?;
    let (entry, effective) = plugin_entry_settings(doc, id).ok_or_else(|| FfiError::failed("not a plugin entry".to_string()))?;
    let mut c = entry.clone();
    c.protocol = Protocol::Ssh;
    c.settings = effective;
    if c.settings.port.is_none() {
        c.settings.port = Some(22);
    }
    Ok(c)
}

/// What the plugin learns when the command could not run: a fixed category, never the SSH
/// layer's text, which can name jump hosts, gateway addresses or host-key details (security
/// review, MEDIUM 4). The full text goes to the app's log only.
fn category(e: &str) -> String {
    let l = e.to_ascii_lowercase();
    let c = if l.contains("host key") || l.contains("fingerprint") {
        "host-key: the server's host key is not trusted yet; open an SSH tab to it once"
    } else if l.contains("auth") || l.contains("login") || l.contains("password") || l.contains("credential") || l.contains("permission denied") {
        "login: the SSH login failed"
    } else if l.contains("timed out") || l.contains("timeout") {
        "timeout: the server did not answer in time"
    } else if l.contains("offline") || l.contains("policy") {
        "policy: the connection is not allowed now"
    } else {
        "unreachable: the SSH connection failed"
    };
    eprintln!("bastion: plugin exec failed: {e}");
    c.to_string()
}

fn cut(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_OUTPUT_BYTES)]).into_owned()
}

fn terminal_commands() -> &'static Mutex<Vec<(Uuid, String)>> {
    static R: OnceLock<Mutex<Vec<(Uuid, String)>>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Vec::new()))
}

/// The command a plugin terminal connection runs instead of the login shell, if `id` is one.
pub(crate) fn terminal_command(id: Uuid) -> Option<String> {
    terminal_commands().lock().unwrap_or_else(|e| e.into_inner()).iter().find(|(k, _)| *k == id).map(|(_, v)| v.clone())
}

#[uniffi::export]
impl SessionManager {
    /// Runs `command` (from an `exec-go` update) on plugin entry `entry_id` of `library`, with
    /// `username` and `login` chosen as for an SSH terminal to the entry. Blocks: call it off the
    /// main thread. Ends early when `cancel` is set or `timeout_ms` (at most 120 s) passes.
    #[allow(clippy::too_many_arguments)]
    pub fn plugin_exec(&self, library: Arc<Library>, entry_id: String, username: String, login: SshLogin, command: String, timeout_ms: u64, cancel: Arc<PluginExecCancel>) -> PluginExecResult {
        let failed = |e: String| PluginExecResult { exit: None, stdout: String::new(), stderr: String::new(), error: Some(e) };
        let conn = match ssh_of_entry(&library.lock(), &entry_id) {
            Ok(c) => c,
            Err(e) => return failed(category(&e.to_string())),
        };
        let timeout = Duration::from_millis(timeout_ms).min(MAX_TIMEOUT);
        let session = match self.dial_ssh_to(&library, conn, username, login, None) {
            Ok(s) => s,
            Err(e) => return failed(category(&e.to_string())),
        };
        let result = RUNTIME.block_on(async {
            let watch = async {
                while !cancel.flag.load(Ordering::SeqCst) {
                    tokio::time::sleep(CANCEL_POLL).await;
                }
            };
            tokio::select! {
                r = session.exec(&command) => match r {
                    Ok(out) => PluginExecResult { exit: out.exit_status.map(|c| c as i32), stdout: cut(&out.stdout), stderr: cut(&out.stderr), error: None },
                    Err(e) => failed(category(&e.to_string())),
                },
                _ = tokio::time::sleep(timeout) => failed("the command ran out of time".into()),
                _ = watch => failed("cancelled".into()),
            }
        });
        let _ = RUNTIME.block_on(session.disconnect());
        result
    }
}

#[uniffi::export]
impl Library {
    /// A one-connection library for an `exec-terminal` update, never saved: an SSH connection to
    /// plugin entry `entry_id` (its host, port, login and gateway) whose terminal runs `command`
    /// in a PTY instead of the login shell. Returns the library; its one connection is the tab.
    pub fn plugin_exec_terminal_library(&self, entry_id: String, command: String, label: String) -> FfiResult<Arc<Library>> {
        let doc = self.lock();
        let mut c = ssh_of_entry(&doc, &entry_id)?;
        c.id = Uuid::new_v4();
        if !label.trim().is_empty() {
            c.name = label.chars().filter(|ch| !ch.is_control()).take(128).collect();
        }
        let mut out = Document::new("Plugin terminal");
        out.gateways = doc.gateways.iter().filter(|g| Some(g.id) == c.settings.gateway_id).cloned().collect();
        {
            let mut r = terminal_commands().lock().unwrap_or_else(|e| e.into_inner());
            if r.len() >= MAX_TERMINAL_COMMANDS {
                r.remove(0);
            }
            r.push((c.id, command));
        }
        out.insert(None, Node::Connection(c))?;
        Ok(Arc::new(Library { store: None, doc: Mutex::new(out), document: None, counts_dir: None, revoked: Default::default() }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_reach_the_plugin_only_as_categories() {
        assert!(category("unknown host key for 10.0.0.9 via jump bastion.lab").starts_with("host-key"));
        assert!(category("Authentication failed for root").starts_with("login"));
        assert!(category("connect to 10.0.0.5:22 timed out").starts_with("timeout"));
        assert!(!category("no route to 10.1.2.3").contains("10.1.2.3"));
    }

    #[test]
    fn a_terminal_command_is_found_only_by_its_fresh_id() {
        let id = Uuid::new_v4();
        terminal_commands().lock().unwrap().push((id, "docker exec -it web sh".into()));
        assert_eq!(terminal_command(id).as_deref(), Some("docker exec -it web sh"));
        assert_eq!(terminal_command(Uuid::new_v4()), None);
    }
}
