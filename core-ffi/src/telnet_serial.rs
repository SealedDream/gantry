//! Telnet and serial terminals for the apps (B7, `docs/plans/B7-TELNET-SERIAL.md`).
//!
//! Every open goes through here so the policy check cannot be skipped by a UI: Telnet is refused
//! unless `policy::telnet_allowed` says yes for the user's "Allow Telnet" switch and the managed
//! policy, and the saved password is read only when the connection itself has
//! `telnet_send_password` on.
use std::sync::{Arc, Mutex};

use bastion_core::model::Protocol;
use bastion_core::serial::{SerialSettings, SERIAL_PORT_POLL};
use bastion_core::session::LinkEnd;
use bastion_core::settings::ALLOW_TELNET_SETTING;
use bastion_core::telnet::{AutoLogin, TelnetOptions, TELNET_PORT};
use bastion_core::terminal::{connect_telnet_stream, TerminalSession, PORT_DISCONNECTED};
use bastion_core::vault::{CredentialKind, Secret};
use bastion_core::CoreError;

use crate::settings::SettingsFile;
use crate::terminal::{SessionManager, SshLogin, Terminal, RUNTIME};
use crate::{parse_id, FfiError, FfiResult, Library};

/// What reconnects a Telnet or serial terminal, and how its link last ended.
pub(crate) struct RemoteLink {
    kind: RemoteKind,
    /// `Some(Lost)` after the link dropped, until a reconnect succeeds.
    last_end: Arc<Mutex<Option<LinkEnd>>>,
}

enum RemoteKind {
    /// Host and port only: a reconnect does not type the saved password again.
    Telnet(TelnetOptions),
    Serial,
}

impl RemoteLink {
    fn watch(&self, end: tokio::sync::oneshot::Receiver<LinkEnd>) {
        *self.last_end.lock().unwrap_or_else(|e| e.into_inner()) = None;
        let slot = self.last_end.clone();
        RUNTIME.spawn(async move {
            let ended = end.await.unwrap_or_else(|_| LinkEnd::Lost("connection lost".into()));
            *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(ended);
        });
    }

    /// "Connection lost" / "Port disconnected" after a drop; `None` while connected or after a
    /// normal end.
    pub(crate) fn status(&self) -> Option<String> {
        match &*self.last_end.lock().unwrap_or_else(|e| e.into_inner()) {
            Some(LinkEnd::Lost(_)) => Some(match self.kind {
                RemoteKind::Telnet(_) => "Connection lost".into(),
                RemoteKind::Serial => PORT_DISCONNECTED.into(),
            }),
            _ => None,
        }
    }

    pub(crate) fn reconnect(&self, term: &TerminalSession) -> FfiResult<()> {
        let end = match &self.kind {
            RemoteKind::Telnet(opts) => {
                let stream = RUNTIME.block_on(connect_telnet_stream(opts))?;
                term.reattach_telnet(stream, opts, RUNTIME.handle())?
            }
            RemoteKind::Serial => term.reopen_serial()?,
        };
        self.watch(end);
        Ok(())
    }
}

/// Whether Telnet may be used now: the user's "Allow Telnet" switch under the managed policy.
#[uniffi::export]
pub fn telnet_allowed(settings: Arc<SettingsFile>) -> bool {
    telnet_allowed_for(&settings)
}

#[doc(hidden)]
pub fn telnet_allowed_for(settings: &SettingsFile) -> bool {
    let user = settings.get(ALLOW_TELNET_SETTING.into()).map(|v| v == "true").unwrap_or(false);
    bastion_core::policy::telnet_allowed(user, &crate::policy::effective())
}

/// Why Telnet cannot be turned on, for the disabled switch: the administrator's policy; `None`
/// when the user may decide.
#[uniffi::export]
pub fn telnet_policy_lock() -> Option<String> {
    match crate::policy::effective() {
        Err(_) => Some("Your administrator's policy could not be read, so Telnet is turned off.".into()),
        Ok(p) if p.forbid_legacy || p.denied_protocols.contains(&Protocol::Telnet) => Some("Your administrator turned off Telnet.".into()),
        Ok(_) => None,
    }
}

/// The warning band text for Telnet forms and connection pages.
#[uniffi::export]
pub fn telnet_warning() -> String {
    bastion_core::properties::TELNET_WARNING.into()
}

#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct SerialPortView {
    /// Stored and opened: `/dev/cu.usbserial-A1`, `COM3`.
    pub name: String,
    pub description: String,
    /// `usb`, `pci`, `bluetooth`, `unknown`.
    pub kind: String,
}

/// Serial ports on this machine (may be empty). Call every `serial_port_poll_ms` while a picker
/// is open, off the main thread.
#[uniffi::export]
pub fn list_serial_ports() -> FfiResult<Vec<SerialPortView>> {
    Ok(bastion_core::serial::list_serial_ports()?.into_iter().map(|p| SerialPortView { name: p.name, description: p.description, kind: p.kind }).collect())
}

#[uniffi::export]
pub fn serial_port_poll_ms() -> u32 {
    SERIAL_PORT_POLL.as_millis() as u32
}

/// Baud rates for the picker; any value from 50 to 4000000 may be typed.
#[uniffi::export]
pub fn serial_common_bauds() -> Vec<u32> {
    bastion_core::serial::COMMON_BAUDS.to_vec()
}

impl Terminal {
    pub(crate) fn remote_status(&self) -> Option<String> {
        self.remote.as_ref().and_then(|r| r.status())
    }
}

#[uniffi::export]
impl Terminal {
    /// Open a saved serial connection's port. Fails in words: "Port not found", "COM3 is in use
    /// by another program", "Access to … was refused".
    #[uniffi::constructor]
    pub fn serial_connection(library: Arc<Library>, connection_id: String, cols: u16, rows: u16) -> FfiResult<Arc<Self>> {
        let c = library.resolve(parse_id(&connection_id)?)?;
        if c.protocol != Protocol::Serial {
            return Err(FfiError::failed("not a serial connection".into()));
        }
        crate::policy::effective()?.check_protocol(Protocol::Serial)?;
        let settings = SerialSettings::from_settings(&c.settings)?;
        let (session, end) = TerminalSession::open_serial(&settings, cols, rows)?;
        let remote = RemoteLink { kind: RemoteKind::Serial, last_end: Default::default() };
        remote.watch(end);
        Ok(Arc::new(Terminal::with_remote(session, remote)))
    }

    /// `COM3 · 115200 8N1` for a serial terminal; `None` for other terminals.
    pub fn serial_status(&self) -> Option<String> {
        self.session().serial_status()
    }

    /// Whether this is a Telnet or serial terminal that `reconnect` can bring back.
    pub fn can_reconnect(&self) -> bool {
        self.remote.is_some()
    }

    /// Reconnect a Telnet terminal (same host and port, nothing typed for you) or reopen a serial
    /// port (the Reopen button). The screen and scrollback stay.
    pub fn reconnect(&self) -> FfiResult<()> {
        let remote = self.remote.as_ref().ok_or_else(|| FfiError::failed("this terminal cannot be reconnected here".into()))?;
        remote.reconnect(self.session())
    }
}

#[uniffi::export]
impl SessionManager {
    /// Open a saved Telnet connection. Refused unless Telnet is allowed (`telnet_allowed`). `login`
    /// is used only when the connection itself has "Type the saved password after the login
    /// prompt" on; it must be a password (typed, vault or Vaultwarden), never a key.
    pub fn connect_telnet(&self, library: Arc<Library>, settings: Arc<SettingsFile>, connection_id: String, username: String, login: Option<SshLogin>, cols: u16, rows: u16) -> FfiResult<Arc<Terminal>> {
        self.connect_telnet_with(&library, &settings, &connection_id, username, login, cols, rows)
    }
}

impl SessionManager {
    /// `connect_telnet` for adapters that hold the settings file without an `Arc` (the C ABI).
    #[doc(hidden)]
    #[allow(clippy::too_many_arguments)]
    pub fn connect_telnet_with(&self, library: &Library, settings: &SettingsFile, connection_id: &str, username: String, login: Option<SshLogin>, cols: u16, rows: u16) -> FfiResult<Arc<Terminal>> {
        let id = parse_id(&connection_id)?;
        let c = library.resolve(id)?;
        if c.protocol != Protocol::Telnet {
            return Err(FfiError::failed("not a Telnet connection".into()));
        }
        let user_allows = settings.get(ALLOW_TELNET_SETTING.into()).map(|v| v == "true").unwrap_or(false);
        let policy = crate::policy::effective().map_err(|_| FfiError::from(CoreError::PolicyDenied(telnet_policy_lock().unwrap_or_default())))?;
        bastion_core::policy::with_user_telnet(policy, user_allows).check_protocol(Protocol::Telnet).map_err(|_| {
            FfiError::from(CoreError::PolicyDenied(match telnet_policy_lock() {
                Some(why) => why,
                None => "Telnet is turned off. Turn on Allow Telnet in Settings → Security.".into(),
            }))
        })?;
        // The connection's own opt-in; folders and type defaults cannot turn it on.
        let opted_in = library.lock().resolve(id)?.connection.settings.telnet_send_password == Some(true);
        let auto_login = match (opted_in, login) {
            (true, Some(login)) => Some(self.telnet_login(library, id, username, login)?),
            _ => None,
        };
        let opts = TelnetOptions { auto_login, ..TelnetOptions::new(c.host.clone(), c.settings.port.unwrap_or(TELNET_PORT)) };
        let stream = RUNTIME.block_on(connect_telnet_stream(&opts))?;
        let (session, end) = TerminalSession::attach_telnet(stream, &opts, cols, rows, RUNTIME.handle())?;
        // Reconnects keep host and port only; the password is not kept.
        let remote = RemoteLink { kind: RemoteKind::Telnet(TelnetOptions { auto_login: None, ..opts }), last_end: Default::default() };
        remote.watch(end);
        Ok(Arc::new(Terminal::with_remote(session, remote)))
    }

    fn telnet_login(&self, library: &Library, id: uuid::Uuid, username: String, login: SshLogin) -> FfiResult<AutoLogin> {
        if !self.login_allowed_for(library, &login, id)? {
            return Err(FfiError::failed(crate::credtree::NOT_OFFERED.into()));
        }
        let username = self.login_username_for(&login, username)?;
        let password = match login {
            SshLogin::Password { password } => Secret::new(password),
            SshLogin::Vault { credential_id } => {
                let vault = self.vault_handle().ok_or_else(|| FfiError::failed("the credential vault is not open".into()))?;
                match vault.secret_for(&credential_id)?.0 {
                    CredentialKind::Password { password, .. } => password,
                    CredentialKind::SshKey { .. } => return Err(FfiError::failed("Telnet can only type a password, not an SSH key.".into())),
                }
            }
            SshLogin::Vaultwarden { item_id } => {
                let vw = self.vaultwarden_handle().ok_or_else(|| FfiError::failed("Vaultwarden is not set up".into()))?;
                vw.secret_for(&item_id)?.0
            }
            SshLogin::Provider { reference } => crate::providers::resolve(&reference)?,
            _ => return Err(FfiError::failed("Telnet can only type a password.".into())),
        };
        if username.trim().is_empty() {
            return Err(FfiError::failed("Enter a user name to type at the login prompt.".into()));
        }
        Ok(AutoLogin { username, password })
    }
}

#[cfg(test)]
#[path = "telnet_serial_tests.rs"]
mod tests;
