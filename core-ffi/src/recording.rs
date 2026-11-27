//! What the bridge records in the activity store (`bastion_core::activity`) for the sessions
//! it opens itself, and with what. Metadata only: no secret reaches this module's records.
//!
//! Recorded: interactive SSH terminals and file sessions (SFTP, SCP, FTPS). Not recorded:
//! tasks, multi-host exec, tunnels, system views, gateway routes, local shells and Mosh.
//!
//! With the setting `logging.activity-enabled` off there is no sink, so nothing is written
//! and the audit records carry no session id.
use std::path::Path;

use bastion_core::activity::{self, App, EndReason, FolderRef, LoginSource, SessionEnd, SessionId, SessionStart};
use bastion_core::connect::ActivitySink;
use bastion_core::logins::{self, LoginPurpose, LoginSource as Candidate};
use bastion_core::model::{Connection, Document};
use bastion_core::CoreError;
use uuid::Uuid;

use crate::terminal::SshLogin;
use crate::{CredentialVault, Library};

/// The app this bridge runs in: the UniFFI bindings serve Native Mac, the C ABI Native Windows.
pub(crate) fn app() -> App {
    if cfg!(windows) {
        App::NativeWindows
    } else {
        App::NativeMac
    }
}

/// The folders from the library root down to `connection`, root first, as they are now. The
/// root itself is left out.
pub(crate) fn folder_path(doc: &Document, connection: Uuid) -> Vec<FolderRef> {
    let mut path = Vec::new();
    let mut at = doc.parent_of(connection);
    while let Some(id) = at {
        let Some(folder) = doc.folder(id).filter(|f| f.id != doc.root.id) else { break };
        path.push(FolderRef { id, name: folder.name.clone() });
        if path.len() >= activity::MAX_FOLDER_DEPTH {
            break;
        }
        at = doc.parent_of(id);
    }
    path.reverse();
    path
}

/// The source of a login the user typed or picked outside the vault; `None` for a saved one.
pub(crate) fn typed_login_source(login: &SshLogin) -> Option<LoginSource> {
    match login {
        SshLogin::Password { .. } | SshLogin::PasswordAndCode { .. } => Some(LoginSource::Typed),
        SshLogin::KeyFile { .. } => Some(LoginSource::Key),
        SshLogin::Agent => Some(LoginSource::Agent),
        SshLogin::Vault { .. } | SshLogin::Vaultwarden { .. } | SshLogin::Provider { .. } => None,
    }
}

/// The source of a saved login, from where the shared resolver lists it for the connection.
pub(crate) fn saved_login_source(candidate: Option<&Candidate>) -> LoginSource {
    match candidate {
        Some(Candidate::Inherited { .. }) => LoginSource::Inherited,
        Some(Candidate::SameHost { .. }) => LoginSource::SameHost,
        Some(Candidate::Default | Candidate::Connection | Candidate::Named) | None => LoginSource::Own,
    }
}

/// Where the login of a connect comes from. Only the kind of login is looked at, never its
/// secret.
pub(crate) fn login_source(login: &SshLogin, library: &Library, vault: Option<&CredentialVault>, connection: Uuid) -> LoginSource {
    if let Some(source) = typed_login_source(login) {
        return source;
    }
    let (SshLogin::Vault { credential_id }, Some(vault)) = (login, vault) else { return LoginSource::Own };
    let Ok(credential) = credential_id.parse::<Uuid>() else { return LoginSource::Own };
    let doc = library.lock();
    let vault = vault.lock();
    let found = logins::login_candidates(&doc, &vault, connection, LoginPurpose::Any).ok().and_then(|list| list.into_iter().find(|c| c.credential == credential));
    saved_login_source(found.as_ref().map(|c| &c.source))
}

/// Where a connect to `connection` is recorded, or `None` while the history is off.
pub(crate) fn sink(data_dir: &Path, library: &Library, connection: Uuid, login_source: LoginSource) -> Option<ActivitySink> {
    if !crate::activity::is_enabled(data_dir) {
        return None;
    }
    let log = crate::activity::log(data_dir);
    log.set_enabled(true);
    let folder_path = folder_path(&library.lock(), connection);
    Some(ActivitySink { log, folder_path, login_source, app: app(), app_version: crate::app_version(), device_name: activity::device_name() })
}

/// Write the start of a session the orchestrator does not make (FTPS). A failed write is
/// reported on stderr and never blocks the connect, like the orchestrator's.
pub(crate) fn begin(sink: &ActivitySink, conn: &Connection, port: u16, username: &str) -> Option<SessionId> {
    let start = SessionStart {
        connection_id: conn.id,
        connection_name: conn.name.clone(),
        folder_path: sink.folder_path.clone(),
        protocol: conn.protocol.as_str().into(),
        host: conn.host.clone(),
        port: Some(port),
        username: Some(username.to_string()),
        route: Vec::new(),
        login_source: sink.login_source,
        started_at: activity::now_ms(),
        app: sink.app,
        app_version: sink.app_version.clone(),
        device_name: sink.device_name.clone(),
    };
    sink.log.begin(start).map_err(|e| eprintln!("bastion: activity log write failed: {e}")).ok()
}

/// Write the end of a session begun with [`begin`].
pub(crate) fn end(sink: &ActivitySink, session: SessionId, connected_at: Option<u64>, reason: EndReason) {
    let end = SessionEnd { connected_at, ended_at: activity::now_ms(), end_reason: reason, reconnects: None, transcript_path: None, transcript_sha256: None };
    if let Err(e) = sink.log.end(session, end) {
        eprintln!("bastion: activity log write failed: {e}");
    }
}

/// The end reason a failed sign-in is recorded with (the orchestrator's rule for SSH).
pub(crate) fn end_reason_for(e: &CoreError) -> EndReason {
    match e {
        CoreError::AuthFailed | CoreError::TwoFactorRequired => EndReason::AuthFailed,
        CoreError::HostKeyUnknown { .. } | CoreError::JumpHostKeyUnknown { .. } | CoreError::HostKeyChanged { .. } => EndReason::HostKey,
        CoreError::Timeout => EndReason::Timeout,
        CoreError::Offline(_) => EndReason::NetworkLost,
        CoreError::Cancelled => EndReason::ClosedByUser,
        _ => EndReason::Failed,
    }
}

/// An end reason as the audit log spells it (`closed_by_user`, …), as in `ssh.disconnect`.
pub(crate) fn reason_text(reason: EndReason) -> String {
    serde_json::to_value(reason).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}
