//! PLUG-02b part 2: starting a plugin view from the app (PLUG-06a part 2 on the Mac).
//!
//! - [`plugin_host_set_helper_path`]: once at app start. Only records the path after checking it
//!   is the helper inside the app's own files; no helper starts.
//! - [`plugin_view_open`]: when a plugin tab opens. Load gate, grants and the pool apply; the
//!   helper's sandbox stays required on macOS and Windows. Call it off the main thread: a cold
//!   open compiles the plugin first (at most 30 s).
//! - [`PluginView`]: `next_update`, `send_event`, `close`. Updates and events are JSON; the event
//!   shapes are listed at `bastion_core::plugin::host::view::event_from_json`.
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bastion_core::plugin::broker::Failure;
use bastion_core::plugin::host::view::{self, EntryBinding, ViewSession, ViewSpec};
use bastion_core::plugin::host::{helper::Timing, helper_path_allowed, Pool};

use crate::policy::effective;
use crate::{FfiError, FfiResult};

/// The one pool of helpers for this app, set by `plugin_host_set_helper_path`.
static POOL: OnceLock<Pool> = OnceLock::new();

/// The longest `next_update` waits, whatever the app asks.
const MAX_WAIT_MS: u32 = 10_000;

pub(crate) fn failure(f: Failure) -> FfiError {
    match f {
        Failure::Denied(m) => FfiError::Failed { message: m, code: "policy".into() },
        Failure::Invalid(m) | Failure::Io(m) => FfiError::Failed { message: m, code: "plugin".into() },
        Failure::TimedOut => FfiError::Failed { message: "timed out".into(), code: "plugin".into() },
    }
}

fn invalid(message: &str) -> FfiError {
    FfiError::Failed { message: message.into(), code: "invalid".into() }
}

/// Where the plugin helper program is. Refused unless it is `bastion-plugin-host` inside the
/// running app's own files (`Contents/Helpers` on the Mac, beside `Bastion.exe` on Windows).
/// Set once; a later call with another path is refused.
#[uniffi::export]
pub fn plugin_host_set_helper_path(path: String) -> FfiResult<()> {
    let exe = std::env::current_exe().map_err(|e| FfiError::Failed { message: e.to_string(), code: "io".into() })?;
    let program = PathBuf::from(&path);
    if !helper_path_allowed(&program, &exe) {
        return Err(invalid("the plugin helper must be inside the app"));
    }
    let program = program.canonicalize().map_err(|e| FfiError::Failed { message: e.to_string(), code: "io".into() })?;
    let pool = POOL.get_or_init(|| Pool::with_program(program.clone(), Timing::DEFAULT));
    if pool.program() != program.as_path() {
        return Err(invalid("the plugin helper is already set"));
    }
    Ok(())
}

/// One of the plugin's own connection-type fields.
#[derive(uniffi::Record, Debug, Clone)]
pub struct PluginField {
    pub key: String,
    pub value: String,
}

/// The library entry a plugin view is opened on.
#[derive(uniffi::Record, Debug, Clone)]
pub struct PluginViewEntry {
    pub document_id: String,
    pub entry_id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub fields: Vec<PluginField>,
    /// The entry's document is protected: plugin storage lasts only as long as the view.
    pub protected: bool,
    /// The environment the entry is in (shown in confirmations), or empty.
    pub environment: String,
}

/// The helper pool, once `plugin_host_set_helper_path` set it.
pub(crate) fn pool() -> FfiResult<&'static Pool> {
    POOL.get().ok_or_else(|| invalid("the plugin helper is not set"))
}

impl PluginView {
    pub(crate) fn from_session(session: ViewSession) -> Arc<PluginView> {
        Arc::new(PluginView { session })
    }
}

/// An open plugin view. Dropping the last reference closes it.
#[derive(uniffi::Object)]
pub struct PluginView {
    session: ViewSession,
}

/// Opens plugin `plugin_id`'s view `view_name` (a connection type's view, a command's view, or
/// `settings`) on `entry`, or on none. `allow_unverified` is the user's setting; `safe_mode` the
/// app's Safe mode. Fails when the helper path is not set.
#[uniffi::export]
pub fn plugin_view_open(data_dir: String, plugin_id: String, view_name: String, entry: Option<PluginViewEntry>, allow_unverified: bool, safe_mode: bool) -> FfiResult<Arc<PluginView>> {
    // The sidebar tree opens only through `plugin_entry_sidebar_open`, which checks the entry's type.
    if view_name == bastion_core::plugin::SIDEBAR_VIEW {
        return Err(FfiError::failed("the sidebar view opens on a library entry".to_string()));
    }
    let pool = pool()?;
    // Fail closed: a managed policy that cannot be read refuses every plugin.
    let policy = effective().map_err(|e| FfiError::Failed { message: e.to_string(), code: "policy".into() })?;
    let entry = entry.map(|e| EntryBinding {
        document_id: e.document_id,
        entry_id: e.entry_id,
        name: e.name,
        host: e.host,
        port: e.port,
        fields: e.fields.into_iter().map(|f| (f.key, f.value)).collect(),
        protected: e.protected,
        environment: e.environment,
        // The entry's TLS settings are not in the app's record yet: the safe defaults
        // (verify-full, no pin, "Allow unencrypted" off) until the property sheet has them.
        tls: Default::default(),
        // The generic opener: the view name decides the type, as before.
        connection_type: String::new(),
    });
    let spec = ViewSpec { data_dir: PathBuf::from(data_dir), plugin_id, view_name, entry, policy, allow_unverified, safe_mode, login: None };
    let session = view::open(pool, spec).map_err(failure)?;
    Ok(PluginView::from_session(session))
}

#[uniffi::export]
impl PluginView {
    /// The next update as JSON, waiting at most `timeout_ms` (10 s at most); `None` when none
    /// came. Types: `set-view`, `patch-view`, `dialog`, `close-dialog`, `mark-errors`,
    /// `provide-rows`, `provide-children`, `provide-completions`, `refuse`, `confirm`, and
    /// `ended` (the last one).
    pub fn next_update(&self, timeout_ms: u32) -> Option<String> {
        let wait = Duration::from_millis(u64::from(timeout_ms.min(MAX_WAIT_MS)));
        self.session.next_update(wait).map(|j| j.to_string())
    }

    /// What the user did, as JSON. Refused when it is not a known event.
    pub fn send_event(&self, json: String) -> FfiResult<()> {
        let value: serde_json::Value = serde_json::from_str(&json).map_err(|e| invalid(&e.to_string()))?;
        self.session.send_event(&value).map_err(failure)
    }

    /// Stops the plugin: `run` gets 2 s to return, then its helper is killed.
    pub fn close(&self) {
        self.session.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_helper_path_outside_the_app_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join(bastion_core::plugin::host::HELPER_PROGRAM);
        std::fs::write(&fake, b"").unwrap();
        assert!(plugin_host_set_helper_path(fake.to_string_lossy().into()).is_err());
        assert!(plugin_host_set_helper_path("/nonexistent/bastion-plugin-host".into()).is_err());
    }

    #[test]
    fn no_view_opens_before_the_helper_path_is_set() {
        let dir = tempfile::tempdir().unwrap();
        let err = plugin_view_open(dir.path().to_string_lossy().into(), "com.example.pg".into(), "settings".into(), None, false, false).err().expect("refused");
        assert!(matches!(err, FfiError::Failed { .. }));
    }
}
