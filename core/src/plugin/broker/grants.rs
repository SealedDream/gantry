//! Permissions checked on every call; one entry per helper; one release per entry per helper
//! (spec section 5; T18.1, T18.2, T18.7, T18.8, T18.16).

use crate::plugin::Permissions;

use super::Failure;

/// What a helper is for. A helper serves exactly one plugin version and at most one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// A helper with no entry, such as one drawing the plugin's settings page. It gets no
    /// network, credential or storage grant.
    NoEntry,
    /// A helper for one library entry, or one Quick connect (each its own temporary entry).
    Entry { entry_id: String, temporary: bool },
}

/// The calls a plugin can make that need a permission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call {
    Connect,
    /// `http.send` (API 1.1).
    Http,
    /// `open.connection` (API 1.2): any protocol the manifest lists.
    Open,
    /// `exec.run` and `exec.terminal` (API 1.5).
    Exec,
    /// `library.propose` (API 1.6).
    LibraryPropose,
    EntryLogin,
    StorageRead,
    StorageWrite,
    ClipboardWrite,
    FileSave,
    FileOpen,
}

/// One helper's grants, as the broker holds them. Built when the helper starts, from the
/// installed manifest and the binding; never from anything the helper says.
#[derive(Debug, Clone)]
pub struct HelperGrants {
    plugin_id: String,
    plugin_version: String,
    permissions: Permissions,
    binding: Binding,
    released: bool,
}

impl HelperGrants {
    pub fn new(plugin_id: &str, plugin_version: &str, permissions: Permissions, binding: Binding) -> HelperGrants {
        HelperGrants { plugin_id: plugin_id.into(), plugin_version: plugin_version.into(), permissions, binding, released: false }
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn binding(&self) -> &Binding {
        &self.binding
    }

    /// The entry this helper serves, if any.
    pub fn entry_id(&self) -> Option<&str> {
        match &self.binding {
            Binding::Entry { entry_id, .. } => Some(entry_id),
            Binding::NoEntry => None,
        }
    }

    /// Whether this helper can serve a view of `plugin_id`@`version` on `entry_id`. A helper
    /// is shared only by views of the same plugin version on the same entry.
    pub fn can_serve(&self, plugin_id: &str, version: &str, entry_id: Option<&str>) -> bool {
        if self.plugin_id != plugin_id || self.plugin_version != version {
            return false;
        }
        match (&self.binding, entry_id) {
            (Binding::Entry { entry_id: mine, temporary: false }, Some(e)) => mine == e,
            // A Quick connect is never shared: each is its own entry.
            (Binding::Entry { temporary: true, .. }, _) => false,
            (Binding::NoEntry, None) => true,
            _ => false,
        }
    }

    /// Check a call against the manifest's permissions and the binding. Called on every call.
    pub fn check(&self, call: Call) -> Result<(), Failure> {
        let p = &self.permissions;
        let (allowed, what) = match call {
            Call::Connect => (p.network_entry, "network"),
            Call::Http => (p.http_entry, "http"),
            Call::Open => (p.opens_any(), "open"),
            Call::Exec => (p.exec_entry, "exec"),
            Call::LibraryPropose => (p.library_propose, "library"),
            Call::EntryLogin => (p.credentials_entry, "credentials"),
            Call::StorageRead | Call::StorageWrite => (p.storage, "storage"),
            Call::ClipboardWrite => (p.clipboard_write, "clipboard"),
            Call::FileSave => (p.files_save, "files"),
            Call::FileOpen => (p.files_open, "files"),
        };
        if !allowed {
            return Err(Failure::Denied(format!("the plugin has no {what} permission")));
        }
        let needs_entry = matches!(call, Call::Connect | Call::Http | Call::Open | Call::LibraryPropose | Call::EntryLogin | Call::StorageRead | Call::StorageWrite);
        if needs_entry && self.entry_id().is_none() {
            return Err(Failure::Denied("this view is not opened on an entry".into()));
        }
        if matches!(call, Call::StorageWrite) {
            if let Binding::Entry { temporary: true, .. } = self.binding {
                return Err(Failure::Denied("a Quick connect has no storage".into()));
            }
        }
        Ok(())
    }

    /// Decide `entry-login`. `login_gate` is the result of
    /// [`super::stream::StreamGate::check_login`] for the stream the login is for, so a release
    /// cannot happen before TLS where TLS is required. `credentials_locked` is the vault state
    /// now. On `Ok`, the caller releases the entry's own login (through the strict release
    /// function and the customer scope check) and writes `credential.release.plugin`; the
    /// helper cannot get a second one, also when the release later fails (fails closed).
    pub fn begin_release(&mut self, login_gate: Result<(), Failure>, credentials_locked: bool) -> Result<(), Failure> {
        self.check(Call::EntryLogin)?;
        login_gate?;
        if credentials_locked {
            return Err(Failure::Denied("credentials are locked".into()));
        }
        if self.released {
            return Err(Failure::Denied("the login was already released to this helper".into()));
        }
        self.released = true;
        Ok(())
    }

    /// Whether this helper holds a released password.
    pub fn holds_release(&self) -> bool {
        self.released
    }
}
