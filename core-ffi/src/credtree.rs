//! Credentials section of the tree over FFI (`bastion_core::credtree`): folders and named
//! credentials in the one vault, hosts or folders pointing at ONE credential, delete-in-use
//! warnings. Views carry names, usernames and kinds only; no secret leaves the core.
use std::sync::Arc;

use bastion_core::credtree::{self, CredentialTreeFolder, CredentialUsage};
use bastion_core::logins::{self, LoginPurpose, LoginSource};
use bastion_core::vault::CredentialKind;

use crate::{parse_id, CredentialVault, FfiResult, Library, RdpSavedLogin};

/// The refusal for a saved login the shared rule does not list for the connection.
pub(crate) const NOT_OFFERED: &str = "that login is not offered for this connection";

impl CredentialVault {
    /// The one gate in this bridge for giving a saved credential to a connection: whether the
    /// shared rule (`logins::may_use`) lists `credential` for the first of `connections` (the
    /// connect target) or for a later one (a jump host on its route). The target must be a
    /// library entry; a later id that is not one (a gateway, a literal ProxyJump host) has no
    /// logins of its own and counts as no.
    pub(crate) fn may_use_any(&self, library: &Library, connections: &[uuid::Uuid], credential: uuid::Uuid, purpose: LoginPurpose) -> FfiResult<bool> {
        let doc = library.lock();
        let vault = self.lock();
        let Some((target, hops)) = connections.split_first() else { return Ok(false) };
        if logins::may_use(&doc, &vault, *target, credential, purpose)? {
            return Ok(true);
        }
        // Fail closed: a hop whose `may_use` is an error (not a library entry, an entry of
        // an unknown type) is treated as "not allowed", never as a reason to let it through.
        Ok(hops.iter().any(|hop| logins::may_use(&doc, &vault, *hop, credential, purpose).unwrap_or(false)))
    }

    /// Whether a connect to the first of `connections` (through the others as jump hosts) may
    /// read the saved credential `credential`: the inline secret of one of those connections
    /// (it is stored under its connection's id and is private to it), or a login the shared
    /// rule lists for one of them.
    pub(crate) fn may_connect_with(&self, library: &Library, connections: &[uuid::Uuid], credential: uuid::Uuid) -> FfiResult<bool> {
        if connections.contains(&credential) && self.lock().inline(credential).is_some() {
            return Ok(true);
        }
        self.may_use_any(library, connections, credential, LoginPurpose::Any)
    }

    /// Whether a path with no step where the user confirms a login (`rdp_login_for`, Test
    /// Connection) may read the saved credential `credential` for `connection`: the
    /// connection's own inline secret, or a login the shared rule lets it use without asking
    /// (`auto_use`). A login that is only offered (saved for another connection of the same
    /// machine, or named by an imported library) needs the user's yes, which only the connect
    /// sheets and `release_login` carry (A1-CORE-01-FU3). Reads no secret.
    pub(crate) fn may_use_unasked(&self, library: &Library, connection: uuid::Uuid, credential: uuid::Uuid, purpose: LoginPurpose) -> FfiResult<bool> {
        let doc = library.lock();
        let vault = self.lock();
        if connection == credential && vault.inline(credential).is_some() {
            return Ok(true);
        }
        Ok(logins::login_candidates(&doc, &vault, connection, purpose)?.iter().any(|c| c.auto_use && c.credential == credential))
    }
}

/// One row of the Credentials section, flattened: folders first, then credentials, each sorted
/// by name within its parent. Apps nest rows by `parent`.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct CredentialTreeItemView {
    pub id: String,
    pub name: String,
    /// Containing folder; `None` at the section root.
    pub parent: Option<String>,
    pub is_folder: bool,
    /// Empty for a folder.
    pub username: String,
    /// `folder`, `password` or `ssh-key`.
    pub kind: String,
}

/// One login a connection can use (no secret). `source`: `default`, `connection`, `named` (the
/// saved credential the connection names), `inherited` (from folder `source_id`, or the type
/// default when `None`) or `same-host` (saved for connection `source_id`).
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct LoginCandidateView {
    pub credential_id: String,
    pub name: String,
    pub username: String,
    /// `password` or `ssh-key`.
    pub kind: String,
    pub source: String,
    pub source_id: Option<String>,
    pub source_name: String,
    /// `true`: the connection's own or inherited login, connect with it without asking.
    /// `false` (`same-host`): saved for another connection; offer it and let the user confirm.
    pub auto_use: bool,
}

/// A host or folder of the library that points straight at a credential.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct CredentialUsageView {
    pub node_id: String,
    pub name: String,
    pub is_folder: bool,
    /// Library folder names from the root down to the node's parent.
    pub path: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct CredentialRemoveView {
    /// False when the credential is in use and `force` was not set: nothing changed.
    pub removed: bool,
    pub users: Vec<CredentialUsageView>,
}

/// The credential a host ends up with and the node (the host or a folder) that sets it.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct EffectiveCredentialView {
    pub credential_id: String,
    pub source_id: String,
    pub inherited: bool,
}

fn usage(u: CredentialUsage) -> CredentialUsageView {
    CredentialUsageView { node_id: u.node_id.to_string(), name: u.name, is_folder: u.is_folder, path: u.path }
}

/// Depth-first rows: under each parent, its folders (each followed by its contents), then its credentials.
fn flatten(f: CredentialTreeFolder, out: &mut Vec<CredentialTreeItemView>) {
    let parent = f.id.map(|id| id.to_string());
    for sub in f.folders {
        let id = sub.id.map(|id| id.to_string()).unwrap_or_default();
        out.push(CredentialTreeItemView { id, name: sub.name.clone(), parent: parent.clone(), is_folder: true, username: String::new(), kind: "folder".into() });
        flatten(sub, out);
    }
    for c in f.credentials {
        out.push(CredentialTreeItemView { id: c.id.to_string(), name: c.name, parent: parent.clone(), is_folder: false, username: c.username, kind: c.kind.into() });
    }
}

fn opt_id(id: Option<String>) -> FfiResult<Option<uuid::Uuid>> {
    id.filter(|s| !s.trim().is_empty()).as_deref().map(parse_id).transpose()
}

#[uniffi::export]
impl CredentialVault {
    /// The whole Credentials section as flat rows (see [`CredentialTreeItemView`]).
    pub fn tree_items(&self) -> Vec<CredentialTreeItemView> {
        let tree = self.lock().credential_tree();
        let mut rows = Vec::new();
        flatten(tree, &mut rows);
        rows
    }

    pub fn add_folder(&self, name: String, parent: Option<String>) -> FfiResult<String> {
        let parent = opt_id(parent)?;
        Ok(self.lock().add_folder(&name, parent)?.to_string())
    }

    pub fn rename_folder(&self, id: String, name: String) -> FfiResult<()> {
        Ok(self.lock().rename_folder(parse_id(&id)?, &name)?)
    }

    pub fn move_folder(&self, id: String, parent: Option<String>) -> FfiResult<()> {
        let parent = opt_id(parent)?;
        Ok(self.lock().move_folder(parse_id(&id)?, parent)?)
    }

    /// Delete an empty folder; a folder that still holds anything is refused.
    pub fn remove_folder(&self, id: String) -> FfiResult<()> {
        Ok(self.lock().remove_folder(parse_id(&id)?)?)
    }

    pub fn rename_credential(&self, id: String, name: String) -> FfiResult<()> {
        Ok(self.lock().rename_credential(parse_id(&id)?, &name)?)
    }

    /// Put a credential in a folder (`None`: the section root).
    pub fn move_credential(&self, id: String, folder: Option<String>) -> FfiResult<()> {
        let folder = opt_id(folder)?;
        Ok(self.lock().move_credential(parse_id(&id)?, folder)?)
    }

    /// Hosts and folders of `library` that point straight at the credential.
    pub fn credential_users(&self, library: Arc<Library>, id: String) -> FfiResult<Vec<CredentialUsageView>> {
        let id = parse_id(&id)?;
        Ok(credtree::credential_usages(&library.lock(), id).into_iter().map(usage).collect())
    }

    /// Delete a credential. In use and `force` false: nothing changes and the users come back
    /// so the app can warn and list them. With `force` those hosts and folders inherit again;
    /// save both the vault and the library afterwards.
    pub fn remove_checked(&self, library: Arc<Library>, id: String, force: bool) -> FfiResult<CredentialRemoveView> {
        let id = parse_id(&id)?;
        let mut doc = library.lock();
        let out = self.lock().remove_checked(&mut doc, id, force)?;
        Ok(CredentialRemoveView { removed: out.removed, users: out.users.into_iter().map(usage).collect() })
    }

    /// Point a host or folder of `library` at ONE saved credential, or with `None` let it
    /// inherit. Save the library afterwards.
    pub fn assign_credential(&self, library: Arc<Library>, node_id: String, credential_id: Option<String>) -> FfiResult<()> {
        let node = parse_id(&node_id)?;
        let cred = opt_id(credential_id)?;
        // Lock order everywhere: Library document, then vault (F10).
        let mut doc = library.lock();
        let vault = self.lock();
        Ok(credtree::assign_credential(&mut doc, &vault, node, cred)?)
    }

    /// Which credential a host connects with and where it comes from; `None` if nothing sets one.
    pub fn effective_credential(&self, library: Arc<Library>, connection_id: String) -> FfiResult<Option<EffectiveCredentialView>> {
        let conn = parse_id(&connection_id)?;
        Ok(credtree::effective_credential(&library.lock(), conn).map(|(c, src)| EffectiveCredentialView {
            credential_id: c.to_string(),
            source_id: src.to_string(),
            inherited: src != conn,
        }))
    }

    // MARK: Logins (owner point W23): one ordered list per connection, see `bastion_core::logins`.

    /// The logins a connection can use, best first: its default, its other logins, the credential
    /// it names, the inherited one (all `auto_use`), then logins saved for other connections on
    /// the same host, route and folder scope, which are only offered. `passwords_only` for RDP.
    pub fn login_candidates(&self, library: Arc<Library>, connection_id: String, passwords_only: bool) -> FfiResult<Vec<LoginCandidateView>> {
        let conn = parse_id(&connection_id)?;
        let doc = library.lock();
        let vault = self.lock();
        let purpose = if passwords_only { LoginPurpose::Password } else { LoginPurpose::Any };
        Ok(logins::login_candidates(&doc, &vault, conn, purpose)?
            .into_iter()
            .filter_map(|c| {
                let cred = vault.get(c.credential)?;
                let (username, kind) = match &cred.kind {
                    CredentialKind::Password { username, .. } => (username.clone(), "password"),
                    CredentialKind::SshKey { username, .. } => (username.clone(), "ssh-key"),
                };
                let (source, source_id, source_name) = match c.source {
                    LoginSource::Default => ("default", None, String::new()),
                    LoginSource::Connection => ("connection", None, String::new()),
                    LoginSource::Named => ("named", None, String::new()),
                    LoginSource::Inherited { folder, name } => ("inherited", folder.map(|f| f.to_string()), name),
                    LoginSource::SameHost { connection, name } => ("same-host", Some(connection.to_string()), name),
                };
                Some(LoginCandidateView {
                    credential_id: c.credential.to_string(),
                    name: cred.name.clone(),
                    username,
                    kind: kind.into(),
                    source: source.into(),
                    source_id,
                    source_name,
                    auto_use: c.auto_use,
                })
            })
            .collect())
    }

    /// Add a saved credential to a connection's logins (the default when it has none). Save the library.
    pub fn add_login(&self, library: Arc<Library>, connection_id: String, credential_id: String) -> FfiResult<()> {
        let (conn, cred) = (parse_id(&connection_id)?, parse_id(&credential_id)?);
        let mut doc = library.lock();
        let vault = self.lock();
        Ok(logins::add_login(&mut doc, &vault, conn, cred)?)
    }

    /// Remove a login from a connection; the credential stays in the vault. Save the library.
    pub fn remove_login(&self, library: Arc<Library>, connection_id: String, credential_id: String) -> FfiResult<bool> {
        let (conn, cred) = (parse_id(&connection_id)?, parse_id(&credential_id)?);
        Ok(logins::remove_login(&mut library.lock(), conn, cred)?)
    }

    /// Make a login the connection's default. Save the library.
    pub fn set_default_login(&self, library: Arc<Library>, connection_id: String, credential_id: String) -> FfiResult<()> {
        let (conn, cred) = (parse_id(&connection_id)?, parse_id(&credential_id)?);
        let mut doc = library.lock();
        let vault = self.lock();
        Ok(logins::set_default_login(&mut doc, &vault, conn, cred)?)
    }

    /// The password of one of the connection's password logins, for the in-process RDP client.
    /// Refuses a credential outside that connection's login list; every release is audited.
    pub fn release_login(&self, library: Arc<Library>, connection_id: String, credential_id: String) -> FfiResult<RdpSavedLogin> {
        let (conn, cred) = (parse_id(&connection_id)?, parse_id(&credential_id)?);
        if !self.may_use_any(&library, &[conn], cred, LoginPurpose::Password)? {
            return Err(crate::FfiError::failed(NOT_OFFERED.into()));
        }
        let login = {
            let vault = self.lock();
            match vault.get(cred).map(|c| &c.kind) {
                Some(CredentialKind::Password { username, password }) => RdpSavedLogin { username: username.clone(), password: password.expose().to_string() },
                _ => return Err(crate::FfiError::failed("that login is not a password".into())),
            }
        };
        self.audit("credential.release.rdp", &connection_id, "password")?;
        Ok(login)
    }
}

impl CredentialVault {
    /// Rust hosts that keep their own `Document` (the Tauri app) run `bastion_core::credtree`
    /// against the open vault through this. Never hand a secret out of `f`.
    pub fn with_vault<T>(&self, f: impl FnOnce(&mut bastion_core::vault::Vault) -> T) -> T {
        f(&mut self.lock())
    }
}
