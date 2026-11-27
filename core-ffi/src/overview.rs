//! Folder overview over FFI (`bastion_core::overview`, DASH-01): the rows of the folder
//! dashboard. Names and states only; no secret and no credential id leaves the core.
use std::path::PathBuf;
use std::sync::Arc;

use bastion_core::connection_history::ConnectionHistory;
use bastion_core::overview::{self, LoginState, OverviewRow, RowKind};

use crate::ui::{icon_view, IconView};
use crate::{parse_id, CredentialVault, FfiResult, Library};

/// One row of a folder's overview: a connection, or a subfolder.
#[derive(uniffi::Record)]
pub struct OverviewRowView {
    pub id: String,
    /// `connection` or `folder`.
    pub kind: String,
    pub name: String,
    /// Host, `host:port` when the port is not the type's default, or the URL. Empty for a folder.
    pub address: String,
    /// Wire name (`ssh`). `None` for a folder and for an entry of a type this app does not
    /// know; `type_label` is then the stored type name, untrusted text for display only.
    pub protocol: Option<String>,
    pub type_label: String,
    /// The user it connects as: its own, else inherited.
    pub username: Option<String>,
    /// `none`, `saved`, `inherited` (from the folder or type `login_from`) or `offered` (saved
    /// for the connection `login_from` on the same host; the user confirms it before use).
    pub login: String,
    pub login_from: Option<String>,
    /// Unix seconds of the last successful connect; format it locally.
    pub last_connected_at: Option<u64>,
    /// "OK", a short one-line error, or `None` before the first attempt.
    pub last_result: Option<String>,
    pub tags: Vec<String>,
    /// Folder names from the folder shown down to the row's parent; empty for a direct child.
    pub folder_path: Vec<String>,
    pub favorite: bool,
    /// The effective host accent, `#rrggbb`.
    pub host_color: Option<String>,
    pub icon: IconView,
}

fn row_view(r: OverviewRow) -> OverviewRowView {
    let (login, login_from) = match r.login {
        LoginState::None => ("none", None),
        LoginState::Saved => ("saved", None),
        LoginState::Inherited { from } => ("inherited", Some(from)),
        LoginState::Offered { from } => ("offered", Some(from)),
    };
    OverviewRowView {
        id: r.id.to_string(),
        kind: match r.kind {
            RowKind::Connection => "connection",
            RowKind::Folder => "folder",
        }
        .into(),
        name: r.name,
        address: r.address,
        protocol: r.protocol.map(|p| p.as_str().to_string()),
        type_label: r.type_label,
        username: r.username,
        login: login.into(),
        login_from,
        last_connected_at: r.last_connected_at,
        last_result: r.last_result,
        tags: r.tags,
        folder_path: r.folder_path,
        favorite: r.favorite,
        host_color: r.host_color,
        icon: icon_view(r.icon),
    }
}

#[uniffi::export]
impl Library {
    /// The rows of `folder_id` for the folder dashboard (the root folder's id for the whole
    /// library). Without `include_subfolders`: its connections, then its folders. With it:
    /// every connection below, in tree order, with `folder_path`, and no folder rows.
    ///
    /// Pass `vault` only while credentials are unlocked. Without it the login state is read
    /// from the library alone (`saved`, `inherited` or `none`) and the vault is not touched,
    /// so opening the page never asks for it. `data_dir` holds the connection history; `None`
    /// leaves the history columns empty. Whether a row is connected is the app's to add.
    pub fn folder_overview(&self, vault: Option<Arc<CredentialVault>>, data_dir: Option<String>, folder_id: String, include_subfolders: bool) -> FfiResult<Vec<OverviewRowView>> {
        let folder = parse_id(&folder_id)?;
        let history = data_dir.map(|d| ConnectionHistory::in_dir(PathBuf::from(d)).all()).unwrap_or_default();
        // Lock order everywhere: Library document, then vault (F10).
        let doc = self.lock();
        let vault = vault.as_ref().map(|v| v.lock());
        let rows = overview::folder_overview(&doc, vault.as_deref(), &history, folder, include_subfolders)?;
        Ok(rows.into_iter().map(row_view).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_core::model::{Connection, Folder, Node, Protocol};
    use bastion_core::vault::{Credential, CredentialKind, Secret};
    use uuid::Uuid;

    const SECRET: &str = "hunter2-do-not-show";

    struct Fixture {
        _dir: tempfile::TempDir,
        data_dir: String,
        lib: Library,
        vault: Arc<CredentialVault>,
        folder: String,
        saved: String,
        offered: String,
    }

    /// Folder "Site" with a connection that has a saved login, one on the same host that has
    /// none, and a subfolder.
    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name).display().to_string();
        let lib = Library::open(path("lib.json")).unwrap();
        let vault = Arc::new(CredentialVault::open_with_key(path("c.vault"), Secret::new("k".repeat(64))).unwrap());
        let credential = Uuid::new_v4();
        vault.lock().add(Credential { id: credential, name: "admin".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "root".into(), password: Secret::new(SECRET) } });
        let mut saved = Connection::new("web ssh", Protocol::Ssh, "web.lan");
        saved.settings.credential_id = Some(credential);
        saved.settings.port = Some(2222);
        saved.settings.username = Some("root".into());
        let offered = Connection::new("web rdp", Protocol::Rdp, "web.lan");
        let (saved_id, offered_id) = (saved.id.to_string(), offered.id.to_string());
        let sub = Folder { id: Uuid::new_v4(), name: "Racks".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() };
        let site = Folder { id: Uuid::new_v4(), name: "Site".into(), color: None, defaults: Default::default(), children: vec![Node::Connection(saved), Node::Folder(sub), Node::Connection(offered)], dynamic_task_id: None, extra: Default::default() };
        let folder = site.id.to_string();
        lib.with_doc(|d| d.insert(None, Node::Folder(site))).unwrap();
        Fixture { data_dir: dir.path().display().to_string(), _dir: dir, lib, vault, folder, saved: saved_id, offered: offered_id }
    }

    fn by_id<'a>(rows: &'a [OverviewRowView], id: &str) -> &'a OverviewRowView {
        rows.iter().find(|r| r.id == id).expect("row")
    }

    #[test]
    fn rows_cross_the_bridge_with_login_state_history_and_no_secret() {
        let f = fixture();
        crate::history::record_connection_success(f.data_dir.clone(), f.saved.clone(), Some("root".into())).unwrap();

        let rows = f.lib.folder_overview(Some(f.vault.clone()), Some(f.data_dir.clone()), f.folder.clone(), false).unwrap();

        let shape: Vec<(&str, &str)> = rows.iter().map(|r| (r.kind.as_str(), r.name.as_str())).collect();
        assert_eq!(shape, [("connection", "web ssh"), ("connection", "web rdp"), ("folder", "Racks")]);
        let saved = by_id(&rows, &f.saved);
        assert_eq!((saved.address.as_str(), saved.protocol.as_deref(), saved.type_label.as_str()), ("web.lan:2222", Some("ssh"), "SSH Terminal"));
        assert_eq!((saved.username.as_deref(), saved.login.as_str(), &saved.login_from), (Some("root"), "saved", &None));
        assert_eq!((saved.icon.id.as_str(), saved.last_result.as_deref()), ("ssh", Some("OK")));
        assert!(saved.last_connected_at.is_some());
        let offered = by_id(&rows, &f.offered);
        assert_eq!((offered.login.as_str(), offered.login_from.as_deref(), offered.last_result.as_deref()), ("offered", Some("web ssh"), None));
        let folder = rows.last().unwrap();
        assert_eq!((folder.protocol.as_deref(), folder.icon.id.as_str(), folder.login.as_str()), (None, "folder", "none"));
        let all: String = rows.iter().map(|r| format!("{} {} {:?} {:?} {:?}", r.name, r.address, r.username, r.login_from, r.last_result)).collect();
        assert!(!all.contains(SECRET));
    }

    #[test]
    fn without_a_vault_the_state_comes_from_the_library_and_nothing_is_offered() {
        let f = fixture();
        let rows = f.lib.folder_overview(None, None, f.folder.clone(), true).unwrap();
        assert_eq!(rows.len(), 2, "subfolders included: connections only");
        assert_eq!(by_id(&rows, &f.saved).login, "saved");
        assert_eq!((by_id(&rows, &f.offered).login.as_str(), by_id(&rows, &f.saved).last_result.as_deref()), ("none", None));
    }

    #[test]
    fn an_unknown_folder_and_a_bad_id_are_errors() {
        let f = fixture();
        assert!(f.lib.folder_overview(None, None, Uuid::new_v4().to_string(), false).is_err());
        assert!(f.lib.folder_overview(None, None, "not-an-id".into(), false).is_err());
    }
}
