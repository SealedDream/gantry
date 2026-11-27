//! Folder actions over FFI (B4): the plan for Connect All (`bastion_core::actions`). Ids and
//! counts only; no secret leaves the core and nothing is connected here.
use std::sync::Arc;

use bastion_core::actions;
use uuid::Uuid;

use crate::{parse_id, CredentialVault, FfiResult, Library};

/// What Connect All on a folder does with each connection in it and in its subfolders, in tree
/// order. Every connection is in exactly one list.
#[derive(Clone, Debug, PartialEq, uniffi::Record)]
pub struct BulkConnectPlanView {
    /// Open these without asking: each has a login of its own, or its type takes none.
    pub ready: Vec<String>,
    /// No login of their own. Never connect these with a login the app picked; open them one
    /// by one through the normal sign-in sheet.
    pub needs_login: Vec<String>,
    /// Already have a session.
    pub skipped_open: Vec<String>,
    /// A type the apps open no session for.
    pub skipped_unsupported: Vec<String>,
    /// A type the effective (managed) policy forbids. Never connected; show them as blocked.
    pub skipped_blocked: Vec<String>,
    /// `ready` plus `needs_login`: the number for "Connect 40 connections?".
    pub to_connect: u32,
    /// Ask before starting: `to_connect` is above the core's limit.
    pub needs_confirmation: bool,
}

#[uniffi::export]
impl CredentialVault {
    /// The plan for Connect All on `folder_id` (`None`: the whole library). `open_ids` are the
    /// connections that have a session now. An unknown folder id is an error.
    pub fn plan_connect_all(&self, library: Arc<Library>, folder_id: Option<String>, open_ids: Vec<String>) -> FfiResult<BulkConnectPlanView> {
        let folder = folder_id.as_deref().map(parse_id).transpose()?;
        let open = open_ids.iter().map(|id| parse_id(id)).collect::<FfiResult<Vec<Uuid>>>()?;
        // A broken managed file fails closed here as it does for every connect (F08).
        let policy = crate::policy::effective()?;
        let doc = library.lock();
        let vault = self.lock();
        let plan = actions::plan_connect_all(&doc, &vault, &policy, folder.unwrap_or(doc.root.id), &open)?;
        let ids = |list: &[Uuid]| list.iter().map(Uuid::to_string).collect();
        Ok(BulkConnectPlanView {
            ready: ids(&plan.ready),
            needs_login: ids(&plan.needs_login),
            skipped_open: ids(&plan.skipped_open),
            skipped_unsupported: ids(&plan.skipped_unsupported),
            skipped_blocked: ids(&plan.skipped_blocked),
            to_connect: u32::try_from(plan.to_connect()).unwrap_or(u32::MAX),
            needs_confirmation: plan.needs_confirmation(),
        })
    }
}

#[cfg(test)]
mod tests {
    use bastion_core::model::{Connection, Node, Protocol};
    use bastion_core::vault::{Credential, CredentialKind, Secret};

    use super::*;

    fn add(lib: &Library, parent: Option<Uuid>, name: &str, p: Protocol, host: &str, login: Option<Uuid>) -> String {
        let mut c = Connection::new(name, p, host);
        c.settings.credential_id = login;
        let id = c.id.to_string();
        lib.with_doc(|d| d.insert(parent, Node::Connection(c))).unwrap();
        id
    }

    #[test]
    fn the_plan_crosses_the_bridge_with_ids_and_counts() {
        let dir = tempfile::tempdir().unwrap();
        let lib = Arc::new(Library::open(dir.path().join("lib.json").display().to_string()).unwrap());
        let vault = CredentialVault::open_with_key(dir.path().join("c.vault").display().to_string(), Secret::new("k".repeat(64))).unwrap();
        let cred = Uuid::new_v4();
        vault.lock().add(Credential { id: cred, name: "ops".into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: "ops".into(), password: Secret::new("x") } });

        let folder = lib.add_folder(None, "Prod".into()).unwrap();
        let sub = lib.add_folder(Some(folder.clone()), "Web".into()).unwrap();
        let (top, below) = (Some(parse_id(&folder).unwrap()), Some(parse_id(&sub).unwrap()));
        let ready = add(&lib, top, "ssh", Protocol::Ssh, "host.example", Some(cred));
        // Same host, no login of its own: the saved login of `ssh` is offered to it, not used.
        let borrower = add(&lib, below, "rdp", Protocol::Rdp, "host.example", None);
        let open = add(&lib, below, "open", Protocol::Ssh, "open.example", Some(cred));
        let telnet = add(&lib, top, "telnet", Protocol::Telnet, "old.example", None);
        let outside = add(&lib, None, "outside", Protocol::Ssh, "out.example", Some(cred));

        let plan = vault.plan_connect_all(lib.clone(), Some(folder.clone()), vec![open.clone()]).unwrap();
        assert_eq!(plan.ready, vec![ready.clone()]);
        assert_eq!(plan.needs_login, vec![borrower]);
        assert_eq!(plan.skipped_open, vec![open.clone()]);
        assert_eq!(plan.skipped_unsupported, vec![telnet]);
        assert!(plan.skipped_blocked.is_empty(), "no managed policy in unit tests");
        assert_eq!((plan.to_connect, plan.needs_confirmation), (2, false));

        let whole = vault.plan_connect_all(lib.clone(), None, vec![]).unwrap();
        assert!(whole.ready.contains(&outside) && whole.ready.contains(&open), "no folder id means the whole library");

        assert!(vault.plan_connect_all(lib.clone(), Some(Uuid::new_v4().to_string()), vec![]).is_err(), "unknown folder");
        assert!(vault.plan_connect_all(lib.clone(), Some(ready), vec![]).is_err(), "a connection is not a folder");
        assert!(vault.plan_connect_all(lib.clone(), Some("nonsense".into()), vec![]).is_err());
        assert!(vault.plan_connect_all(lib.clone(), Some(folder.clone()), vec!["nonsense".into()]).is_err());

        // The folder menu now lists the two actions for an app that handles them.
        let none = crate::SessionSnapshot { connected: vec![], connecting: vec![], failed: vec![] };
        let items = lib.menu(Some(folder), none, vec!["connect-all".into(), "reconnect-all".into()]).unwrap();
        assert!(items.iter().any(|i| i.id == "connect-all" && i.enabled));
        assert!(items.iter().any(|i| i.id == "reconnect-all" && !i.enabled));
    }
}
