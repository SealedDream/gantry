//! Recently Deleted (B10): delete to a restorable area, restore, purge.
//!
//! The apps pass the time and the keep time (setting `library.deleted-retention-days`), so
//! tests can move the clock. Every call that drops connections returns their ids; the app then
//! prunes inline secrets with [`Library::live_connection_ids`], never with the tree alone.

use crate::{parse_id, FfiResult, Library};
use bastion_core::model::{DeletedItem, Node};

#[derive(uniffi::Record)]
pub struct DeletedItemView {
    pub id: String,
    pub name: String,
    /// `folder` or `connection`.
    pub kind: String,
    /// Original folder; `None` = the library root.
    pub parent_id: Option<String>,
    /// That folder's name when it still exists (in the tree or in Recently Deleted).
    pub parent_name: Option<String>,
    /// Unix seconds.
    pub deleted_at: i64,
    /// Connections inside (1 for a connection).
    pub connection_count: u32,
}

#[derive(uniffi::Record)]
pub struct RestoreView {
    /// The folder it landed in; `None` = the library root.
    pub landed_in: Option<String>,
    /// The original folder was gone, so it went to the root.
    pub at_root_because_parent_missing: bool,
}

fn count(node: &Node) -> u32 {
    match node {
        Node::Connection(_) => 1,
        Node::Folder(f) => f.children.iter().map(count).sum(),
    }
}

fn find_name(node: &Node, id: uuid::Uuid) -> Option<String> {
    match node {
        Node::Folder(f) if f.id == id => Some(f.name.clone()),
        Node::Folder(f) => f.children.iter().find_map(|n| find_name(n, id)),
        Node::Connection(_) => None,
    }
}

fn view(doc: &bastion_core::model::Document, d: &DeletedItem) -> DeletedItemView {
    let (name, kind) = match &d.node {
        Node::Folder(f) => (f.name.clone(), "folder"),
        Node::Connection(c) => (c.name.clone(), "connection"),
    };
    let parent_name = d.parent.and_then(|p| doc.folder(p).map(|f| f.name.clone()).or_else(|| doc.deleted.iter().find_map(|o| find_name(&o.node, p))));
    DeletedItemView {
        id: d.node.id().to_string(),
        name,
        kind: kind.into(),
        parent_id: d.parent.map(|p| p.to_string()),
        parent_name,
        deleted_at: d.deleted_at,
        connection_count: count(&d.node),
    }
}

fn strings(ids: Vec<uuid::Uuid>) -> Vec<String> {
    ids.into_iter().map(|i| i.to_string()).collect()
}

#[uniffi::export]
impl Library {
    /// Delete a folder or connection: to Recently Deleted, or for good when `retention_days`
    /// is 0. Returns the connection ids dropped for good (prune their inline secrets).
    pub fn trash_node(&self, id: String, now: i64, retention_days: u32) -> FfiResult<Vec<String>> {
        let id = parse_id(&id)?;
        self.with_doc(|d| d.trash(id, now, retention_days)).map(strings)
    }

    /// Recently Deleted, oldest first.
    pub fn deleted_items(&self) -> Vec<DeletedItemView> {
        let doc = self.lock();
        doc.deleted.iter().map(|d| view(&doc, d)).collect()
    }

    pub fn restore_node(&self, id: String) -> FfiResult<RestoreView> {
        let id = parse_id(&id)?;
        let r = self.with_doc(|d| d.restore(id))?;
        Ok(RestoreView { landed_in: r.landed_in.map(|p| p.to_string()), at_root_because_parent_missing: r.at_root_because_parent_missing })
    }

    pub fn delete_permanently(&self, id: String) -> FfiResult<Vec<String>> {
        let id = parse_id(&id)?;
        self.with_doc(|d| d.delete_permanently(id)).map(strings)
    }

    pub fn empty_deleted(&self) -> Vec<String> {
        strings(self.lock().empty_deleted())
    }

    /// Drop items older than the keep time (at open and once a day).
    pub fn purge_deleted(&self, now: i64, retention_days: u32) -> Vec<String> {
        strings(self.lock().purge_deleted(now, retention_days))
    }

    /// The tree plus Recently Deleted: the only correct live set for pruning inline secrets.
    pub fn live_connection_ids(&self) -> Vec<String> {
        self.lock().all_connection_ids().into_iter().map(|i| i.to_string()).collect()
    }
}
