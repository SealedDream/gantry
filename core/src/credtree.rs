//! Credentials section of the tree (Royal TS style): one vault, user folders holding named
//! credentials, and hosts or folders that point to ONE credential or inherit it.
//!
//! Everything is keyed by stable ids, so renaming or moving a credential or a folder never
//! breaks a reference. Folders and placement live inside the sealed vault; the views here
//! carry names, usernames and kinds only, never a secret.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Document, Folder, Node};
use crate::vault::{CredentialKind, Vault};

/// Longest folder or credential name accepted.
pub const MAX_NAME_LEN: usize = 128;
/// Deepest folder nesting accepted (keeps walks bounded on a crafted vault).
pub const MAX_DEPTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialFolder {
    pub id: Uuid,
    pub name: String,
    /// Parent folder; `None` is the section root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<Uuid>,
}

/// One credential in the tree, without its secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CredentialLeaf {
    pub id: Uuid,
    pub name: String,
    pub username: String,
    /// `password`, `ssh-key`, or `unsupported` (a kind a newer app wrote; delete only).
    pub kind: &'static str,
}

/// A folder of the Credentials section with its sub-folders and credentials, sorted by name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CredentialTreeFolder {
    /// `None` only for the section root.
    pub id: Option<Uuid>,
    pub name: String,
    pub folders: Vec<CredentialTreeFolder>,
    pub credentials: Vec<CredentialLeaf>,
}

/// A host or folder of the library that points straight at a credential.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CredentialUsage {
    pub node_id: Uuid,
    pub name: String,
    pub is_folder: bool,
    /// Folder names from the library root down to (not including) this node.
    pub path: Vec<String>,
}

/// Result of [`Vault::remove_checked`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemoveOutcome {
    pub removed: bool,
    pub users: Vec<CredentialUsage>,
}

fn clean_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::Invalid("name is empty".into()));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(CoreError::Invalid(format!("name is longer than {MAX_NAME_LEN} characters")));
    }
    if name.chars().any(char::is_control) || name.contains('/') {
        return Err(CoreError::Invalid("name contains a control character or /".into()));
    }
    Ok(name.to_string())
}

fn kind_id(kind: &CredentialKind) -> (&str, &'static str) {
    match kind {
        CredentialKind::Password { username, .. } => (username, "password"),
        CredentialKind::SshKey { username, .. } => (username, "ssh-key"),
    }
}

fn by_name(a: &str, b: &str) -> std::cmp::Ordering {
    a.to_lowercase().cmp(&b.to_lowercase())
}

impl Vault {
    /// Every Credentials-section folder, by name.
    pub fn folders(&self) -> Vec<CredentialFolder> {
        let mut v: Vec<_> = self.folders.values().cloned().collect();
        v.sort_by(|a, b| by_name(&a.name, &b.name));
        v
    }

    fn require_folder(&self, id: Option<Uuid>) -> Result<()> {
        match id {
            Some(id) if !self.folders.contains_key(&id) => Err(CoreError::NotFound(format!("credential folder {id}"))),
            _ => Ok(()),
        }
    }

    fn sibling_taken(&self, parent: Option<Uuid>, name: &str, except: Option<Uuid>) -> bool {
        self.folders.values().any(|f| f.parent == parent && Some(f.id) != except && f.name.to_lowercase() == name.to_lowercase())
    }

    fn require_credential(&self, id: Uuid) -> Result<()> {
        if self.is_assignable(id) {
            Ok(())
        } else {
            Err(CoreError::NotFound(format!("credential {id}")))
        }
    }

    /// True for a saved credential a host or folder may point to (not an inline secret, not a folder).
    pub fn is_assignable(&self, id: Uuid) -> bool {
        self.entries.get(&id).is_some_and(|c| c.owner.is_none())
    }

    pub fn add_folder(&mut self, name: &str, parent: Option<Uuid>) -> Result<Uuid> {
        let name = clean_name(name)?;
        self.require_folder(parent)?;
        if self.depth(parent) + 1 > MAX_DEPTH {
            return Err(CoreError::Invalid(format!("folders nest at most {MAX_DEPTH} deep")));
        }
        if self.sibling_taken(parent, &name, None) {
            return Err(CoreError::Invalid(format!("a folder named \"{name}\" already exists here")));
        }
        let id = Uuid::new_v4();
        self.folders.insert(id, CredentialFolder { id, name, parent });
        Ok(id)
    }

    pub fn rename_folder(&mut self, id: Uuid, name: &str) -> Result<()> {
        let name = clean_name(name)?;
        self.require_folder(Some(id))?;
        let parent = self.folders[&id].parent;
        if self.sibling_taken(parent, &name, Some(id)) {
            return Err(CoreError::Invalid(format!("a folder named \"{name}\" already exists here")));
        }
        self.folders.insert(id, CredentialFolder { id, name, parent });
        self.refresh_paths();
        Ok(())
    }

    /// Move a folder (with everything in it) under `parent`; refuses moving it into itself.
    pub fn move_folder(&mut self, id: Uuid, parent: Option<Uuid>) -> Result<()> {
        self.require_folder(Some(id))?;
        self.require_folder(parent)?;
        if self.ancestors(parent).contains(&id) {
            return Err(CoreError::Invalid("a folder cannot move into itself".into()));
        }
        if self.depth(parent) + self.height(id) > MAX_DEPTH {
            return Err(CoreError::Invalid(format!("folders nest at most {MAX_DEPTH} deep")));
        }
        let name = self.folders[&id].name.clone();
        if self.sibling_taken(parent, &name, Some(id)) {
            return Err(CoreError::Invalid(format!("a folder named \"{name}\" already exists there")));
        }
        self.folders.insert(id, CredentialFolder { id, name, parent });
        self.refresh_paths();
        Ok(())
    }

    /// Delete an empty folder. A folder that still holds folders or credentials is refused,
    /// so nothing is deleted by accident.
    pub fn remove_folder(&mut self, id: Uuid) -> Result<()> {
        self.require_folder(Some(id))?;
        let has_folders = self.folders.values().any(|f| f.parent == Some(id));
        let has_credentials = self.placement.values().any(|f| *f == id);
        if has_folders || has_credentials {
            return Err(CoreError::Invalid("the folder is not empty".into()));
        }
        self.folders.remove(&id);
        Ok(())
    }

    pub fn rename_credential(&mut self, id: Uuid, name: &str) -> Result<()> {
        let name = clean_name(name)?;
        self.require_credential(id)?;
        if let Some(c) = self.entries.get_mut(&id) {
            c.name = name;
        }
        Ok(())
    }

    /// Put a credential in `folder` (`None`: the section root).
    pub fn move_credential(&mut self, id: Uuid, folder: Option<Uuid>) -> Result<()> {
        self.require_credential(id)?;
        self.require_folder(folder)?;
        match folder {
            Some(f) => self.placement.insert(id, f),
            None => self.placement.remove(&id),
        };
        self.refresh_paths();
        Ok(())
    }

    /// The folder a credential sits in, or `None` at the section root.
    pub fn folder_of(&self, credential: Uuid) -> Option<Uuid> {
        self.placement.get(&credential).copied()
    }

    /// Folder names from the section root to the credential's folder, joined by `/`.
    pub fn folder_path(&self, credential: Uuid) -> Option<String> {
        let folder = self.folder_of(credential)?;
        let mut names: Vec<&str> = self.ancestors(Some(folder)).iter().filter_map(|f| self.folders.get(f)).map(|f| f.name.as_str()).collect();
        names.reverse();
        Some(names.join("/"))
    }

    /// Keep the legacy text `Credential::folder` in step with the tree, for older readers.
    fn refresh_paths(&mut self) {
        let paths: Vec<(Uuid, Option<String>)> = self.entries.keys().filter(|id| self.is_assignable(**id)).map(|id| (*id, self.folder_path(*id))).collect();
        for (id, path) in paths {
            if let Some(c) = self.entries.get_mut(&id) {
                c.folder = path;
            }
        }
    }

    /// `folder` and its ancestors, nearest first (bounded, so a cycle cannot hang).
    fn ancestors(&self, folder: Option<Uuid>) -> Vec<Uuid> {
        let mut out = Vec::new();
        let mut cur = folder;
        while let Some(id) = cur {
            if out.contains(&id) || out.len() > MAX_DEPTH {
                break;
            }
            out.push(id);
            cur = self.folders.get(&id).and_then(|f| f.parent);
        }
        out
    }

    fn depth(&self, folder: Option<Uuid>) -> usize {
        self.ancestors(folder).len()
    }

    /// Levels of folders at and below `id` (1 for a folder with no sub-folders).
    fn height(&self, id: Uuid) -> usize {
        fn go(v: &Vault, id: Uuid, level: usize) -> usize {
            if level > MAX_DEPTH {
                return level;
            }
            v.folders.values().filter(|f| f.parent == Some(id)).map(|f| go(v, f.id, level + 1)).max().unwrap_or(level)
        }
        go(self, id, 1)
    }

    /// The whole Credentials section, sorted by name. Inline secrets are not part of it.
    pub fn credential_tree(&self) -> CredentialTreeFolder {
        let mut by_parent: BTreeMap<Option<Uuid>, Vec<&CredentialFolder>> = BTreeMap::new();
        for f in self.folders.values() {
            by_parent.entry(f.parent).or_default().push(f);
        }
        let mut leaves: BTreeMap<Option<Uuid>, Vec<CredentialLeaf>> = BTreeMap::new();
        for c in self.entries.values().filter(|c| c.owner.is_none()) {
            let (username, kind) = kind_id(&c.kind);
            leaves.entry(self.folder_of(c.id)).or_default().push(CredentialLeaf { id: c.id, name: c.name.clone(), username: username.to_string(), kind });
        }
        for c in self.unsupported.values().filter(|c| c.owner.is_none()) {
            let username = crate::vault_unknown::UNSUPPORTED_CREDENTIAL.to_string();
            leaves.entry(self.folder_of(c.id)).or_default().push(CredentialLeaf { id: c.id, name: c.name.clone(), username, kind: "unsupported" });
        }
        build_tree(None, "Credentials".into(), &by_parent, &mut leaves, 0)
    }

    /// Fix what a hand-edited or older vault may hold: folders under a missing parent or in a
    /// cycle go to the root, placement pointing at a missing folder or credential is dropped,
    /// and legacy text folders (`Credential::folder`, `A/B`) become real folders.
    pub(crate) fn repair_tree(&mut self) {
        let ids: BTreeSet<Uuid> = self.folders.keys().copied().collect();
        let broken: Vec<Uuid> = self
            .folders
            .values()
            .filter(|f| {
                let up = self.ancestors(f.parent);
                f.parent.is_some_and(|p| !ids.contains(&p)) || up.contains(&f.id) || up.len() >= MAX_DEPTH
            })
            .map(|f| f.id)
            .collect();
        for id in broken {
            if let Some(f) = self.folders.get_mut(&id) {
                f.parent = None;
            }
        }
        let entries = &self.entries;
        let unsupported = &self.unsupported;
        let folders = &self.folders;
        self.placement.retain(|c, f| {
            let named = entries.get(c).is_some_and(|c| c.owner.is_none()) || unsupported.get(c).is_some_and(|c| c.owner.is_none());
            named && folders.contains_key(f)
        });
        let legacy: Vec<(Uuid, String)> = self
            .entries
            .values()
            .filter(|c| c.owner.is_none() && !self.placement.contains_key(&c.id))
            .filter_map(|c| c.folder.clone().map(|f| (c.id, f)))
            .collect();
        for (cred, path) in legacy {
            let mut parent = None;
            for part in path.split('/').filter_map(|p| clean_name(p).ok()).take(MAX_DEPTH) {
                let found = self.folders.values().find(|f| f.parent == parent && f.name.to_lowercase() == part.to_lowercase()).map(|f| f.id);
                parent = Some(found.unwrap_or_else(|| {
                    let id = Uuid::new_v4();
                    self.folders.insert(id, CredentialFolder { id, name: part, parent });
                    id
                }));
            }
            if let Some(f) = parent {
                self.placement.insert(cred, f);
            }
        }
    }

    /// Delete a credential unless a host or folder of `doc` points at it. In use and not
    /// `force`: nothing changes and the users come back so the UI can warn and list them.
    /// With `force` the references are cleared first (those nodes inherit again).
    pub fn remove_checked(&mut self, doc: &mut Document, id: Uuid, force: bool) -> Result<RemoveOutcome> {
        self.require_credential(id)?;
        let users = credential_usages(doc, id);
        if !users.is_empty() && !force {
            return Ok(RemoveOutcome { removed: false, users });
        }
        clear_credential_references(doc, id);
        self.remove(id);
        Ok(RemoveOutcome { removed: true, users })
    }
}

fn build_tree(
    id: Option<Uuid>,
    name: String,
    by_parent: &BTreeMap<Option<Uuid>, Vec<&CredentialFolder>>,
    leaves: &mut BTreeMap<Option<Uuid>, Vec<CredentialLeaf>>,
    level: usize,
) -> CredentialTreeFolder {
    let mut folders: Vec<CredentialTreeFolder> = if level >= MAX_DEPTH {
        Vec::new()
    } else {
        by_parent.get(&id).into_iter().flatten().map(|f| build_tree(Some(f.id), f.name.clone(), by_parent, leaves, level + 1)).collect()
    };
    folders.sort_by(|a, b| by_name(&a.name, &b.name));
    let mut credentials = leaves.remove(&id).unwrap_or_default();
    credentials.sort_by(|a, b| by_name(&a.name, &b.name).then(a.id.cmp(&b.id)));
    CredentialTreeFolder { id, name, folders, credentials }
}

/// Hosts and folders that point straight at `credential` (not the ones that only inherit it).
pub fn credential_usages(doc: &Document, credential: Uuid) -> Vec<CredentialUsage> {
    fn walk(f: &Folder, credential: Uuid, path: &mut Vec<String>, out: &mut Vec<CredentialUsage>) {
        for n in &f.children {
            match n {
                Node::Connection(c) if c.settings.credential_id == Some(credential) || c.settings.logins.contains(&credential) => {
                    out.push(CredentialUsage { node_id: c.id, name: c.name.clone(), is_folder: false, path: path.clone() });
                }
                Node::Folder(sub) => {
                    if sub.defaults.credential_id == Some(credential) {
                        out.push(CredentialUsage { node_id: sub.id, name: sub.name.clone(), is_folder: true, path: path.clone() });
                    }
                    path.push(sub.name.clone());
                    walk(sub, credential, path, out);
                    path.pop();
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    if doc.root.defaults.credential_id == Some(credential) {
        out.push(CredentialUsage { node_id: doc.root.id, name: doc.root.name.clone(), is_folder: true, path: Vec::new() });
    }
    walk(&doc.root, credential, &mut Vec::new(), &mut out);
    out
}

/// Make every host and folder that points at `credential` inherit instead; returns how many changed.
pub fn clear_credential_references(doc: &mut Document, credential: Uuid) -> usize {
    fn walk(f: &mut Folder, credential: Uuid) -> usize {
        let mut n = 0;
        if f.defaults.credential_id == Some(credential) {
            f.defaults.credential_id = None;
            n += 1;
        }
        for child in &mut f.children {
            match child {
                Node::Connection(c) if c.settings.credential_id == Some(credential) || c.settings.logins.contains(&credential) => {
                    c.settings.logins.retain(|l| *l != credential);
                    if c.settings.credential_id == Some(credential) {
                        // The next saved login becomes the default (W23).
                        c.settings.credential_id = (!c.settings.logins.is_empty()).then(|| c.settings.logins.remove(0));
                    }
                    n += 1;
                }
                Node::Folder(sub) => n += walk(sub, credential),
                _ => {}
            }
        }
        n
    }
    walk(&mut doc.root, credential)
}

/// Point a host or folder at ONE credential, or with `None` let it inherit from its folder.
/// `vault` must hold `credential` as a saved (not inline) credential.
pub fn assign_credential(doc: &mut Document, vault: &Vault, node: Uuid, credential: Option<Uuid>) -> Result<()> {
    if let Some(c) = credential {
        if !vault.is_assignable(c) {
            return Err(CoreError::NotFound(format!("credential {c}")));
        }
    }
    fn walk(f: &mut Folder, node: Uuid, credential: Option<Uuid>) -> bool {
        if f.id == node {
            f.defaults.credential_id = credential;
            return true;
        }
        f.children.iter_mut().any(|child| match child {
            Node::Connection(c) if c.id == node => {
                c.settings.credential_id = credential;
                true
            }
            Node::Folder(sub) => walk(sub, node, credential),
            _ => false,
        })
    }
    if walk(&mut doc.root, node, credential) {
        Ok(())
    } else {
        Err(CoreError::NotFound(node.to_string()))
    }
}

/// The credential a host ends up with and the node it comes from (the host itself or the
/// nearest folder that sets one), or `None` when nothing up the chain sets one.
pub fn effective_credential(doc: &Document, connection: Uuid) -> Option<(Uuid, Uuid)> {
    fn walk(f: &Folder, connection: Uuid, inherited: Option<(Uuid, Uuid)>) -> Option<Option<(Uuid, Uuid)>> {
        let here = f.defaults.credential_id.map(|c| (c, f.id)).or(inherited);
        f.children.iter().find_map(|n| match n {
            Node::Connection(c) if c.id == connection => Some(c.settings.credential_id.map(|cr| (cr, c.id)).or(here)),
            Node::Folder(sub) => walk(sub, connection, here),
            _ => None,
        })
    }
    walk(&doc.root, connection, None).flatten()
}
