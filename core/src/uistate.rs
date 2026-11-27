//! Per-user view state that must survive a restart but is not part of the shared library:
//! which folders are expanded and whether the inspector shows. Kept in its own
//! file so expanding a folder never bumps the library revision or creates a library backup.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::PathBuf;
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::model::{Document, Folder, Node};
use crate::store::write_atomic;

/// What double-clicking a connection does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DoubleClick {
    #[default]
    Connect,
    Properties,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiState {
    pub expanded: BTreeSet<Uuid>,
    /// The right inspector shows. Hidden for new profiles (owner decision 2026-11-05); one global choice.
    pub inspector_visible: bool,
    /// The library (navigation) panel shows; false after the user collapses it.
    pub library_visible: bool,
    pub double_click: DoubleClick,
}

impl Default for UiState {
    fn default() -> Self {
        UiState { expanded: BTreeSet::new(), inspector_visible: false, library_visible: true, double_click: DoubleClick::Connect }
    }
}

impl UiState {
    /// Drop expanded ids that no longer name a folder in `doc`.
    pub fn prune(&mut self, doc: &Document) {
        let mut live = BTreeSet::new();
        collect_folders(&doc.root, &mut live);
        self.expanded.retain(|id| live.contains(id));
    }

    /// Expand or collapse every folder below `folder` (and `folder` itself unless it is the root).
    pub fn set_subtree_expanded(&mut self, doc: &Document, folder: Uuid, expanded: bool) -> Result<()> {
        let f = doc.folder(folder).ok_or_else(|| CoreError::NotFound(folder.to_string()))?;
        let mut ids = BTreeSet::new();
        collect_folders(f, &mut ids);
        if folder != doc.root.id {
            ids.insert(folder);
        }
        for id in ids {
            if expanded {
                self.expanded.insert(id);
            } else {
                self.expanded.remove(&id);
            }
        }
        Ok(())
    }
}

/// Ids of every folder below `f` (not `f` itself).
fn collect_folders(f: &Folder, out: &mut BTreeSet<Uuid>) {
    for n in &f.children {
        if let Node::Folder(sub) = n {
            out.insert(sub.id);
            collect_folders(sub, out);
        }
    }
}

pub struct UiStateStore {
    path: PathBuf,
}

impl UiStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        UiStateStore { path: path.into() }
    }

    /// The saved state; defaults when the file is missing or unreadable (view state is never
    /// worth refusing to start over).
    pub fn load(&self) -> UiState {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self, state: &UiState) -> Result<()> {
        let json = serde_json::to_vec_pretty(state).map_err(|e| CoreError::Invalid(e.to_string()))?;
        write_atomic(&self.path, &json)
    }
}
