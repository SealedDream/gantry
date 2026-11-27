//! Bridge for the navigation tree and command menus: the action registry evaluated against the
//! library, tree operations (ordered moves, rename, duplicate, sort, notes), icons, theme tokens
//! and the persisted view state.
use std::collections::HashSet;
use std::sync::Mutex;

use bastion_core::actions::{self, ActionContext, ActionId, ObjectKind, SessionState};
use bastion_core::model::{Document, Folder, Node, Protocol};
use bastion_core::uistate::{UiState, UiStateStore};
use bastion_core::{icons, theme};

use crate::{parse_id, FfiResult, Library};

#[derive(uniffi::Record)]
pub struct MenuItemView {
    /// Action id (`copy-ssh-command`); the frontend switches on it.
    pub id: String,
    pub label: String,
    pub glyph: String,
    pub section: u8,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
    pub destructive: bool,
    pub confirm: Option<String>,
    pub primary: bool,
}

#[derive(uniffi::Record)]
pub struct IconView {
    pub id: String,
    pub label: String,
    /// Theme colour token (`icon.terminal`).
    pub tint: String,
}

#[derive(uniffi::Record)]
pub struct ColorTokenView {
    pub name: String,
    pub hex: String,
}

#[derive(uniffi::Record)]
pub struct MetricsView {
    pub tree_row: f64,
    pub tree_icon: f64,
    pub tree_indent: f64,
    pub inspector_row: f64,
}

/// Session state of open tabs, as the frontend knows it. Connection ids in no list are closed.
#[derive(uniffi::Record)]
pub struct SessionSnapshot {
    pub connected: Vec<String>,
    pub connecting: Vec<String>,
    pub failed: Vec<String>,
}

pub(crate) fn icon_view(i: icons::Icon) -> IconView {
    IconView { id: i.id.into(), label: i.label.into(), tint: i.tint.token() }
}

fn protocol(name: &str) -> Option<Protocol> {
    serde_json::from_value(serde_json::Value::String(name.to_string())).ok()
}

/// Icon for a connection type (`ssh`) or for any other icon id (`folder`).
#[uniffi::export]
pub fn icon_for(id: String) -> IconView {
    protocol(&id)
        .map(icons::for_protocol)
        .or_else(|| icons::by_id(&id))
        .map(icon_view)
        .unwrap_or(IconView { id: "folder".into(), label: id, tint: icons::Tint::Neutral.token() })
}

#[uniffi::export]
pub fn all_icons() -> Vec<IconView> {
    icons::ALL.iter().copied().map(icon_view).collect()
}

/// Names a connection may take as its own icon (core `model::ICONS`), in display order.
#[uniffi::export]
pub fn connection_icon_names() -> Vec<String> {
    bastion_core::model::ICONS.iter().map(|s| s.to_string()).collect()
}

#[uniffi::export]
pub fn theme_colors(dark: bool) -> Vec<ColorTokenView> {
    theme::colors(dark).into_iter().map(|c| ColorTokenView { name: c.name.into(), hex: c.hex.into() }).collect()
}

/// The accent palette (`appearance.accent` ids) as `#RRGGBB`.
#[uniffi::export]
pub fn theme_accents() -> Vec<ColorTokenView> {
    theme::ACCENTS.iter().map(|(id, hex)| ColorTokenView { name: (*id).into(), hex: (*hex).into() }).collect()
}

/// Metrics for `compact`, `comfortable` or `spacious`.
#[uniffi::export]
pub fn theme_metrics(density: String) -> MetricsView {
    let d = match density.as_str() {
        "compact" => theme::Density::Compact,
        "spacious" => theme::Density::Spacious,
        _ => theme::Density::Comfortable,
    };
    let m = theme::metrics(d);
    MetricsView { tree_row: m.tree_row, tree_icon: m.tree_icon, tree_indent: m.tree_indent, inspector_row: m.inspector_row }
}

/// Every action id the registry knows, so a frontend can check its handler table.
#[uniffi::export]
pub fn action_ids() -> Vec<String> {
    actions::all_ids().into_iter().map(ActionId::as_str).collect()
}

fn session_of(id: &str, s: &SessionSnapshot) -> SessionState {
    let has = |v: &Vec<String>| v.iter().any(|x| x == id);
    if has(&s.connected) {
        SessionState::Connected
    } else if has(&s.connecting) {
        SessionState::Connecting
    } else if has(&s.failed) {
        SessionState::Failed
    } else {
        SessionState::Closed
    }
}

/// (connections, folders, open sessions) anywhere below `f`.
fn counts(f: &Folder, open: &HashSet<&str>) -> (u32, u32, u32) {
    f.children.iter().fold((0, 0, 0), |(c, d, o), n| match n {
        Node::Folder(sub) => {
            let (sc, sd, so) = counts(sub, open);
            (c + sc, d + 1 + sd, o + so)
        }
        Node::Connection(x) => (c + 1, d, o + open.contains(x.id.to_string().as_str()) as u32),
    })
}

fn context(doc: &Document, id: uuid::Uuid, sessions: &SessionSnapshot) -> bastion_core::Result<ActionContext> {
    if let Some(f) = doc.folder(id) {
        let open: HashSet<&str> = sessions.connected.iter().chain(&sessions.connecting).map(String::as_str).collect();
        let (c, d, o) = counts(f, &open);
        return Ok(ActionContext {
            kind: Some(ObjectKind::Folder),
            is_root: id == doc.root.id,
            descendant_connections: c,
            descendant_folders: d,
            open_sessions: o,
            ..Default::default()
        });
    }
    // A type this app does not know (PLUG-03a) never resolves, but its menu still offers
    // Rename, Move and Delete.
    if let Some(c) = doc.unavailable_entry(id) {
        return Ok(ActionContext { kind: Some(ObjectKind::Connection), protocol: Some(c.protocol), favorite: c.favorite, ..Default::default() });
    }
    let r = doc.resolve(id)?;
    Ok(ActionContext {
        kind: Some(ObjectKind::Connection),
        protocol: Some(r.connection.protocol),
        session: session_of(&id.to_string(), sessions),
        favorite: r.connection.favorite,
        has_username: r.effective.username.as_deref().map_or(false, |u| !u.is_empty()),
        sensitive: r.connection.classification.is_sensitive(),
        ..Default::default()
    })
}

fn menu_view(m: actions::MenuItem) -> MenuItemView {
    MenuItemView {
        id: m.id.as_str(),
        label: m.label,
        glyph: m.glyph.into(),
        section: m.section,
        enabled: m.enabled,
        disabled_reason: m.disabled_reason,
        destructive: m.destructive,
        confirm: m.confirm,
        primary: m.primary,
    }
}

#[uniffi::export]
impl Library {
    /// Menu for a folder or connection (`None` = the library root). `handled` lists the action
    /// ids the caller has handlers for; nothing else is returned.
    pub fn menu(&self, id: Option<String>, sessions: SessionSnapshot, handled: Vec<String>) -> FfiResult<Vec<MenuItemView>> {
        let handled: Vec<ActionId> = handled.iter().filter_map(|s| ActionId::parse(s)).collect();
        let target = id.as_deref().map(parse_id).transpose()?;
        self.with_doc(|d| {
            let cx = context(d, target.unwrap_or(d.root.id), &sessions)?;
            Ok(actions::menu(&cx, &crate::policy::effective_or_default(), &handled).into_iter().map(menu_view).collect())
        })
    }

    /// Drag-and-drop: move into `parent` (root when `None`) before sibling `before` (last when `None`).
    pub fn move_node_before(&self, id: String, parent: Option<String>, before: Option<String>) -> FfiResult<()> {
        let id = parse_id(&id)?;
        let parent = parent.as_deref().map(parse_id).transpose()?;
        let before = before.as_deref().map(parse_id).transpose()?;
        self.with_doc(|d| d.move_node_before(id, parent, before))
    }

    pub fn rename(&self, id: String, name: String) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| d.rename(id, &name))
    }

    /// Copy a connection (into its own folder) or a folder with its subtree. Returns the new id.
    pub fn duplicate_node(&self, id: String) -> FfiResult<String> {
        let id = parse_id(&id)?;
        self.with_doc(|d| {
            if d.folder(id).is_some() {
                d.duplicate_folder(id)
            } else {
                let parent = d.parent_of(id).filter(|p| *p != d.root.id);
                d.duplicate(id, parent)
            }
        })
        .map(|u| u.to_string())
    }

    /// Sort a folder by name, folders first (`None` = the library root).
    pub fn sort_folder(&self, id: Option<String>, recursive: bool) -> FfiResult<()> {
        let id = id.as_deref().map(parse_id).transpose()?;
        self.with_doc(|d| {
            let target = id.unwrap_or(d.root.id);
            d.sort_folder(target, recursive)
        })
    }

    /// Set a connection's own icon (one of [`connection_icon_names`]), or clear it with `None`
    /// to use the type icon. The core refuses any other name.
    pub fn set_icon(&self, id: String, icon: Option<String>) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| d.set_icon(id, icon.as_deref()))
    }

    pub fn set_notes(&self, id: String, notes: String) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.with_doc(|d| d.set_notes(id, &notes))
    }

    pub fn notes(&self, id: String) -> FfiResult<String> {
        let id = parse_id(&id)?;
        self.with_doc(|d| Ok(d.resolve(id)?.connection.notes))
    }

    /// `ssh -p 2222 user@host` with inherited settings applied.
    pub fn ssh_command(&self, id: String) -> FfiResult<String> {
        let c = self.resolve(parse_id(&id)?)?;
        Ok(actions::ssh_command(&c.host, c.settings.port, c.settings.username.as_deref()))
    }

    /// `host` or `host:port` (port only when it is not the type's default).
    pub fn address(&self, id: String) -> FfiResult<String> {
        let c = self.resolve(parse_id(&id)?)?;
        Ok(actions::address(&c.host, c.settings.port, c.protocol.default_port()))
    }

    /// Effective username after folder and type defaults; `None` when unset.
    pub fn effective_username(&self, id: String) -> FfiResult<Option<String>> {
        Ok(self.resolve(parse_id(&id)?)?.settings.username.filter(|u| !u.is_empty()))
    }

    /// Parent folder id; `None` at the top level.
    pub fn parent_of(&self, id: String) -> FfiResult<Option<String>> {
        let id = parse_id(&id)?;
        self.with_doc(|d| Ok(d.parent_of(id).filter(|p| *p != d.root.id).map(|u| u.to_string())))
    }
}

/// Persisted view state (`ui-state.json` next to the library). Every change is saved at once.
#[derive(uniffi::Object)]
pub struct TreeState {
    store: UiStateStore,
    state: Mutex<UiState>,
}

#[uniffi::export]
impl TreeState {
    #[uniffi::constructor]
    pub fn open(path: String) -> Self {
        let store = UiStateStore::new(path);
        let state = Mutex::new(store.load());
        TreeState { store, state }
    }

    pub fn expanded(&self) -> Vec<String> {
        self.lock().expanded.iter().map(|u| u.to_string()).collect()
    }

    pub fn set_expanded(&self, id: String, expanded: bool) -> FfiResult<()> {
        let id = parse_id(&id)?;
        self.update(|s| {
            if expanded {
                s.expanded.insert(id);
            } else {
                s.expanded.remove(&id);
            }
            Ok(())
        })
    }

    /// `set_expanded` for several folders with one save (an Option-click expands a whole subtree,
    /// one notification per folder).
    pub fn set_expanded_many(&self, ids: Vec<String>, expanded: bool) -> FfiResult<()> {
        let ids = ids.iter().map(|i| parse_id(i)).collect::<Result<Vec<_>, _>>()?;
        self.update(|s| {
            for id in ids {
                if expanded {
                    s.expanded.insert(id);
                } else {
                    s.expanded.remove(&id);
                }
            }
            Ok(())
        })
    }

    /// Expand or collapse a folder and all its descendants (`None` = everything).
    pub fn set_subtree_expanded(&self, library: std::sync::Arc<Library>, id: Option<String>, expanded: bool) -> FfiResult<()> {
        self.set_subtree_expanded_in(&library, id, expanded)
    }

    /// Forget folders that no longer exist.
    pub fn prune(&self, library: std::sync::Arc<Library>) -> FfiResult<()> {
        self.prune_in(&library)
    }

    pub fn inspector_visible(&self) -> bool {
        self.lock().inspector_visible
    }

    pub fn set_inspector_visible(&self, visible: bool) -> FfiResult<()> {
        self.update(|s| {
            s.inspector_visible = visible;
            Ok(())
        })
    }

    pub fn library_visible(&self) -> bool {
        self.lock().library_visible
    }

    pub fn set_library_visible(&self, visible: bool) -> FfiResult<()> {
        self.update(|s| {
            s.library_visible = visible;
            Ok(())
        })
    }
}

impl TreeState {
    /// `set_subtree_expanded` for hosts holding a plain `&Library` (the C ABI).
    pub fn set_subtree_expanded_in(&self, library: &Library, id: Option<String>, expanded: bool) -> FfiResult<()> {
        let id = id.as_deref().map(parse_id).transpose()?;
        let doc = library.with_doc(|d| Ok(d.clone()))?;
        self.update(|s| s.set_subtree_expanded(&doc, id.unwrap_or(doc.root.id), expanded))
    }

    /// `prune` for hosts holding a plain `&Library` (the C ABI).
    pub fn prune_in(&self, library: &Library) -> FfiResult<()> {
        let doc = library.with_doc(|d| Ok(d.clone()))?;
        self.update(|s| {
            s.prune(&doc);
            Ok(())
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, UiState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Apply a change and save it; on any error the in-memory state stays as it was.
    fn update(&self, f: impl FnOnce(&mut UiState) -> bastion_core::Result<()>) -> FfiResult<()> {
        let mut s = self.lock();
        let mut next = s.clone();
        f(&mut next)?;
        self.store.save(&next)?;
        *s = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(connected: &[&String]) -> SessionSnapshot {
        SessionSnapshot { connected: connected.iter().map(|s| s.to_string()).collect(), connecting: vec![], failed: vec![] }
    }

    #[test]
    fn own_icon_is_set_shown_refused_and_cleared() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-icon-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let lib = Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap();
        let f = lib.add_folder(None, "Db".into()).unwrap();
        let c = lib.add_connection(Some(f), "db-1".into(), "ssh".into(), "10.0.0.9".into(), None, None).unwrap();
        fn find(f: &crate::FolderView, id: &str) -> Option<Option<String>> {
            f.connections.iter().find(|x| x.id == id).map(|x| x.own_icon.clone()).or_else(|| f.folders.iter().find_map(|s| find(s, id)))
        }
        let own = |l: &Library| find(&l.tree(), &c).expect("connection in tree");
        assert_eq!(own(&lib), None, "a new connection uses its type icon");

        let names = connection_icon_names();
        assert_eq!(names.len(), bastion_core::model::ICONS.len());
        assert!(names.contains(&"database".to_string()));

        lib.set_icon(c.clone(), Some("database".into())).unwrap();
        assert_eq!(own(&lib).as_deref(), Some("database"));
        assert!(lib.set_icon(c.clone(), Some("../evil".into())).is_err(), "names outside the set are refused");

        lib.set_icon(c.clone(), None).unwrap();
        assert_eq!(own(&lib), None);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn menus_come_from_the_registry_and_tree_state_persists() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-ui-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let lib = std::sync::Arc::new(Library::open(dir.join("lib.json").to_string_lossy().into_owned()).unwrap());
        let f = lib.add_folder(None, "Prod".into()).unwrap();
        let sub = lib.add_folder(Some(f.clone()), "Web".into()).unwrap();
        let c = lib.add_connection(Some(sub.clone()), "web-1".into(), "ssh".into(), "10.0.0.5".into(), Some(2222), Some("ops".into())).unwrap();
        let all = action_ids();

        let m = lib.menu(Some(c.clone()), snap(&[&c]), all.clone()).unwrap();
        assert_eq!(m[0].label, "Show Session");
        assert!(m.iter().any(|i| i.id == "disconnect" && i.enabled));
        let fm = lib.menu(Some(f.clone()), snap(&[&c]), all.clone()).unwrap();
        assert!(fm.iter().any(|i| i.id == "disconnect-all" && i.enabled));
        assert!(fm.iter().any(|i| i.id == "expand-all"));
        assert!(lib.menu(None, snap(&[]), all.clone()).unwrap().iter().all(|i| i.id != "delete"), "root cannot be deleted");
        assert_eq!(lib.menu(Some(c.clone()), snap(&[]), vec!["connect".into()]).unwrap().len(), 1);
        assert_eq!(lib.ssh_command(c.clone()).unwrap(), "ssh -p 2222 ops@10.0.0.5");
        assert_eq!(lib.address(c.clone()).unwrap(), "10.0.0.5:2222");

        let copy = lib.duplicate_node(sub.clone()).unwrap();
        assert_eq!(lib.parent_of(copy.clone()).unwrap(), Some(f.clone()));
        lib.move_node_before(copy.clone(), Some(f.clone()), Some(sub.clone())).unwrap();
        assert_eq!(lib.tree().folders[0].folders[0].name, "Web (copy)");
        lib.rename(copy, "Api".into()).unwrap();
        lib.sort_folder(Some(f.clone()), false).unwrap();
        assert_eq!(lib.tree().folders[0].folders[0].name, "Api");

        let path = dir.join("ui-state.json").to_string_lossy().into_owned();
        let st = TreeState::open(path.clone());
        st.set_subtree_expanded(lib.clone(), Some(f.clone()), true).unwrap();
        let back = TreeState::open(path);
        assert_eq!(back.expanded().len(), 3);
        assert_eq!(icon_for("rdp".into()).label, "Remote Desktop (RDP)");
        assert_eq!(icon_for("folder".into()).tint, "icon.folder");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn set_expanded_many_persists_all_in_one_go() {
        let dir = std::env::temp_dir().join(format!("bastion-ffi-ui-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ui-state.json").to_string_lossy().into_owned();
        let (a, b) = (uuid::Uuid::new_v4().to_string(), uuid::Uuid::new_v4().to_string());
        let st = TreeState::open(path.clone());
        st.set_expanded_many(vec![a.clone(), b.clone()], true).unwrap();
        assert_eq!(TreeState::open(path.clone()).expanded().len(), 2);
        st.set_expanded_many(vec![a], false).unwrap();
        assert_eq!(TreeState::open(path.clone()).expanded(), vec![b]);
        assert!(st.set_expanded_many(vec!["not-an-id".into()], true).is_err());
        assert_eq!(TreeState::open(path).expanded().len(), 1, "a bad id saves nothing");
        std::fs::remove_dir_all(dir).ok();
    }
}
