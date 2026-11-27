//! Workspace bridge: the per-user `workspaces.json` next to the library. Every change is
//! validated by the core and saved at once; times are stamped here, in Unix seconds.
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use bastion_core::workspace::{clamp_ratio, PaneLayout, SplitAxis, TabMode, Workspace, WorkspaceStore as CoreStore, WorkspaceTab, RATIO_EVEN};

use bastion_core::tabgroups::TabGroup;

use crate::{parse_id, FfiError, FfiResult};

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct WorkspaceTabView {
    pub connection_id: String,
    /// `terminal` or `files`.
    pub mode: String,
    /// The split tree in pre-order: `right` / `down` (followed by its two sides) or `leaf`. A
    /// split may carry the share of its first side, `right:0.62`; without one it is even.
    /// Empty for a single pane.
    pub layout: Vec<String>,
}

#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct WorkspaceView {
    pub id: String,
    pub name: String,
    pub tabs: Vec<WorkspaceTabView>,
    pub selected: u32,
    /// Unix seconds; `None` when never opened since it was copied.
    pub last_used: Option<i64>,
    /// Per tab, in order: the id of its group in `groups_json`, or none.
    pub tab_groups: Vec<Option<String>>,
    /// The tab groups as JSON: `[{"id","name","color","collapsed","folder"}]`.
    pub groups_json: String,
}


fn decode(steps: &mut std::slice::Iter<'_, String>) -> FfiResult<PaneLayout> {
    let bad = || FfiError::failed("invalid pane layout".into());
    let step = steps.next().ok_or_else(bad)?;
    let (axis, ratio) = step.split_once(':').map_or((step.as_str(), None), |(a, r)| (a, Some(r)));
    let axis = match axis {
        "leaf" if ratio.is_none() => return Ok(PaneLayout::Leaf),
        "right" => SplitAxis::Right,
        "down" => SplitAxis::Down,
        _ => return Err(bad()),
    };
    let ratio = match ratio {
        None => RATIO_EVEN,
        Some(r) => clamp_ratio(r.parse::<f32>().map_err(|_| bad())?),
    };
    let first = Box::new(decode(steps)?);
    let second = Box::new(decode(steps)?);
    Ok(PaneLayout::Split { axis, ratio, first, second })
}

fn tab_from(v: WorkspaceTabView) -> FfiResult<WorkspaceTab> {
    let mode = match v.mode.as_str() {
        "terminal" => TabMode::Terminal,
        "files" => TabMode::Files,
        m => return Err(FfiError::failed(format!("unknown tab mode `{m}`"))),
    };
    let layout = match v.layout.as_slice() {
        [] => None,
        steps => {
            let mut it = steps.iter();
            let l = decode(&mut it)?;
            if it.next().is_some() {
                return Err(FfiError::failed("invalid pane layout".into()));
            }
            // A single leaf is the default shape.
            (l != PaneLayout::Leaf).then_some(l)
        }
    };
    Ok(WorkspaceTab { connection: parse_id(&v.connection_id)?, mode, layout, group: None })
}

fn tab_view(t: &WorkspaceTab) -> WorkspaceTabView {
    let layout = t.layout.as_ref().map_or_else(Vec::new, PaneLayout::steps);
    WorkspaceTabView {
        connection_id: t.connection.to_string(),
        mode: if t.mode == TabMode::Files { "files" } else { "terminal" }.into(),
        layout,
    }
}

fn view(w: &Workspace) -> WorkspaceView {
    WorkspaceView {
        id: w.id.to_string(),
        name: w.name.clone(),
        tabs: w.tabs.iter().map(tab_view).collect(),
        selected: w.selected as u32,
        last_used: w.last_used,
        tab_groups: w.tabs.iter().map(|t| t.group.map(|g| g.to_string())).collect(),
        groups_json: serde_json::to_string(&w.groups).unwrap_or_else(|_| "[]".into()),
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Saved workspaces (`workspaces.json`). A corrupt file is an error, never an empty list, so
/// saving cannot silently overwrite it.
#[derive(uniffi::Object)]
pub struct WorkspaceStore {
    store: Mutex<CoreStore>,
}

#[uniffi::export]
impl WorkspaceStore {
    #[uniffi::constructor]
    pub fn open(path: String) -> FfiResult<Self> {
        Ok(WorkspaceStore { store: Mutex::new(CoreStore::open(std::path::Path::new(&path))?) })
    }

    pub fn list(&self) -> Vec<WorkspaceView> {
        self.lock().list().iter().map(view).collect()
    }

    /// Save Current Layout under `name`; an existing workspace of that name is replaced in place.
    pub fn save_layout(&self, name: String, tabs: Vec<WorkspaceTabView>, selected: u32) -> FfiResult<WorkspaceView> {
        let tabs = tabs.into_iter().map(tab_from).collect::<FfiResult<Vec<_>>>()?;
        Ok(view(&self.lock().save_layout(&name, tabs, selected as usize, now())?))
    }

    /// Save Current Layout with tab groups: `tab_groups[i]` is tab i's group id in `groups_json`
    /// (`[{"id","name","color","collapsed","folder"}]`), or none.
    pub fn save_grouped_layout(&self, name: String, tabs: Vec<WorkspaceTabView>, tab_groups: Vec<Option<String>>, groups_json: String, selected: u32) -> FfiResult<WorkspaceView> {
        if tab_groups.len() != tabs.len() {
            return Err(FfiError::failed("one group entry per tab is required".into()));
        }
        let groups: Vec<TabGroup> = serde_json::from_str(&groups_json).map_err(|e| FfiError::failed(format!("invalid tab groups: {e}")))?;
        let tabs = tabs
            .into_iter()
            .zip(tab_groups)
            .map(|(t, g)| Ok(WorkspaceTab { group: g.as_deref().map(parse_id).transpose()?, ..tab_from(t)? }))
            .collect::<FfiResult<Vec<_>>>()?;
        Ok(view(&self.lock().save_grouped_layout(&name, tabs, groups, selected as usize, now())?))
    }

    pub fn rename(&self, id: String, name: String) -> FfiResult<()> {
        Ok(self.lock().rename(&parse_id(&id)?, &name)?)
    }

    pub fn duplicate(&self, id: String) -> FfiResult<WorkspaceView> {
        Ok(view(&self.lock().duplicate(&parse_id(&id)?)?))
    }

    pub fn remove(&self, id: String) -> FfiResult<()> {
        Ok(self.lock().remove(&parse_id(&id)?)?)
    }

    /// Add to Workspace: append one tab (`terminal` or `files`) for a saved connection.
    pub fn add_tab(&self, id: String, tab: WorkspaceTabView) -> FfiResult<WorkspaceView> {
        Ok(view(&self.lock().add_tab(&parse_id(&id)?, tab_from(tab)?)?))
    }

    /// Stamp the workspace as opened now.
    pub fn mark_used(&self, id: String) -> FfiResult<()> {
        Ok(self.lock().mark_used(&parse_id(&id)?, now())?)
    }

    /// New workspace with these tabs. Unlike `save_layout`, a name already used (any case) is
    /// refused.
    pub fn create(&self, name: String, tabs: Vec<WorkspaceTabView>) -> FfiResult<WorkspaceView> {
        let tabs = tabs.into_iter().map(tab_from).collect::<FfiResult<Vec<_>>>()?;
        Ok(view(&self.lock().create(&name, tabs, now())?))
    }

    /// What opening workspace `id` should do: `existing` = ids of connections in the library,
    /// `open` = live tabs. Deleted and already-open tabs are left out. Read-only: call
    /// `mark_used` once it is opened.
    pub fn restore_plan(&self, id: String, existing: Vec<String>, open: Vec<WorkspaceTabView>) -> FfiResult<WorkspaceRestorePlan> {
        let store = self.lock();
        let ws = store.get(&parse_id(&id)?).ok_or_else(|| FfiError::failed(format!("workspace {id} not found")))?;
        let existing: Vec<uuid::Uuid> = existing.iter().filter_map(|s| uuid::Uuid::parse_str(s).ok()).collect();
        let live = open.into_iter().map(tab_from).collect::<FfiResult<Vec<_>>>()?;
        let plan = ws.restore_plan(|c| existing.contains(c), |c, m| live.iter().any(|t| &t.connection == c && t.mode == m));
        Ok(WorkspaceRestorePlan { open: plan.open.iter().map(tab_view).collect(), missing: plan.missing as u32, select: plan.select.as_ref().map(tab_view) })
    }
}

/// See `WorkspaceStore::restore_plan`.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct WorkspaceRestorePlan {
    /// Tabs to connect, in order.
    pub open: Vec<WorkspaceTabView>,
    /// How many saved tabs were dropped because their connection was deleted.
    pub missing: u32,
    /// The saved tab to select, if it is still there.
    pub select: Option<WorkspaceTabView>,
}

impl WorkspaceStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, CoreStore> {
        self.store.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(layout: &[&str]) -> WorkspaceTabView {
        WorkspaceTabView {
            connection_id: uuid::Uuid::new_v4().to_string(),
            mode: "terminal".into(),
            layout: layout.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn open(d: &tempfile::TempDir) -> WorkspaceStore {
        WorkspaceStore::open(d.path().join("workspaces.json").to_string_lossy().into_owned()).unwrap()
    }

    #[test]
    fn create_refuses_a_used_name_and_restore_plan_skips_deleted_and_open_tabs() {
        let d = tempfile::tempdir().unwrap();
        let s = open(&d);
        let (a, b, gone) = (tab(&[]), tab(&["right", "leaf", "leaf"]), tab(&[]));
        let ws = s.create("Ops".into(), vec![a.clone(), b.clone(), gone.clone()]).unwrap();
        assert!(s.create("ops".into(), vec![a.clone()]).is_err(), "names are unique, any case");
        let plan = s.restore_plan(ws.id.clone(), vec![a.connection_id.clone(), b.connection_id.clone()], vec![a.clone()]).unwrap();
        assert_eq!(plan.missing, 1);
        assert_eq!(plan.open, vec![WorkspaceTabView { layout: vec!["right:0.500".into(), "leaf".into(), "leaf".into()], ..b }]);
        assert_eq!(plan.select.map(|t| t.connection_id), Some(a.connection_id));
        assert!(s.restore_plan(uuid::Uuid::new_v4().to_string(), vec![], vec![]).is_err());
    }

    #[test]
    fn layouts_round_trip_through_the_file() {
        let d = tempfile::tempdir().unwrap();
        let shape = ["right:0.620", "leaf", "down", "leaf", "leaf"];
        let saved = open(&d).save_layout("Ops".into(), vec![tab(&shape), tab(&[]), tab(&["leaf"])], 0).unwrap();
        assert!(saved.last_used.is_some());
        let again = open(&d).list();
        assert_eq!(again.len(), 1);
        assert_eq!(again[0].tabs[0].layout, ["right:0.620", "leaf", "down:0.500", "leaf", "leaf"], "a split without a ratio is even");
        assert!(again[0].tabs[1].layout.is_empty());
        assert!(again[0].tabs[2].layout.is_empty(), "a single leaf is stored as no layout");
    }

    #[test]
    fn malformed_layouts_and_modes_are_refused() {
        let d = tempfile::tempdir().unwrap();
        let s = open(&d);
        for bad in [&["right", "leaf"][..], &["leaf", "leaf"], &["sideways"], &["down"], &["right:wide", "leaf", "leaf"], &["leaf:0.5"]] {
            assert!(s.save_layout("x".into(), vec![tab(bad)], 0).is_err(), "{bad:?}");
        }
        let mut t = tab(&[]);
        t.mode = "desktop".into();
        assert!(s.save_layout("x".into(), vec![t], 0).is_err());
        assert!(s.list().is_empty());
    }

    #[test]
    fn ratios_out_of_range_are_clamped() {
        let d = tempfile::tempdir().unwrap();
        let s = open(&d);
        let saved = s.save_layout("x".into(), vec![tab(&["down:0.01", "leaf", "leaf"])], 0).unwrap();
        assert_eq!(saved.tabs[0].layout[0], "down:0.100");
    }

    #[test]
    fn rename_duplicate_remove_by_id() {
        let d = tempfile::tempdir().unwrap();
        let s = open(&d);
        let a = s.save_layout("A".into(), vec![], 0).unwrap();
        s.rename(a.id.clone(), "B".into()).unwrap();
        let c = s.duplicate(a.id.clone()).unwrap();
        assert_eq!(c.name, "B copy");
        s.mark_used(c.id.clone()).unwrap();
        s.remove(a.id.clone()).unwrap();
        assert_eq!(open(&d).list().iter().map(|w| w.name.clone()).collect::<Vec<_>>(), ["B copy"]);
        assert!(s.remove("not-an-id".into()).is_err());
    }

    #[test]
    fn add_tab_appends_and_refuses_duplicates() {
        let d = tempfile::tempdir().unwrap();
        let s = open(&d);
        let a = s.save_layout("A".into(), vec![tab(&[])], 0).unwrap();
        let t = tab(&[]);
        assert_eq!(s.add_tab(a.id.clone(), t.clone()).unwrap().tabs.len(), 2);
        assert!(s.add_tab(a.id.clone(), t).is_err());
        assert_eq!(open(&d).list()[0].tabs.len(), 2);
    }

    #[test]
    fn corrupt_file_fails_to_open() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("w.json");
        std::fs::write(&p, "{").unwrap();
        assert!(WorkspaceStore::open(p.to_string_lossy().into_owned()).is_err());
    }
}
