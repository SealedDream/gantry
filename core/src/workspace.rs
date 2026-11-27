//! Workspaces: named sets of open sessions a user restores together. They are personal, so
//! they live in their own file next to the library (`workspaces.json`), never in a shared
//! document, and hold only connection ids and pane shapes — no hosts, users or secrets.
//! Restoring one goes through each connection's normal connect flow (credential prompt,
//! host key check), so a workspace never grants access a fresh connect would not.
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{CoreError, Result};
use crate::store::write_atomic;
use crate::tabgroups::{TabGroup, MAX_GROUP_NAME};

const MAX_NAME: usize = 120;
const MAX_TABS: usize = 256;
/// Panes in one tab's split tree.
const MAX_PANES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TabMode {
    Terminal,
    Files,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitAxis {
    /// Side by side.
    Right,
    /// Stacked.
    Down,
}

/// Share of a split given to its first side: what the divider allows, and the even split that
/// files from before ratios were saved get.
pub const RATIO_MIN: f32 = 0.1;
pub const RATIO_MAX: f32 = 0.9;
pub const RATIO_EVEN: f32 = 0.5;

fn even() -> f32 {
    RATIO_EVEN
}

/// Clamp into `RATIO_MIN..=RATIO_MAX`; a non-number becomes an even split.
pub fn clamp_ratio(r: f32) -> f32 {
    if r.is_finite() { r.clamp(RATIO_MIN, RATIO_MAX) } else { RATIO_EVEN }
}

/// Shape of a terminal tab's split tree. Every leaf is another shell on the tab's connection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase", tag = "kind")]
pub enum PaneLayout {
    Leaf,
    Split {
        axis: SplitAxis,
        /// Share of the split given to `first`.
        #[serde(default = "even")]
        ratio: f32,
        first: Box<PaneLayout>,
        second: Box<PaneLayout>,
    },
}

impl PaneLayout {
    /// The same tree with every ratio clamped (a hand-edited file can hold anything).
    pub fn clamped(&self) -> PaneLayout {
        match self {
            PaneLayout::Leaf => PaneLayout::Leaf,
            PaneLayout::Split { axis, ratio, first, second } => PaneLayout::Split {
                axis: *axis,
                ratio: clamp_ratio(*ratio),
                first: Box::new(first.clamped()),
                second: Box::new(second.clamped()),
            },
        }
    }

    /// Pre-order steps (`"leaf"`, `"right:0.620"`, `"down:0.500"`), the layout's wire form.
    pub fn steps(&self) -> Vec<String> {
        match self {
            PaneLayout::Leaf => vec!["leaf".into()],
            PaneLayout::Split { axis, ratio, first, second } => {
                let head = format!("{}:{ratio:.3}", if *axis == SplitAxis::Right { "right" } else { "down" });
                [vec![head], first.steps(), second.steps()].concat()
            }
        }
    }

    pub fn leaves(&self) -> usize {
        match self {
            PaneLayout::Leaf => 1,
            PaneLayout::Split { first, second, .. } => first.leaves() + second.leaves(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkspaceTab {
    pub connection: Uuid,
    pub mode: TabMode,
    /// Split panes of a terminal tab; absent means one pane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<PaneLayout>,
    /// The tab group (`Workspace::groups`) this tab is in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Workspace {
    pub id: Uuid,
    pub name: String,
    pub tabs: Vec<WorkspaceTab>,
    /// Index into `tabs` of the tab to focus on restore.
    #[serde(default)]
    pub selected: usize,
    /// Unix seconds of the last save or open; `None` for files from before this field.
    #[serde(default)]
    pub last_used: Option<i64>,
    /// Tab groups, restored with the tabs (`tabgroups`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<TabGroup>,
}

fn valid_name(name: &str) -> Result<String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(CoreError::Invalid(format!("workspace name must be 1–{MAX_NAME} characters")));
    }
    Ok(name.to_string())
}

fn valid_tabs(tabs: &[WorkspaceTab]) -> Result<()> {
    if tabs.len() > MAX_TABS {
        return Err(CoreError::Invalid(format!("a workspace holds at most {MAX_TABS} tabs")));
    }
    if tabs.iter().any(|t| t.layout.as_ref().is_some_and(|l| l.leaves() > MAX_PANES)) {
        return Err(CoreError::Invalid(format!("a tab holds at most {MAX_PANES} panes")));
    }
    if tabs.iter().any(|t| t.mode == TabMode::Files && t.layout.is_some()) {
        return Err(CoreError::Invalid("a files tab has no panes".into()));
    }
    Ok(())
}

fn valid_groups(tabs: &[WorkspaceTab], groups: &[TabGroup]) -> Result<()> {
    if groups.iter().any(|g| g.name.chars().count() > MAX_GROUP_NAME) {
        return Err(CoreError::Invalid(format!("a group name is at most {MAX_GROUP_NAME} characters")));
    }
    if tabs.iter().filter_map(|t| t.group).any(|g| !groups.iter().any(|x| x.id == g)) {
        return Err(CoreError::Invalid("a tab names a group the workspace does not have".into()));
    }
    Ok(())
}

/// Groups that still hold a tab; tabs naming a dropped group lose it (a hand-edited file).
fn kept_groups(w: Workspace) -> Workspace {
    let groups: Vec<TabGroup> = w.groups.iter().filter(|g| w.tabs.iter().any(|t| t.group == Some(g.id))).cloned().collect();
    let tabs = w.tabs.iter().map(|t| WorkspaceTab { group: t.group.filter(|g| groups.iter().any(|x| x.id == *g)), ..t.clone() }).collect();
    Workspace { tabs, groups, ..w }
}

impl Workspace {
    pub fn new(name: &str, tabs: Vec<WorkspaceTab>) -> Result<Self> {
        let name = valid_name(name)?;
        valid_tabs(&tabs)?;
        Ok(Workspace { id: Uuid::new_v4(), name, tabs, selected: 0, last_used: None, groups: vec![] })
    }

    /// Tabs whose connection still exists, for restoring after the library changed.
    pub fn restorable(&self, exists: impl Fn(&Uuid) -> bool) -> Vec<WorkspaceTab> {
        self.tabs.iter().filter(|t| exists(&t.connection)).cloned().collect()
    }

    /// What opening this workspace should do: the tabs to connect (their connection still exists
    /// and no live tab already shows it in that mode), how many were dropped because their
    /// connection was deleted, and the saved tab to select (if its connection still exists).
    pub fn restore_plan(&self, exists: impl Fn(&Uuid) -> bool, is_open: impl Fn(&Uuid, TabMode) -> bool) -> RestorePlan {
        let open = self.tabs.iter().filter(|t| exists(&t.connection) && !is_open(&t.connection, t.mode)).cloned().collect();
        let missing = self.tabs.iter().filter(|t| !exists(&t.connection)).count();
        let select = self.tabs.get(self.selected).filter(|t| exists(&t.connection)).cloned();
        RestorePlan { open, missing, select }
    }
}

/// See [`Workspace::restore_plan`].
#[derive(Debug, Clone, PartialEq)]
pub struct RestorePlan {
    pub open: Vec<WorkspaceTab>,
    pub missing: usize,
    pub select: Option<WorkspaceTab>,
}

fn clamped(w: Workspace) -> Workspace {
    let tabs = w.tabs.iter().map(|t| WorkspaceTab { layout: t.layout.as_ref().map(PaneLayout::clamped), ..t.clone() }).collect();
    kept_groups(Workspace { tabs, ..w })
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    workspaces: Vec<Workspace>,
}

/// The per-user workspace list on disk.
pub struct WorkspaceStore {
    path: PathBuf,
    workspaces: Vec<Workspace>,
}

impl WorkspaceStore {
    /// Open `path`, treating a missing file as empty.
    pub fn open(path: &Path) -> Result<Self> {
        let workspaces = match fs::read(path) {
            Ok(bytes) => serde_json::from_slice::<File>(&bytes).map_err(|e| CoreError::Corrupt(e.to_string()))?.workspaces.into_iter().map(clamped).collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(WorkspaceStore { path: path.to_path_buf(), workspaces })
    }

    pub fn list(&self) -> &[Workspace] {
        &self.workspaces
    }

    pub fn get(&self, id: &Uuid) -> Option<&Workspace> {
        self.workspaces.iter().find(|w| &w.id == id)
    }

    fn named(&self, name: &str) -> Option<&Workspace> {
        self.workspaces.iter().find(|w| w.name.eq_ignore_ascii_case(name))
    }

    fn existing(&self, id: &Uuid) -> Result<&Workspace> {
        self.get(id).ok_or_else(|| CoreError::NotFound(format!("workspace {id}")))
    }

    /// Insert or replace (by name, case-insensitive) and persist.
    pub fn save(&mut self, ws: Workspace) -> Result<()> {
        let mut next: Vec<Workspace> =
            self.workspaces.iter().filter(|w| !w.name.eq_ignore_ascii_case(&ws.name)).cloned().collect();
        next.push(ws);
        self.persist(next)
    }

    /// Save Current Layout: a workspace with this name keeps its id and position and gets the
    /// new tabs; otherwise a new one is appended. `selected` is clamped to the tabs.
    pub fn save_layout(&mut self, name: &str, tabs: Vec<WorkspaceTab>, selected: usize, now: i64) -> Result<Workspace> {
        self.save_grouped_layout(name, tabs, vec![], selected, now)
    }

    /// Save Current Layout with the strip's tab groups; each tab's `group` names one of `groups`.
    pub fn save_grouped_layout(&mut self, name: &str, tabs: Vec<WorkspaceTab>, groups: Vec<TabGroup>, selected: usize, now: i64) -> Result<Workspace> {
        let name = valid_name(name)?;
        valid_tabs(&tabs)?;
        valid_groups(&tabs, &groups)?;
        let selected = selected.min(tabs.len().saturating_sub(1));
        let shaped = clamped(Workspace { id: Uuid::nil(), name: String::new(), tabs, selected, last_used: None, groups });
        let (tabs, groups) = (shaped.tabs, shaped.groups);
        let saved = match self.named(&name) {
            Some(existing) => Workspace { tabs, selected, last_used: Some(now), groups, ..existing.clone() },
            None => Workspace { id: Uuid::new_v4(), name, tabs, selected, last_used: Some(now), groups },
        };
        let mut next = self.workspaces.clone();
        match next.iter().position(|w| w.id == saved.id) {
            Some(i) => next[i] = saved.clone(),
            None => next.push(saved.clone()),
        }
        self.persist(next)?;
        Ok(saved)
    }

    /// A new workspace holding `tabs`; unlike Save Current Layout, an existing name (any case)
    /// is refused rather than replaced.
    pub fn create(&mut self, name: &str, tabs: Vec<WorkspaceTab>, now: i64) -> Result<Workspace> {
        let name = valid_name(name)?;
        if self.named(&name).is_some() {
            return Err(CoreError::Invalid(format!("a workspace named “{name}” already exists")));
        }
        self.save_layout(&name, tabs, 0, now)
    }

    /// Rename, refusing a name another workspace already has.
    pub fn rename(&mut self, id: &Uuid, name: &str) -> Result<()> {
        let name = valid_name(name)?;
        self.existing(id)?;
        if self.named(&name).is_some_and(|w| &w.id != id) {
            return Err(CoreError::Invalid(format!("a workspace named “{name}” already exists")));
        }
        self.persist(self.replacing(id, |w| Workspace { name: name.clone(), ..w.clone() }))
    }

    /// Copy placed after the original, named "<name> copy" (then "copy 2", …).
    pub fn duplicate(&mut self, id: &Uuid) -> Result<Workspace> {
        let source = self.existing(id)?.clone();
        let base: String = source.name.chars().take(MAX_NAME - " copy 999".len()).collect();
        let name = (1..1000)
            .map(|n| if n == 1 { format!("{base} copy") } else { format!("{base} copy {n}") })
            .find(|n| self.named(n).is_none())
            .ok_or_else(|| CoreError::Invalid("too many copies of this workspace".into()))?;
        let copy = Workspace { id: Uuid::new_v4(), name, last_used: None, ..source };
        let at = self.workspaces.iter().position(|w| &w.id == id).map_or(self.workspaces.len(), |i| i + 1);
        let mut next = self.workspaces.clone();
        next.insert(at, copy.clone());
        self.persist(next)?;
        Ok(copy)
    }

    /// Add to Workspace: append `tab` to a saved workspace. A tab for the same connection and
    /// mode is refused (restoring would open it once anyway).
    pub fn add_tab(&mut self, id: &Uuid, tab: WorkspaceTab) -> Result<Workspace> {
        let ws = self.existing(id)?;
        if ws.tabs.iter().any(|t| t.connection == tab.connection && t.mode == tab.mode) {
            return Err(CoreError::Invalid(format!("“{}” already opens this connection", ws.name)));
        }
        let tabs: Vec<WorkspaceTab> = ws.tabs.iter().cloned().chain([WorkspaceTab { group: None, ..tab }]).collect();
        valid_tabs(&tabs)?;
        let updated = Workspace { tabs, ..ws.clone() };
        self.persist(self.replacing(id, |_| updated.clone()))?;
        Ok(updated)
    }

    /// Record that the workspace was opened.
    pub fn mark_used(&mut self, id: &Uuid, now: i64) -> Result<()> {
        self.existing(id)?;
        self.persist(self.replacing(id, |w| Workspace { last_used: Some(now), ..w.clone() }))
    }

    pub fn remove(&mut self, id: &Uuid) -> Result<()> {
        self.existing(id)?;
        let next = self.workspaces.iter().filter(|w| &w.id != id).cloned().collect();
        self.persist(next)
    }

    fn replacing(&self, id: &Uuid, change: impl Fn(&Workspace) -> Workspace) -> Vec<Workspace> {
        self.workspaces.iter().map(|w| if &w.id == id { change(w) } else { w.clone() }).collect()
    }

    fn persist(&mut self, workspaces: Vec<Workspace>) -> Result<()> {
        let file = File { workspaces };
        let bytes = serde_json::to_vec_pretty(&file).map_err(|e| CoreError::Corrupt(e.to_string()))?;
        write_atomic(&self.path, &bytes)?;
        self.workspaces = file.workspaces;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tab(mode: TabMode) -> WorkspaceTab {
        WorkspaceTab { connection: Uuid::new_v4(), mode, layout: None, group: None }
    }

    fn split(first: PaneLayout, second: PaneLayout) -> PaneLayout {
        PaneLayout::Split { axis: SplitAxis::Right, ratio: RATIO_EVEN, first: Box::new(first), second: Box::new(second) }
    }

    fn store() -> (tempfile::TempDir, WorkspaceStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = WorkspaceStore::open(&dir.path().join("workspaces.json")).unwrap();
        (dir, s)
    }

    fn reopen(d: &tempfile::TempDir) -> WorkspaceStore {
        WorkspaceStore::open(&d.path().join("workspaces.json")).unwrap()
    }

    #[test]
    fn missing_file_is_empty() {
        let (_d, s) = store();
        assert!(s.list().is_empty());
    }

    #[test]
    fn save_layout_persists_tabs_layout_and_time_across_reopen() {
        let (d, mut s) = store();
        let mut t = tab(TabMode::Terminal);
        t.layout = Some(split(PaneLayout::Leaf, PaneLayout::Split {
            axis: SplitAxis::Down, ratio: 0.7, first: Box::new(PaneLayout::Leaf), second: Box::new(PaneLayout::Leaf) }));
        let ws = s.save_layout("  Ops  ", vec![t.clone(), tab(TabMode::Files)], 1, 1_700_000_000).unwrap();
        assert_eq!(ws.name, "Ops");
        let again = reopen(&d);
        let w = again.get(&ws.id).unwrap();
        assert_eq!(w.tabs[0], t);
        assert_eq!(w.tabs[0].layout.as_ref().unwrap().leaves(), 3);
        assert_eq!((w.selected, w.last_used), (1, Some(1_700_000_000)));
    }

    #[test]
    fn save_layout_with_existing_name_keeps_id_and_position() {
        let (_d, mut s) = store();
        let a = s.save_layout("Alpha", vec![tab(TabMode::Terminal)], 0, 1).unwrap();
        s.save_layout("Beta", vec![], 0, 2).unwrap();
        let again = s.save_layout("alpha", vec![tab(TabMode::Files), tab(TabMode::Files)], 9, 3).unwrap();
        assert_eq!(again.id, a.id);
        assert_eq!(again.name, "Alpha");
        assert_eq!(again.selected, 1, "selected is clamped to the tabs");
        assert_eq!(s.list().iter().map(|w| w.name.as_str()).collect::<Vec<_>>(), ["Alpha", "Beta"]);
        assert_eq!(s.list()[0].tabs.len(), 2);
    }

    #[test]
    fn invalid_names_and_sizes_are_refused() {
        let (_d, mut s) = store();
        assert!(s.save_layout("   ", vec![], 0, 0).is_err());
        assert!(s.save_layout(&"x".repeat(MAX_NAME + 1), vec![], 0, 0).is_err());
        assert!(s.save_layout("big", (0..=MAX_TABS).map(|_| tab(TabMode::Terminal)).collect(), 0, 0).is_err());
        let mut deep = PaneLayout::Leaf;
        for _ in 0..MAX_PANES {
            deep = split(deep, PaneLayout::Leaf);
        }
        let mut t = tab(TabMode::Terminal);
        t.layout = Some(deep);
        assert!(s.save_layout("panes", vec![t], 0, 0).is_err());
        let mut f = tab(TabMode::Files);
        f.layout = Some(PaneLayout::Leaf);
        assert!(s.save_layout("files", vec![f], 0, 0).is_err());
        assert!(s.list().is_empty(), "nothing invalid was written");
    }

    #[test]
    fn rename_refuses_another_workspaces_name_but_allows_case_change() {
        let (d, mut s) = store();
        let a = s.save_layout("Alpha", vec![], 0, 0).unwrap();
        s.save_layout("Beta", vec![], 0, 0).unwrap();
        assert!(s.rename(&a.id, "BETA").is_err());
        assert!(s.rename(&a.id, " ").is_err());
        s.rename(&a.id, "ALPHA").unwrap();
        s.rename(&a.id, "Gamma").unwrap();
        assert_eq!(reopen(&d).get(&a.id).unwrap().name, "Gamma");
        assert!(s.rename(&Uuid::new_v4(), "x").is_err());
    }

    #[test]
    fn duplicate_names_copies_and_inserts_after_original() {
        let (_d, mut s) = store();
        let a = s.save_layout("Alpha", vec![tab(TabMode::Terminal)], 0, 5).unwrap();
        s.save_layout("Beta", vec![], 0, 0).unwrap();
        let c1 = s.duplicate(&a.id).unwrap();
        let c2 = s.duplicate(&a.id).unwrap();
        assert_eq!((c1.name.as_str(), c2.name.as_str()), ("Alpha copy", "Alpha copy 2"));
        assert_ne!(c1.id, a.id);
        assert_eq!(c1.tabs, a.tabs);
        assert_eq!(c1.last_used, None);
        assert_eq!(s.list().iter().map(|w| w.name.as_str()).collect::<Vec<_>>(), ["Alpha", "Alpha copy 2", "Alpha copy", "Beta"]);
        assert!(s.duplicate(&Uuid::new_v4()).is_err());
    }

    #[test]
    fn duplicate_of_a_maximum_length_name_stays_valid() {
        let (_d, mut s) = store();
        let a = s.save_layout(&"n".repeat(MAX_NAME), vec![], 0, 0).unwrap();
        let c = s.duplicate(&a.id).unwrap();
        assert!(c.name.chars().count() <= MAX_NAME);
    }

    #[test]
    fn add_tab_appends_once_per_connection_and_mode() {
        let (d, mut s) = store();
        let first = tab(TabMode::Terminal);
        let a = s.save_layout("Alpha", vec![first.clone()], 0, 7).unwrap();
        let added = tab(TabMode::Terminal);
        let w = s.add_tab(&a.id, added.clone()).unwrap();
        assert_eq!(w.tabs, vec![first.clone(), added.clone()]);
        assert_eq!((w.selected, w.last_used), (0, Some(7)), "selection and time unchanged");
        assert_eq!(reopen(&d).get(&a.id).unwrap().tabs.len(), 2);
        assert!(s.add_tab(&a.id, added.clone()).is_err(), "same connection and mode twice");
        let files = WorkspaceTab { mode: TabMode::Files, ..added };
        assert_eq!(s.add_tab(&a.id, files).unwrap().tabs.len(), 3);
        assert!(s.add_tab(&Uuid::new_v4(), first).is_err());
        let full = s.save_layout("Full", (0..MAX_TABS).map(|_| tab(TabMode::Terminal)).collect(), 0, 0).unwrap();
        assert!(s.add_tab(&full.id, tab(TabMode::Terminal)).is_err());
    }

    #[test]
    fn mark_used_and_remove() {
        let (d, mut s) = store();
        let a = s.save_layout("Alpha", vec![], 0, 1).unwrap();
        s.mark_used(&a.id, 99).unwrap();
        assert_eq!(reopen(&d).get(&a.id).unwrap().last_used, Some(99));
        s.remove(&a.id).unwrap();
        assert!(s.remove(&a.id).is_err());
        assert!(s.mark_used(&a.id, 1).is_err());
        assert!(reopen(&d).list().is_empty());
    }

    #[test]
    fn reads_files_written_before_layouts_and_last_used() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("workspaces.json");
        let id = Uuid::new_v4();
        fs::write(&p, format!(r#"{{"workspaces":[{{"id":"{id}","name":"Old","tabs":[{{"connection":"{id}","mode":"terminal"}}]}}]}}"#)).unwrap();
        let s = WorkspaceStore::open(&p).unwrap();
        let w = s.get(&id).unwrap();
        assert_eq!((w.selected, w.last_used, w.tabs[0].layout.clone()), (0, None, None));
    }

    #[test]
    fn ratios_are_clamped_on_save_and_default_to_even_in_old_files() {
        let (d, mut s) = store();
        let mut t = tab(TabMode::Terminal);
        t.layout = Some(PaneLayout::Split { axis: SplitAxis::Down, ratio: 2.0, first: Box::new(PaneLayout::Leaf), second: Box::new(PaneLayout::Leaf) });
        s.save_layout("w", vec![t], 0, 0).unwrap();
        let ratio = |s: &WorkspaceStore| match s.list()[0].tabs[0].layout {
            Some(PaneLayout::Split { ratio, .. }) => ratio,
            _ => panic!("split expected"),
        };
        assert_eq!(ratio(&s), RATIO_MAX);
        assert_eq!(ratio(&reopen(&d)), RATIO_MAX);
        assert_eq!(clamp_ratio(f32::NAN), RATIO_EVEN);

        let p = d.path().join("old.json");
        let id = Uuid::new_v4();
        fs::write(&p, format!(r#"{{"workspaces":[{{"id":"{id}","name":"Old","tabs":[{{"connection":"{id}","mode":"terminal","layout":{{"kind":"split","axis":"right","first":{{"kind":"leaf"}},"second":{{"kind":"leaf"}}}}}}]}}]}}"#)).unwrap();
        let old = WorkspaceStore::open(&p).unwrap();
        assert!(matches!(old.list()[0].tabs[0].layout, Some(PaneLayout::Split { ratio, .. }) if ratio == RATIO_EVEN));
    }

    #[test]
    fn corrupt_file_is_an_error_not_an_empty_list() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("workspaces.json");
        fs::write(&p, b"{not json").unwrap();
        assert!(matches!(WorkspaceStore::open(&p), Err(CoreError::Corrupt(_))));
    }

    #[test]
    fn restorable_drops_missing_connections() {
        let keep = tab(TabMode::Terminal);
        let ws = Workspace::new("w", vec![keep.clone(), tab(TabMode::Files)]).unwrap();
        assert_eq!(ws.restorable(|id| *id == keep.connection), vec![keep]);
    }
}
