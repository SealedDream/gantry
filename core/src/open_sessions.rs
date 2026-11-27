//! The open-session set: the tabs (with splits, groups and cwd where known) a window has open,
//! saved on every change so the next launch can bring them back after a crash or force-quit.
//!
//! The file also carries a `running` flag. [`OpenSessionStore::begin`] sets it at launch and
//! [`OpenSessionStore::mark_clean_quit`] clears it, so a launch that finds it still set knows the
//! last run did not quit cleanly. After a crash the tabs always come back; after a clean quit the
//! `session.restore-on-launch` setting decides. After a clean quit restored tabs reconnect through
//! the usual [`ReconnectPolicy`](crate::session::ReconnectPolicy) ([`restore_reconnect_policy`]).
//! After a crash they come back disconnected and wait for the user (owner decision D15):
//! [`LaunchPlan::auto_reconnect`] is false.
//!
//! Tabs torn off into their own windows (B12) name their window; each window keeps its frame so
//! the next launch reopens it where it was (owner 2026-11-14). The core does not know the screens:
//! the app clamps a restored frame to a visible screen.
//!
//! It never holds secrets: connection ids, tab modes, pane layouts, group names, window frames and
//! a working directory. Credentials come from the vault or agent when a tab connects.
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

use crate::connection_history::ConnectionHistory;
use crate::error::{CoreError, Result};
use crate::model::{Document, Protocol};
use crate::session::ReconnectPolicy;
use crate::store::write_atomic;
use crate::tabgroups::TabGroup;
use crate::workspace::{PaneLayout, TabMode};

/// File name inside the app data directory.
pub const FILE_NAME: &str = "open-sessions.json";
/// The setting that decides restore after a clean quit.
pub const RESTORE_SETTING: &str = "session.restore-on-launch";
/// Tabs kept in the set.
pub const MAX_TABS: usize = 256;
/// Panes per tab.
pub const MAX_PANES: usize = 16;
/// Longest working directory kept, in characters.
pub const MAX_CWD_CHARS: usize = 1024;
/// Extra (torn-off) windows kept in the set.
pub const MAX_WINDOWS: usize = 64;
/// Largest window coordinate or size kept, in points; anything larger is refused as damaged.
pub const MAX_WINDOW_EXTENT: f64 = 1_000_000.0;
/// Recents returned when the caller asks for more.
pub const MAX_RECENTS: usize = 200;

/// One open tab.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenTab {
    pub connection: Uuid,
    pub mode: TabMode,
    /// Split panes of a terminal tab; absent means one pane.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layout: Option<PaneLayout>,
    /// The tab group (`OpenSessionSet::groups`) this tab is in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<Uuid>,
    /// Remote working directory when the terminal reported one (OSC 7).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// The extra window (`OpenSessionSet::windows`) this tab was torn off into; absent means the
    /// main window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window: Option<Uuid>,
}

/// An extra window holding torn-off tabs: where it was and which of its tabs was in front.
/// Frames are in the app's own screen coordinates (points), top-left origin on Windows and
/// bottom-left on the Mac; only the app that saved them reads them back.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedWindow {
    pub id: Uuid,
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
    /// Index into the set's `tabs` of this window's front tab, when it is one of its tabs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<usize>,
}

impl SavedWindow {
    fn frame_is_sane(&self) -> bool {
        let fine = |v: f64| v.is_finite() && v.abs() <= MAX_WINDOW_EXTENT;
        fine(self.x) && fine(self.y) && fine(self.width) && fine(self.height) && self.width > 0.0 && self.height > 0.0
    }
}

/// Everything open in the window.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct OpenSessionSet {
    pub tabs: Vec<OpenTab>,
    /// Index into `tabs` of the focused tab.
    pub selected: usize,
    pub groups: Vec<TabGroup>,
    /// Extra windows that hold at least one tab of `tabs`.
    pub windows: Vec<SavedWindow>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct File {
    /// Set from launch until a clean quit; still set at the next launch means a crash.
    running: bool,
    /// Unix seconds of the last save.
    saved_at: u64,
    set: OpenSessionSet,
}

/// Why the last run ended, as seen at launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LastExit {
    /// No saved set (first launch, or the file was unreadable).
    None,
    /// The app quit through `mark_clean_quit`.
    Clean,
    /// The app crashed, was force-quit or the machine lost power.
    Crash,
}

/// What a launch should do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LaunchPlan {
    pub last_exit: LastExit,
    /// True when tabs come back (always after a crash; after a clean quit, per the setting).
    pub restore: bool,
    /// Tabs to open, in order; their connections still exist. Empty when `restore` is false.
    pub tabs: Vec<OpenTab>,
    /// Index into `tabs` to focus, when the saved selection survived.
    pub selected: Option<usize>,
    /// Groups still used by `tabs`.
    pub groups: Vec<TabGroup>,
    /// Extra windows still holding a tab of `tabs`; `selected` indexes `tabs` of this plan.
    #[serde(default)]
    pub windows: Vec<SavedWindow>,
    /// Saved tabs dropped because their connection was deleted.
    pub missing: usize,
    /// True after a clean quit: restored tabs connect at once and retry with backoff
    /// ([`restore_reconnect_policy`]). False after a crash (owner decision D15): each remote tab
    /// comes back in its place, disconnected, and the app sends nothing to any host and releases
    /// no saved login until the user asks to connect that tab.
    pub auto_reconnect: bool,
}

/// The reconnect policy for restored tabs: the usual attempts and backoff, switched on.
pub fn restore_reconnect_policy() -> ReconnectPolicy {
    ReconnectPolicy { enabled: true, ..ReconnectPolicy::default() }
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn valid_cwd(cwd: Option<&str>) -> Result<Option<String>> {
    let Some(cwd) = cwd.map(str::trim).filter(|c| !c.is_empty()) else { return Ok(None) };
    if cwd.chars().count() > MAX_CWD_CHARS || cwd.chars().any(char::is_control) {
        return Err(CoreError::Invalid(format!("a working directory is one line of at most {MAX_CWD_CHARS} characters")));
    }
    Ok(Some(cwd.to_string()))
}

/// Checks a set from a frontend; returns the stored form (cwd trimmed, unused groups dropped,
/// selection clamped).
pub fn validated(set: OpenSessionSet) -> Result<OpenSessionSet> {
    if set.windows.len() > MAX_WINDOWS {
        return Err(CoreError::Invalid(format!("at most {MAX_WINDOWS} extra windows are saved")));
    }
    if set.windows.iter().any(|w| !w.frame_is_sane()) {
        return Err(CoreError::Invalid("a window frame is not a usable size or position".into()));
    }
    if set.tabs.len() > MAX_TABS {
        return Err(CoreError::Invalid(format!("at most {MAX_TABS} open tabs are saved")));
    }
    let mut tabs = Vec::with_capacity(set.tabs.len());
    for t in set.tabs {
        if t.layout.as_ref().is_some_and(|l| l.leaves() > MAX_PANES) {
            return Err(CoreError::Invalid(format!("a tab holds at most {MAX_PANES} panes")));
        }
        if t.mode == TabMode::Files && t.layout.is_some() {
            return Err(CoreError::Invalid("a files tab has no panes".into()));
        }
        if t.group.is_some_and(|g| !set.groups.iter().any(|x| x.id == g)) {
            return Err(CoreError::Invalid("a tab names a group the set does not have".into()));
        }
        if t.window.is_some_and(|w| !set.windows.iter().any(|x| x.id == w)) {
            return Err(CoreError::Invalid("a tab names a window the set does not have".into()));
        }
        let cwd = valid_cwd(t.cwd.as_deref())?;
        tabs.push(OpenTab { layout: t.layout.as_ref().map(PaneLayout::clamped), cwd, ..t });
    }
    let groups = set.groups.into_iter().filter(|g| tabs.iter().any(|t| t.group == Some(g.id))).collect();
    let selected = set.selected.min(tabs.len().saturating_sub(1));
    let windows = windows_in_use(set.windows, &tabs, Some);
    Ok(OpenSessionSet { tabs, selected, groups, windows })
}

/// Keeps the windows that still hold a tab, and each window's `selected` only when it still
/// names one of that window's tabs. `remap` turns an index of the old tab list into the new one.
fn windows_in_use(windows: Vec<SavedWindow>, tabs: &[OpenTab], remap: impl Fn(usize) -> Option<usize>) -> Vec<SavedWindow> {
    windows
        .into_iter()
        .filter(|w| tabs.iter().any(|t| t.window == Some(w.id)))
        .map(|w| {
            let selected = w.selected.and_then(&remap).filter(|&i| tabs.get(i).is_some_and(|t| t.window == Some(w.id)));
            SavedWindow { selected, ..w }
        })
        .collect()
}

/// The open-session file in the data directory.
pub struct OpenSessionStore {
    path: PathBuf,
}

impl OpenSessionStore {
    pub fn in_dir(data_dir: impl AsRef<Path>) -> Self {
        OpenSessionStore { path: data_dir.as_ref().join(FILE_NAME) }
    }

    /// `None` when missing or unreadable: a damaged file must never stop the app starting.
    fn load(&self) -> Option<File> {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok())
    }

    fn write(&self, f: &File) -> Result<()> {
        let json = serde_json::to_vec(f).map_err(|e| CoreError::Invalid(e.to_string()))?;
        write_atomic(&self.path, &json)
    }

    /// The saved set (empty when there is none).
    pub fn current(&self) -> OpenSessionSet {
        self.load().map(|f| f.set).unwrap_or_default()
    }

    /// Save the set after any change (tab opened, closed, moved, split, cwd changed). The write
    /// is atomic, so a crash mid-save leaves the previous set.
    pub fn save(&self, set: OpenSessionSet) -> Result<()> {
        let set = validated(set)?;
        self.write(&File { running: true, saved_at: now(), set })
    }

    /// Call on a clean quit, after the last `save`. Keeps the set for "restore on launch".
    pub fn mark_clean_quit(&self) -> Result<()> {
        let set = self.current();
        self.write(&File { running: false, saved_at: now(), set })
    }

    /// Call once at launch: works out what to restore and marks this run as started. When the
    /// plan restores nothing, the saved set is cleared so it is not offered again.
    /// `restore_on_launch` is the setting's value; `exists` says whether a connection is still
    /// in the library.
    pub fn begin(&self, restore_on_launch: bool, exists: impl Fn(&Uuid) -> bool) -> Result<LaunchPlan> {
        let file = self.load();
        let last_exit = match &file {
            None => LastExit::None,
            Some(f) if f.running => LastExit::Crash,
            Some(_) => LastExit::Clean,
        };
        let set = file.map(|f| f.set).unwrap_or_default();
        let restore = !set.tabs.is_empty() && (last_exit == LastExit::Crash || (last_exit == LastExit::Clean && restore_on_launch));
        let plan = if restore { plan_for(&set, last_exit, &exists) } else { LaunchPlan { last_exit, restore: false, tabs: vec![], selected: None, groups: vec![], windows: vec![], missing: 0, auto_reconnect: false } };
        let kept = if restore { OpenSessionSet { tabs: plan.tabs.clone(), selected: plan.selected.unwrap_or(0), groups: plan.groups.clone(), windows: plan.windows.clone() } } else { OpenSessionSet::default() };
        self.write(&File { running: true, saved_at: now(), set: kept })?;
        Ok(plan)
    }
}

fn plan_for(set: &OpenSessionSet, last_exit: LastExit, exists: &impl Fn(&Uuid) -> bool) -> LaunchPlan {
    let mut tabs = Vec::new();
    let mut selected = None;
    let mut new_index = vec![None; set.tabs.len()];
    for (i, t) in set.tabs.iter().enumerate() {
        if !exists(&t.connection) {
            continue;
        }
        if i == set.selected {
            selected = Some(tabs.len());
        }
        new_index[i] = Some(tabs.len());
        tabs.push(t.clone());
    }
    let windows = windows_in_use(set.windows.clone(), &tabs, |i| new_index.get(i).copied().flatten());
    let missing = set.tabs.len() - tabs.len();
    let groups = set.groups.iter().filter(|g| tabs.iter().any(|t| t.group == Some(g.id))).cloned().collect();
    // D15: after a crash nobody may be at the machine, so no session opens unasked.
    let auto_reconnect = last_exit != LastExit::Crash;
    LaunchPlan { last_exit, restore: true, tabs, selected, groups, windows, missing, auto_reconnect }
}

/// One row of the start page's "Recent sessions".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Recent {
    pub connection: Uuid,
    pub name: String,
    pub host: String,
    pub port: Option<u16>,
    /// Who it last logged in as, else the configured user.
    pub user: Option<String>,
    pub protocol: Protocol,
    /// Unix seconds of the last successful connect, else the last attempt.
    pub last_connected_at: u64,
    /// `None` when the last attempt succeeded.
    pub last_error: Option<String>,
}

/// Recent sessions from connection history, most recent first, at most `limit` (capped at
/// [`MAX_RECENTS`]). Connections no longer in `doc` are left out. "Remove from recents" is
/// [`ConnectionHistory::forget`].
pub fn recents(history: &ConnectionHistory, doc: &Document, limit: usize) -> Vec<Recent> {
    let all = history.all();
    let mut rows: Vec<Recent> = doc
        .connections()
        .into_iter()
        .filter_map(|r| {
            let h = all.get(&r.connection.id)?;
            let at = h.last_connected_at.or(h.last_attempt_at)?;
            Some(Recent {
                connection: r.connection.id,
                name: r.connection.name.clone(),
                host: r.connection.host.clone(),
                port: r.effective.port,
                user: h.last_user.clone().or(r.effective.username.clone()),
                protocol: r.connection.protocol,
                last_connected_at: at,
                last_error: h.last_error.clone(),
            })
        })
        .collect();
    rows.sort_by(|a, b| b.last_connected_at.cmp(&a.last_connected_at).then(a.name.cmp(&b.name)));
    rows.truncate(limit.min(MAX_RECENTS));
    rows
}

#[cfg(test)]
#[path = "open_sessions_tests.rs"]
mod tests;
