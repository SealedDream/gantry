//! Workspaces over the C ABI (ABI v10; split layouts with ratios, Add to Workspace, rename, duplicate
//! and last-used since v16): named sets of open connection tabs, kept per user in
//! `<data dir>/workspaces.json` by `core::workspace::WorkspaceStore`.
//!
//! A workspace holds connection ids and a tab mode only: no hosts, users or secrets. Reopening one
//! is the host's job and goes through its normal Connect flow for each tab, so nothing logs in on
//! its own. Tabs whose connection was deleted since are reported, not opened.
use std::ffi::c_char;
use std::path::{Path, PathBuf};

use bastion_core::workspace::{PaneLayout, TabMode, Workspace, WorkspaceStore, WorkspaceTab};
use bastion_ffi::{WorkspaceStore as LayoutStore, WorkspaceTabView, WorkspaceView};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{guarded, required, set_ok, to_c};

fn store_path(data_dir: &str) -> Result<PathBuf, String> {
    if data_dir.trim().is_empty() {
        return Err("data_dir is required".into());
    }
    Ok(Path::new(data_dir).join("workspaces.json"))
}

fn open(data_dir: &str) -> Result<WorkspaceStore, String> {
    WorkspaceStore::open(&store_path(data_dir)?).map_err(|e| e.to_string())
}

fn open_layouts(data_dir: &str) -> Result<LayoutStore, String> {
    LayoutStore::open(store_path(data_dir)?.to_string_lossy().into_owned()).map_err(|e| e.to_string())
}

fn workspace_json(w: &WorkspaceView) -> Value {
    json!({
        "id": w.id,
        "name": w.name,
        "selected": w.selected,
        "lastUsed": w.last_used,
        "tabs": w.tabs.iter().zip(&w.tab_groups).map(|(t, g)| json!({ "connection": t.connection_id, "mode": t.mode, "layout": t.layout, "group": g })).collect::<Vec<_>>(),
        "groups": serde_json::from_str::<Value>(&w.groups_json).unwrap_or_else(|_| json!([])),
    })
}

/// Every workspace as JSON: `[{"id","name","selected","lastUsed","tabs":[{"connection","mode","layout"}]}]`,
/// where `mode` is `terminal` or `files`, `lastUsed` Unix seconds or null, and `layout` (v16) the tab's
/// split panes in pre-order: `"leaf"`, or `"right:0.620"` / `"down:0.500"` followed by its two children
/// (the ratio is the first child's share, clamped 0.1–0.9); `[]` = one pane. Free the result with
/// `bastion_string_free`.
///
/// # Safety
/// `data_dir` valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspaces_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let list: Vec<Value> = open_layouts(&required(data_dir, "data_dir")?)?.list().iter().map(workspace_json).collect();
        Ok(to_c(Value::Array(list).to_string()))
    })
}

fn tab_view(v: &Value) -> Result<WorkspaceTabView, String> {
    let o = v.as_object().ok_or_else(|| format!("{v} is not a tab"))?;
    let text = |k: &str| o.get(k).and_then(Value::as_str);
    Ok(WorkspaceTabView {
        connection_id: text("connection").ok_or_else(|| format!("{v} has no connection id"))?.to_string(),
        mode: text("mode").unwrap_or("terminal").to_string(),
        layout: match o.get("layout") {
            None | Some(Value::Null) => vec![],
            Some(Value::Array(a)) => a.iter().map(|s| s.as_str().map(str::to_string).ok_or_else(|| "layout steps are strings".to_string())).collect::<Result<_, _>>()?,
            Some(_) => return Err("layout must be an array".into()),
        },
    })
}

/// Save Current Layout (v16): `tabs_json` = `[{"connection","mode","layout"}]` as in
/// [`bastion_workspaces_json`]. A workspace with this name (any case) keeps its id and place and gets the
/// new tabs; otherwise one is appended. Marks it used now. Returns the workspace as JSON; NULL and `*err`
/// on a bad name, layout, mode or id, or more than 256 tabs.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_save_layout(data_dir: *const c_char, name: *const c_char, tabs_json: *const c_char, selected: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let store = open_layouts(&required(data_dir, "data_dir")?)?;
        let tabs: Vec<Value> = serde_json::from_str(&required(tabs_json, "tabs_json")?).map_err(|_| "tabs_json must be a JSON array".to_string())?;
        let tabs = tabs.iter().map(tab_view).collect::<Result<Vec<_>, _>>()?;
        let saved = store.save_layout(required(name, "name")?, tabs, selected).map_err(|e| e.to_string())?;
        Ok(to_c(workspace_json(&saved).to_string()))
    })
}

/// Save Current Layout with tab groups (v32): as [`bastion_workspace_save_layout`], where each tab may
/// carry `"group"` (an id from `groups_json`, `[{"id","name","color","collapsed","folder"}]`). The
/// workspace JSON returned (and listed) has `group` on each tab and `groups`.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_save_grouped_layout(
    data_dir: *const c_char,
    name: *const c_char,
    tabs_json: *const c_char,
    groups_json: *const c_char,
    selected: u32,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let store = open_layouts(&required(data_dir, "data_dir")?)?;
        let tabs: Vec<Value> = serde_json::from_str(&required(tabs_json, "tabs_json")?).map_err(|_| "tabs_json must be a JSON array".to_string())?;
        let groups = tabs.iter().map(|t| t.get("group").and_then(Value::as_str).map(str::to_string)).collect();
        let tabs = tabs.iter().map(tab_view).collect::<Result<Vec<_>, _>>()?;
        let saved = store.save_grouped_layout(required(name, "name")?, tabs, groups, required(groups_json, "groups_json")?, selected).map_err(|e| e.to_string())?;
        Ok(to_c(workspace_json(&saved).to_string()))
    })
}

/// Add to Workspace (v16): append one `{"connection","mode"}` tab to workspace `id`. A tab for the same
/// connection and mode is refused. Returns the workspace as JSON, or NULL and `*err`.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_add_tab(data_dir: *const c_char, id: *const c_char, tab_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let store = open_layouts(&required(data_dir, "data_dir")?)?;
        let tab: Value = serde_json::from_str(&required(tab_json, "tab_json")?).map_err(|_| "tab_json must be a JSON object".to_string())?;
        let saved = store.add_tab(required(id, "id")?, tab_view(&tab)?).map_err(|e| e.to_string())?;
        Ok(to_c(workspace_json(&saved).to_string()))
    })
}

/// Rename workspace `id` (v16), refusing a name another workspace has. 0 / -1.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_rename(data_dir: *const c_char, id: *const c_char, name: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        open_layouts(&required(data_dir, "data_dir")?)?.rename(required(id, "id")?, required(name, "name")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Duplicate workspace `id` as "<name> copy" right after it (v16). Returns the copy as JSON.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_duplicate(data_dir: *const c_char, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let copy = open_layouts(&required(data_dir, "data_dir")?)?.duplicate(required(id, "id")?).map_err(|e| e.to_string())?;
        Ok(to_c(workspace_json(&copy).to_string()))
    })
}

/// Record that workspace `id` was opened (v16; the manager sorts by it). 0 / -1.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_mark_used(data_dir: *const c_char, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        open_layouts(&required(data_dir, "data_dir")?)?.mark_used(required(id, "id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Save `connection_ids_json` (a JSON array, in tab order, of connection ids for terminal tabs or,
/// since v12, `{"connection": id, "mode": "terminal"|"files"}` objects) as the tabs
/// of workspace `name`, replacing a workspace of the same name (case-insensitive). `selected` is
/// the index of the tab to focus on reopen. Returns the new workspace id; NULL and `*err` on
/// failure (empty or overlong name, more than 64 tabs, a value that is not a connection id).
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_save(data_dir: *const c_char, name: *const c_char, connection_ids_json: *const c_char, selected: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let mut store = open(&required(data_dir, "data_dir")?)?;
        let name = required(name, "name")?;
        let ids: Vec<serde_json::Value> = serde_json::from_str(&required(connection_ids_json, "connection_ids_json")?).map_err(|_| "connection_ids_json must be a JSON array of ids".to_string())?;
        let tabs = ids
            .iter()
            .map(tab_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let count = tabs.len();
        let mut ws = Workspace::new(&name, tabs).map_err(|e| e.to_string())?;
        ws.selected = (selected as usize).min(count.saturating_sub(1));
        let id = ws.id.to_string();
        store.save(ws).map_err(|e| e.to_string())?;
        Ok(to_c(id))
    })
}

/// Delete workspace `id`. 0 / -1.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_remove(data_dir: *const c_char, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let mut store = open(&required(data_dir, "data_dir")?)?;
        let id = Uuid::parse_str(&required(id, "id")?).map_err(|_| "not a workspace id".to_string())?;
        store.remove(&id).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// One saved tab: a bare connection id (a terminal tab) or `{"connection": id, "mode": "terminal"|"files"}`.
fn tab_entry(v: &serde_json::Value) -> Result<WorkspaceTab, String> {
    let (id, mode) = match v {
        serde_json::Value::String(id) => (id.as_str(), "terminal"),
        serde_json::Value::Object(o) => (
            o.get("connection").and_then(|c| c.as_str()).ok_or_else(|| format!("{v} has no connection id"))?,
            o.get("mode").and_then(|m| m.as_str()).unwrap_or("terminal"),
        ),
        _ => return Err(format!("{v} is not a connection id")),
    };
    let connection = Uuid::parse_str(id).map_err(|_| format!("{id} is not a connection id"))?;
    let mode = match mode {
        "terminal" => TabMode::Terminal,
        "files" => TabMode::Files,
        other => return Err(format!("unknown tab mode {other}")),
    };
    Ok(WorkspaceTab { connection, mode, layout: None, group: None })
}

fn mode_name(m: TabMode) -> &'static str {
    match m {
        TabMode::Terminal => "terminal",
        TabMode::Files => "files",
    }
}

/// New workspace with one or more tabs (v61): `tabs_json` as in [`bastion_workspace_save`]. Unlike Save
/// Current Layout, a name already used (any case) is refused. Returns the workspace id, or NULL and `*err`.
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_create(data_dir: *const c_char, name: *const c_char, tabs_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let mut store = open(&required(data_dir, "data_dir")?)?;
        let tabs: Vec<Value> = serde_json::from_str(&required(tabs_json, "tabs_json")?).map_err(|_| "tabs_json must be a JSON array".to_string())?;
        let tabs = tabs.iter().map(tab_entry).collect::<Result<Vec<_>, _>>()?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
        Ok(to_c(store.create(&required(name, "name")?, tabs, now).map_err(|e| e.to_string())?.id.to_string()))
    })
}

/// What opening workspace `id` should do (v61). `existing_json` = ids of connections in the library;
/// `open_json` = live tabs as `[{"connection","mode"}]`. Returns
/// `{"open":[{"connection","mode","layout"}],"missing":n,"select":{"connection","mode"}|null}`: tabs to
/// connect in order (deleted or already-open ones left out), how many were dropped as deleted, and the
/// saved tab to select. Read-only: mark it used with [`bastion_workspace_mark_used`].
///
/// # Safety
/// Strings valid UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_workspace_restore_plan_json(
    data_dir: *const c_char,
    id: *const c_char,
    existing_json: *const c_char,
    open_json: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let store = open(&required(data_dir, "data_dir")?)?;
        let id = Uuid::parse_str(&required(id, "id")?).map_err(|_| "not a workspace id".to_string())?;
        let ws = store.get(&id).ok_or_else(|| format!("workspace {id} not found"))?;
        let existing: Vec<String> = serde_json::from_str(&required(existing_json, "existing_json")?).map_err(|_| "existing_json must be an array of ids".to_string())?;
        let existing: Vec<Uuid> = existing.iter().filter_map(|s| Uuid::parse_str(s).ok()).collect();
        let live: Vec<Value> = serde_json::from_str(&required(open_json, "open_json")?).map_err(|_| "open_json must be a JSON array".to_string())?;
        let live = live.iter().map(tab_entry).collect::<Result<Vec<_>, _>>()?;
        let plan = ws.restore_plan(|c| existing.contains(c), |c, m| live.iter().any(|t| &t.connection == c && t.mode == m));
        let tab = |t: &WorkspaceTab| json!({ "connection": t.connection.to_string(), "mode": mode_name(t.mode), "layout": t.layout.as_ref().map_or_else(Vec::new, PaneLayout::steps) });
        Ok(to_c(json!({ "open": plan.open.iter().map(tab).collect::<Vec<_>>(), "missing": plan.missing, "select": plan.select.as_ref().map(|t| json!({ "connection": t.connection.to_string(), "mode": mode_name(t.mode) })) }).to_string()))
    })
}
