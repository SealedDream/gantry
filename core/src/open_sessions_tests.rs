use super::*;
use crate::model::{Connection, Node};
use crate::tabgroups::GroupColor;

fn tab(c: Uuid) -> OpenTab {
    OpenTab { connection: c, mode: TabMode::Terminal, layout: None, group: None, cwd: None, window: None }
}

fn set(tabs: Vec<OpenTab>, selected: usize) -> OpenSessionSet {
    OpenSessionSet { tabs, selected, groups: vec![], windows: vec![] }
}

#[test]
fn first_launch_restores_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let plan = OpenSessionStore::in_dir(dir.path()).begin(true, |_| true).unwrap();
    assert_eq!(plan.last_exit, LastExit::None);
    assert!(!plan.restore && plan.tabs.is_empty() && !plan.auto_reconnect);
}

#[test]
fn a_crash_restores_even_when_the_setting_is_off() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    store.begin(true, |_| true).unwrap();
    store.save(set(vec![tab(a), OpenTab { cwd: Some(" /var/log ".into()), ..tab(b) }], 1)).unwrap();
    // No mark_clean_quit: the process died.
    let plan = OpenSessionStore::in_dir(dir.path()).begin(false, |_| true).unwrap();
    assert_eq!(plan.last_exit, LastExit::Crash);
    // D15: the tabs come back, but nothing signs in until the user asks.
    assert!(plan.restore && !plan.auto_reconnect);
    assert_eq!(plan.tabs.iter().map(|t| t.connection).collect::<Vec<_>>(), vec![a, b]);
    assert_eq!(plan.tabs[1].cwd.as_deref(), Some("/var/log"));
    assert_eq!(plan.selected, Some(1));
}

/// What the apps read: the plan as JSON. After a crash it says so and switches reconnecting off,
/// whatever the setting is; a second crash in a row is no different.
#[test]
fn the_plan_json_after_a_crash_tells_the_app_not_to_connect() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    store.save(set(vec![tab(Uuid::new_v4()), OpenTab { mode: TabMode::Files, ..tab(Uuid::new_v4()) }], 0)).unwrap();
    for restore_on_launch in [true, false] {
        // No mark_clean_quit between the launches: each one finds a run that died.
        let plan = store.begin(restore_on_launch, |_| true).unwrap();
        let json = serde_json::to_value(&plan).unwrap();
        assert_eq!((json["lastExit"].as_str(), json["restore"].as_bool(), json["autoReconnect"].as_bool()), (Some("crash"), Some(true), Some(false)));
        assert_eq!(json["tabs"].as_array().map(Vec::len), Some(2));
    }
}

/// A crash, then a normal quit: the next launch is an ordinary reopen and reconnects again.
#[test]
fn a_clean_quit_after_a_crash_reconnects_again() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    store.save(set(vec![tab(Uuid::new_v4())], 0)).unwrap();
    assert!(!store.begin(true, |_| true).unwrap().auto_reconnect);
    store.mark_clean_quit().unwrap();
    let plan = store.begin(true, |_| true).unwrap();
    assert_eq!(plan.last_exit, LastExit::Clean);
    assert!(plan.restore && plan.auto_reconnect);
}

#[test]
fn a_clean_quit_follows_the_setting() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    let a = Uuid::new_v4();
    store.save(set(vec![tab(a)], 0)).unwrap();
    store.mark_clean_quit().unwrap();
    let on = store.begin(true, |_| true).unwrap();
    assert_eq!(on.last_exit, LastExit::Clean);
    assert!(on.restore && on.tabs.len() == 1);
    assert!(on.auto_reconnect, "a normal quit and reopen reconnects as before");

    store.mark_clean_quit().unwrap();
    let off = store.begin(false, |_| true).unwrap();
    assert_eq!(off.last_exit, LastExit::Clean);
    assert!(!off.restore && off.tabs.is_empty() && !off.auto_reconnect);
    // Not restored = cleared, so a later crash does not bring back stale tabs.
    assert!(store.current().tabs.is_empty());
}

#[test]
fn deleted_connections_are_dropped_and_counted() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    let (a, gone, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let g = TabGroup { id: Uuid::new_v4(), name: "prod".into(), color: GroupColor::Red, collapsed: false, folder: None };
    store.save(OpenSessionSet { tabs: vec![tab(a), OpenTab { group: Some(g.id), ..tab(gone) }, tab(c)], selected: 1, groups: vec![g], windows: vec![] }).unwrap();
    let plan = store.begin(true, |id| *id != gone).unwrap();
    assert_eq!(plan.missing, 1);
    assert_eq!(plan.tabs.len(), 2);
    assert_eq!(plan.selected, None, "the selected tab was the deleted one");
    assert!(plan.groups.is_empty(), "the group only held the deleted tab");
}

#[test]
fn a_damaged_file_is_treated_as_none() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(FILE_NAME), b"{not json").unwrap();
    let plan = OpenSessionStore::in_dir(dir.path()).begin(true, |_| true).unwrap();
    assert_eq!(plan.last_exit, LastExit::None);
}

#[test]
fn invalid_sets_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    let a = Uuid::new_v4();
    assert!(store.save(set(vec![OpenTab { group: Some(Uuid::new_v4()), ..tab(a) }], 0)).is_err());
    assert!(store.save(set(vec![OpenTab { cwd: Some("/a\n/b".into()), ..tab(a) }], 0)).is_err());
    assert!(store.save(set(vec![tab(a); MAX_TABS + 1], 0)).is_err());
    store.save(set(vec![tab(a)], 9)).unwrap();
    assert_eq!(store.current().selected, 0, "selection past the end is clamped");
}

#[test]
fn the_file_holds_no_secrets_only_ids_and_layout() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    store.save(set(vec![tab(Uuid::new_v4())], 0)).unwrap();
    let text = std::fs::read_to_string(dir.path().join(FILE_NAME)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let keys: Vec<_> = v["set"]["tabs"][0].as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, vec!["connection", "mode"]);
    assert_eq!(v["running"], true);
}

#[test]
fn restore_policy_is_the_usual_one_switched_on() {
    let p = restore_reconnect_policy();
    let d = ReconnectPolicy::default();
    assert!(p.enabled);
    assert_eq!((p.max_attempts, p.initial, p.max_delay), (d.max_attempts, d.initial, d.max_delay));
}

#[test]
fn recents_are_newest_first_and_skip_deleted_connections() {
    let dir = tempfile::tempdir().unwrap();
    let history = ConnectionHistory::in_dir(dir.path());
    let mut doc = Document::new("t");
    let mut old = Connection::new("old", Protocol::Ssh, "10.0.0.1");
    old.settings.username = Some("cfg".into());
    let new = Connection::new("new", Protocol::Rdp, "10.0.0.2");
    let never = Connection::new("never", Protocol::Ssh, "10.0.0.3");
    let (o, n) = (old.id, new.id);
    for c in [old, new, never] {
        doc.insert(None, Node::Connection(c)).unwrap();
    }
    history.record_success(o, None, 100).unwrap();
    history.record_success(n, Some("appuser"), 200).unwrap();
    history.record_failure(n, "Timed out", 300).unwrap();
    history.record_success(Uuid::new_v4(), Some("x"), 400).unwrap(); // deleted connection

    let rows = recents(&history, &doc, 10);
    assert_eq!(rows.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(), vec!["new", "old"]);
    assert_eq!(rows[0].user.as_deref(), Some("appuser"));
    assert_eq!(rows[0].last_connected_at, 200);
    assert_eq!(rows[0].last_error.as_deref(), Some("Timed out"));
    assert_eq!(rows[0].port, Some(3389));
    assert_eq!(rows[1].user.as_deref(), Some("cfg"), "falls back to the configured user");
    assert_eq!(recents(&history, &doc, 1).len(), 1);

    history.forget(n).unwrap();
    assert_eq!(recents(&history, &doc, 10).len(), 1);
}

fn window(x: f64, selected: Option<usize>) -> SavedWindow {
    SavedWindow { id: Uuid::new_v4(), x, y: 40.0, width: 900.0, height: 600.0, selected }
}

#[test]
fn an_old_file_without_windows_still_restores() {
    let dir = tempfile::tempdir().unwrap();
    let a = Uuid::new_v4();
    let old = format!(r#"{{"running":true,"savedAt":1,"set":{{"tabs":[{{"connection":"{a}","mode":"terminal"}}],"selected":0,"groups":[]}}}}"#);
    std::fs::write(dir.path().join(FILE_NAME), old).unwrap();
    let plan = OpenSessionStore::in_dir(dir.path()).begin(true, |_| true).unwrap();
    assert_eq!(plan.tabs.len(), 1);
    assert_eq!(plan.tabs[0].window, None);
    assert!(plan.windows.is_empty());
}

#[test]
fn torn_off_windows_come_back_with_their_frames_and_front_tab() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    let (a, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (w1, w2) = (window(100.0, Some(2)), window(-1200.0, Some(1)));
    let tabs = vec![tab(a), OpenTab { window: Some(w2.id), ..tab(b) }, OpenTab { window: Some(w1.id), ..tab(c) }];
    store.begin(true, |_| true).unwrap();
    store.save(OpenSessionSet { tabs, selected: 0, groups: vec![], windows: vec![w1.clone(), w2.clone()] }).unwrap();
    store.mark_clean_quit().unwrap();
    let plan = OpenSessionStore::in_dir(dir.path()).begin(true, |_| true).unwrap();
    assert_eq!(plan.windows, vec![w1.clone(), w2.clone()], "frames, including one on a monitor left of the main one, are kept as saved");
    assert_eq!(plan.tabs[2].window, Some(w1.id));
    assert_eq!(OpenSessionStore::in_dir(dir.path()).current().windows.len(), 2, "begin keeps the windows for the next run");
}

#[test]
fn a_window_whose_tabs_are_all_gone_is_not_restored_and_indices_follow_the_tabs() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    let (gone, b, c) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (lonely, kept) = (window(0.0, Some(0)), window(50.0, Some(2)));
    let tabs = vec![OpenTab { window: Some(lonely.id), ..tab(gone) }, tab(b), OpenTab { window: Some(kept.id), ..tab(c) }];
    store.save(OpenSessionSet { tabs, selected: 1, groups: vec![], windows: vec![lonely, kept.clone()] }).unwrap();
    let plan = store.begin(true, |id| *id != gone).unwrap();
    assert_eq!(plan.windows.len(), 1);
    assert_eq!(plan.windows[0].id, kept.id);
    assert_eq!(plan.windows[0].selected, Some(1), "the front tab's index moved with the dropped tab");
    assert_eq!(plan.tabs[1].window, Some(kept.id));
}

#[test]
fn bad_windows_are_refused_or_cleaned() {
    let dir = tempfile::tempdir().unwrap();
    let store = OpenSessionStore::in_dir(dir.path());
    let a = Uuid::new_v4();
    let w = window(0.0, None);
    let with = |tabs: Vec<OpenTab>, windows: Vec<SavedWindow>| OpenSessionSet { tabs, selected: 0, groups: vec![], windows };
    assert!(store.save(with(vec![OpenTab { window: Some(Uuid::new_v4()), ..tab(a) }], vec![])).is_err(), "unknown window");
    for bad in [SavedWindow { width: 0.0, ..w.clone() }, SavedWindow { x: f64::NAN, ..w.clone() }, SavedWindow { height: 2.0 * MAX_WINDOW_EXTENT, ..w.clone() }] {
        assert!(store.save(with(vec![OpenTab { window: Some(bad.id), ..tab(a) }], vec![bad])).is_err());
    }
    let many: Vec<SavedWindow> = (0..=MAX_WINDOWS).map(|_| window(0.0, None)).collect();
    assert!(store.save(with(vec![tab(a)], many)).is_err());
    // An empty window is dropped; a front tab that is not the window's own is cleared.
    let used = window(0.0, Some(0));
    store.save(with(vec![tab(a), OpenTab { window: Some(used.id), ..tab(a) }], vec![w, used.clone()])).unwrap();
    let saved = store.current();
    assert_eq!(saved.windows.len(), 1);
    assert_eq!(saved.windows[0].selected, None);
}
