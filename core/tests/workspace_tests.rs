//! Workspace model.
use bastion_core::workspace::*;
use uuid::Uuid;

fn tab() -> WorkspaceTab {
    WorkspaceTab { connection: Uuid::new_v4(), mode: TabMode::Terminal, layout: None, group: None }
}

#[test]
fn save_reload_replace_and_remove() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspaces.json");
    let mut store = WorkspaceStore::open(&path).unwrap();
    assert!(store.list().is_empty());
    store.save(Workspace::new("Prod", vec![tab()]).unwrap()).unwrap();
    store.save(Workspace::new("prod", vec![tab(), tab()]).unwrap()).unwrap();
    let reopened = WorkspaceStore::open(&path).unwrap();
    assert_eq!(reopened.list().len(), 1, "same name (any case) replaces");
    assert_eq!(reopened.list()[0].tabs.len(), 2);
    let id = reopened.list()[0].id;
    let mut store = reopened;
    store.remove(&id).unwrap();
    assert!(WorkspaceStore::open(&path).unwrap().list().is_empty());
    assert!(store.remove(&id).is_err());
}

#[test]
fn rejects_bad_names_and_too_many_tabs() {
    assert!(Workspace::new("  ", vec![]).is_err());
    assert!(Workspace::new(&"x".repeat(121), vec![]).is_err());
    assert!(Workspace::new("big", (0..257).map(|_| tab()).collect()).is_err());
}

#[test]
fn restore_skips_deleted_connections() {
    let keep = tab();
    let ws = Workspace::new("w", vec![keep.clone(), tab()]).unwrap();
    assert_eq!(ws.restorable(|id| *id == keep.connection), vec![keep]);
}

#[test]
fn corrupt_file_is_an_error_not_silently_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("workspaces.json");
    std::fs::write(&path, b"{not json").unwrap();
    assert!(WorkspaceStore::open(&path).is_err());
}

#[test]
fn create_refuses_an_existing_name_any_case() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = WorkspaceStore::open(&dir.path().join("workspaces.json")).unwrap();
    store.create("Prod", vec![tab()], 1).unwrap();
    assert!(store.create(" prod ", vec![tab()], 2).is_err());
    assert_eq!(store.list().len(), 1);
    assert!(store.create("", vec![tab()], 2).is_err());
}

#[test]
fn restore_plan_skips_deleted_and_already_open_tabs() {
    let (a, b, gone) = (tab(), tab(), tab());
    let files = WorkspaceTab { mode: TabMode::Files, ..a.clone() };
    let mut ws = Workspace::new("W", vec![a.clone(), files.clone(), b.clone(), gone.clone()]).unwrap();
    ws.selected = 2;
    let exists = |id: &Uuid| *id != gone.connection;
    let plan = ws.restore_plan(exists, |id, mode| *id == a.connection && mode == TabMode::Terminal);
    assert_eq!(plan.open, vec![files, b.clone()]);
    assert_eq!(plan.missing, 1);
    assert_eq!(plan.select, Some(b));
    ws.selected = 3;
    assert_eq!(ws.restore_plan(exists, |_, _| false).select, None, "selected tab's connection was deleted");
}
