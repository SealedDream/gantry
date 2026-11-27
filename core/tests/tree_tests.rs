use bastion_core::model::{Connection, Document, Folder, Node, Protocol};
use bastion_core::store::Store;
use bastion_core::uistate::{UiState, UiStateStore};
use bastion_core::CoreError;
use uuid::Uuid;

fn folder(name: &str) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }
}

/// Root: Customers/{Acme/{a1, a2}, b1}, Lab/{l1}, top
fn sample() -> (Document, [Uuid; 8]) {
    let mut doc = Document::new("t");
    let (customers, acme, lab) = (folder("Customers"), folder("Acme"), folder("Lab"));
    let ids_f = [customers.id, acme.id, lab.id];
    doc.insert(None, Node::Folder(customers)).unwrap();
    doc.insert(Some(ids_f[0]), Node::Folder(acme)).unwrap();
    doc.insert(None, Node::Folder(lab)).unwrap();
    let mut add = |parent: Option<Uuid>, name: &str| {
        let c = Connection::new(name, Protocol::Ssh, format!("{name}.example"));
        let id = c.id;
        doc.insert(parent, Node::Connection(c)).unwrap();
        id
    };
    let a1 = add(Some(ids_f[1]), "a1");
    let a2 = add(Some(ids_f[1]), "a2");
    let b1 = add(Some(ids_f[0]), "b1");
    let l1 = add(Some(ids_f[2]), "l1");
    let top = add(None, "top");
    (doc, [ids_f[0], ids_f[1], ids_f[2], a1, a2, b1, l1, top])
}

fn names(f: &Folder) -> Vec<String> {
    f.children
        .iter()
        .map(|n| match n {
            Node::Folder(x) => x.name.clone(),
            Node::Connection(c) => c.name.clone(),
        })
        .collect()
}

#[test]
fn reorder_within_a_folder_and_move_before_a_sibling_in_another() {
    let (mut doc, [_, acme, lab, a1, a2, _, l1, _]) = sample();
    doc.move_node_before(a2, Some(acme), Some(a1)).unwrap();
    assert_eq!(names(doc.folder(acme).unwrap()), ["a2", "a1"]);
    doc.move_node_before(a1, Some(lab), Some(l1)).unwrap();
    assert_eq!(names(doc.folder(lab).unwrap()), ["a1", "l1"]);
    assert_eq!(doc.parent_of(a1), Some(lab));
    doc.move_node_before(a2, Some(lab), None).unwrap();
    assert_eq!(names(doc.folder(lab).unwrap()), ["a1", "l1", "a2"], "no anchor appends");
}

#[test]
fn invalid_moves_leave_the_tree_unchanged() {
    let (mut doc, [customers, acme, lab, a1, _, _, l1, _]) = sample();
    let before = doc.clone();
    assert!(matches!(doc.move_node_before(customers, Some(acme), None), Err(CoreError::Invalid(_))), "into own descendant");
    assert!(matches!(doc.move_node_before(customers, Some(customers), None), Err(CoreError::Invalid(_))), "into itself");
    assert!(matches!(doc.move_node_before(a1, Some(acme), Some(l1)), Err(CoreError::Invalid(_))), "anchor in another folder");
    assert!(doc.move_node_before(a1, Some(Uuid::new_v4()), None).is_err(), "unknown parent");
    let root = doc.root.id;
    assert!(doc.move_node_before(root, Some(lab), None).is_err(), "root");
    assert_eq!(doc, before);
}

#[test]
fn moving_a_folder_into_another_keeps_its_subtree() {
    let (mut doc, [customers, acme, lab, a1, ..]) = sample();
    doc.move_node_before(acme, Some(lab), None).unwrap();
    assert_eq!(names(doc.folder(customers).unwrap()), ["b1"]);
    assert_eq!(doc.resolve(a1).unwrap().path, ["Lab", "Acme"]);
}

#[test]
fn order_and_parents_survive_save_and_reload() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("lib.json"));
    let (mut doc, [_, acme, lab, a1, a2, ..]) = sample();
    doc.move_node_before(a2, Some(acme), Some(a1)).unwrap();
    let first = doc.root.children[0].id();
    doc.move_node_before(lab, None, Some(first)).unwrap();
    store.save(&doc).unwrap();
    let back = store.load().unwrap();
    assert_eq!(names(&back.root), ["Lab", "Customers", "top"]);
    assert_eq!(names(back.folder(acme).unwrap()), ["a2", "a1"]);
}

#[test]
fn rename_duplicate_folder_and_sort() {
    let (mut doc, [customers, acme, _, a1, a2, ..]) = sample();
    doc.rename(acme, "  Acme Corp ").unwrap();
    assert_eq!(doc.folder(acme).unwrap().name, "Acme Corp");
    doc.rename(a1, "zz").unwrap();
    assert!(matches!(doc.rename(a1, "   "), Err(CoreError::Invalid(_))));

    let copy = doc.duplicate_folder(acme).unwrap();
    assert_eq!(names(doc.folder(customers).unwrap()), ["Acme Corp", "Acme Corp (copy)", "b1"]);
    let dup = doc.folder(copy).unwrap();
    assert_eq!(names(dup), ["zz", "a2"]);
    assert!(dup.children.iter().all(|n| n.id() != a1 && n.id() != a2), "fresh ids in the copy");
    assert_eq!(doc.connections().len(), 7);
    let root = doc.root.id;
    assert!(doc.duplicate_folder(root).is_err());

    doc.sort_folder(acme, false).unwrap();
    assert_eq!(names(doc.folder(acme).unwrap()), ["a2", "zz"]);
    doc.sort_folder(root, true).unwrap();
    assert_eq!(names(&doc.root), ["Customers", "Lab", "top"]);
    assert_eq!(names(doc.folder(copy).unwrap()), ["a2", "zz"], "recursive sort reaches the copy");
}

#[test]
fn notes_are_saved_on_the_connection() {
    let (mut doc, [.., top]) = sample();
    doc.set_notes(top, "rack 4, port 12").unwrap();
    assert_eq!(doc.resolve(top).unwrap().connection.notes, "rack 4, port 12");
}

#[test]
fn ui_state_persists_expansion_and_prunes_deleted_folders() {
    let dir = tempfile::tempdir().unwrap();
    let store = UiStateStore::new(dir.path().join("ui-state.json"));
    assert_eq!(store.load(), UiState::default(), "missing file gives defaults");
    assert!(store.load().library_visible, "the library panel shows by default");
    assert!(!store.load().inspector_visible, "the inspector is hidden for new profiles");
    let (mut doc, [customers, acme, lab, ..]) = sample();
    let mut st = UiState::default();
    st.set_subtree_expanded(&doc, customers, true).unwrap();
    assert!(st.expanded.contains(&customers) && st.expanded.contains(&acme));
    st.expanded.insert(lab);
    st.inspector_visible = true;
    st.library_visible = false;
    store.save(&st).unwrap();
    let mut back = store.load();
    assert_eq!(back, st);

    doc.remove(acme).unwrap();
    back.prune(&doc);
    assert_eq!(back.expanded.len(), 2);
    let root = doc.root.id;
    back.set_subtree_expanded(&doc, root, false).unwrap();
    assert!(back.expanded.is_empty(), "collapse all from the root");

    std::fs::write(dir.path().join("ui-state.json"), "{not json").unwrap();
    assert_eq!(store.load(), UiState::default(), "corrupt view state falls back to defaults");
}
