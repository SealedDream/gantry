//! `Library::node_view` matches the same node in `tree()` (patching the app's tree after an edit).
use bastion_ffi::{FolderView, Library, NodeView};

fn find(f: &FolderView, id: &str) -> Option<NodeView> {
    if let Some(i) = f.folders.iter().position(|x| x.id == id) {
        return Some(NodeView { parent_id: f.id.clone(), index: i as u32, folder: Some(f.folders[i].clone()), connection: None });
    }
    if let Some(i) = f.connections.iter().position(|x| x.id == id) {
        return Some(NodeView { parent_id: f.id.clone(), index: i as u32, folder: None, connection: Some(f.connections[i].clone()) });
    }
    f.folders.iter().find_map(|sub| find(sub, id))
}

#[test]
fn node_view_matches_tree_for_folders_connections_and_moves() {
    let dir = tempfile::tempdir().unwrap();
    let lib = Library::open(dir.path().join("l.json").to_string_lossy().into()).unwrap();
    let a = lib.add_folder(None, "A".into()).unwrap();
    let b = lib.add_folder(Some(a.clone()), "B".into()).unwrap();
    lib.add_connection(Some(a.clone()), "a1".into(), "ssh".into(), "h1".into(), None, Some("u".into())).unwrap();
    let c = lib.add_connection(Some(b.clone()), "b1".into(), "ssh".into(), "h2".into(), None, None).unwrap();
    let top = lib.add_folder(None, "Top".into()).unwrap();
    for id in [&a, &b, &c, &top] {
        assert_eq!(lib.node_view(id.clone()).unwrap(), find(&lib.tree(), id), "{id}");
    }
    lib.rename(b.clone(), "B2".into()).unwrap();
    lib.move_node(b.clone(), Some(top.clone())).unwrap();
    assert_eq!(lib.node_view(b.clone()).unwrap(), find(&lib.tree(), &b));
    assert_eq!(lib.node_view(c.clone()).unwrap(), find(&lib.tree(), &c));
    lib.remove(c.clone()).unwrap();
    assert_eq!(lib.node_view(c).unwrap(), None);
}
