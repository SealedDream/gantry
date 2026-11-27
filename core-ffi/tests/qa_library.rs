//! Journey 2: public UniFFI library calls, with generated data only.
use bastion_ffi::Library;

#[test]
fn ten_deep_tree_move_duplicate_notes_and_order_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json").to_str().unwrap().to_owned();
    let lib = Library::open(path.clone()).unwrap();
    let mut parent = None;
    for depth in 0..10 {
        parent = Some(
            lib.add_folder(parent, format!("Folder {depth} 日本"))
                .unwrap(),
        );
    }
    let host = lib
        .add_connection(
            parent.clone(),
            "server 🖥".into(),
            "ssh".into(),
            "127.0.0.1".into(),
            Some(2222),
            Some("tester".into()),
        )
        .unwrap();
    lib.set_notes(host.clone(), "e\u{301} 中文 العربية\nnotes".into())
        .unwrap();
    let copy = lib.duplicate_node(host.clone()).unwrap();
    assert_ne!(copy, host);
    lib.rename(copy.clone(), "Copy renamed".into()).unwrap();
    lib.move_node_before(copy.clone(), None, None).unwrap();
    let another = lib
        .add_connection(
            None,
            "Other".into(),
            "vnc".into(),
            "127.0.0.1".into(),
            None,
            None,
        )
        .unwrap();
    lib.move_node_before(another.clone(), None, Some(copy.clone()))
        .unwrap();
    assert!(lib
        .move_node_before(parent.clone().unwrap(), parent.clone(), None)
        .is_err());
    lib.save().unwrap();
    drop(lib);
    let lib = Library::open(path).unwrap();
    let tree = lib.tree();
    assert_eq!(
        tree.connections
            .iter()
            .map(|c| c.id.as_str())
            .collect::<Vec<_>>(),
        [another.as_str(), copy.as_str()]
    );
    let mut folder = &tree;
    for depth in 0..10 {
        assert_eq!(folder.folders.len(), 1);
        folder = &folder.folders[0];
        assert_eq!(folder.name, format!("Folder {depth} 日本"));
    }
    assert_eq!(folder.connections[0].id, host);
    assert_eq!(
        lib.notes(copy.clone()).unwrap(),
        "e\u{301} 中文 العربية\nnotes"
    );
    lib.remove(copy).unwrap();
    lib.save().unwrap();
    assert_eq!(lib.tree().connections.len(), 1);
}
