//! Journey 3: import through the app-facing bridge, with files confined to a temporary dir.
use bastion_ffi::Library;

#[test]
fn rejected_import_does_not_mutate_the_library_or_input() {
    let dir = tempfile::tempdir().unwrap();
    let lib = Library::open(dir.path().join("library.json").to_str().unwrap().into()).unwrap();
    let source = dir.path().join("broken.csv");
    let bytes = b"name,host,protocol,password\nlab,127.0.0.1,ssh,generated-test-secret\n";
    std::fs::write(&source, bytes).unwrap();
    assert!(lib.import_file(source.to_str().unwrap().into()).is_err());
    assert!(lib.tree().folders.is_empty());
    assert!(lib.tree().connections.is_empty());
    assert_eq!(std::fs::read(source).unwrap(), bytes);
}

#[test]
fn reimporting_the_same_csv_deduplicates_connections() {
    let dir = tempfile::tempdir().unwrap();
    let lib = Library::open(dir.path().join("library.json").to_str().unwrap().into()).unwrap();
    let source = dir.path().join("lab.csv");
    std::fs::write(&source, "name,host,protocol\nlab,127.0.0.1,ssh\n").unwrap();
    lib.import_file(source.to_str().unwrap().into()).unwrap();
    lib.import_file(source.to_str().unwrap().into()).unwrap();
    let tree = lib.tree();
    assert_eq!(
        tree.folders
            .iter()
            .map(|f| f.connections.len())
            .sum::<usize>(),
        1
    );
}
