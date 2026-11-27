use bastion_core::logexport::{export_snippet, MAX_SNIPPET_BYTES};

#[test]
fn writes_new_owner_only_file_and_never_overwrites() {
    let dir = tempfile::tempdir().unwrap();
    let a = export_snippet(dir.path(), "web-01", "web-01 2026-11-04 10:00", "\x1b[32mok\x1b[0m\r\nline 2  \n", true).unwrap();
    let b = export_snippet(dir.path(), "web-01", "", "second", true).unwrap();
    assert_eq!(a.file_name().unwrap(), "web-01.log");
    assert_eq!(b.file_name().unwrap(), "web-01-2.log");
    assert_eq!(std::fs::read_to_string(&a).unwrap(), "web-01 2026-11-04 10:00\nok\nline 2\n");
    assert_eq!(std::fs::read_to_string(&b).unwrap(), "second\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&a).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn name_hint_cannot_escape_the_folder() {
    let dir = tempfile::tempdir().unwrap();
    let p = export_snippet(dir.path(), "../../../tmp/evil", "", "x", true).unwrap();
    assert_eq!(p.parent().unwrap(), dir.path());
}

#[test]
fn refuses_empty_huge_and_missing_folder() {
    let dir = tempfile::tempdir().unwrap();
    assert!(export_snippet(dir.path(), "a", "", "\x1b[0m \n\n", true).is_err());
    assert!(export_snippet(dir.path(), "a", "", &"x".repeat(MAX_SNIPPET_BYTES + 1), true).is_err());
    assert!(export_snippet(&dir.path().join("missing"), "a", "", "x", true).is_err());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
