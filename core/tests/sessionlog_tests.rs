use bastion_core::sessionlog::{LogOptions, SessionLog};

fn read(p: &std::path::Path) -> String {
    std::fs::read_to_string(p).unwrap()
}

#[test]
fn owner_only_refuses_existing_and_flushes_partial_line() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.log");
    let mut log = SessionLog::create(&path, "# header", LogOptions::default()).unwrap();
    log.write(b"one\r\ntw").unwrap();
    log.write(b"o\nprompt$ ").unwrap();
    log.finish().unwrap();
    assert_eq!(read(&path), "# header\none\r\ntwo\nprompt$ \n");
    assert!(SessionLog::create(&path, "", LogOptions::default()).is_err(), "never overwrites");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn prompt_split_across_chunks_is_still_redacted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.log");
    let mut log = SessionLog::create(&path, "#", LogOptions::default()).unwrap();
    for chunk in [&b"Pass"[..], b"word: hun", b"ter2\r\n", b"after\n"] {
        log.write(chunk).unwrap();
    }
    log.finish().unwrap();
    let text = read(&path);
    assert!(!text.contains("hunter2"), "{text}");
    assert!(text.contains("Password: [redacted]\nafter\n"), "{text}");
}

#[test]
fn rotates_and_keeps_only_n_files() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.log");
    let opts = LogOptions { max_bytes: 4096, keep: 2, ..Default::default() };
    let mut log = SessionLog::create(&path, "#", opts).unwrap();
    let line = format!("{}\n", "x".repeat(1023));
    for _ in 0..20 {
        log.write(line.as_bytes()).unwrap();
    }
    log.finish().unwrap();
    let mut names: Vec<String> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
    names.sort();
    assert_eq!(names, ["s.log", "s.log.1", "s.log.2"]);
    for n in &names {
        let p = dir.path().join(n);
        assert!(std::fs::metadata(&p).unwrap().len() <= 4096, "{n} exceeds the limit");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600, "{n}");
        }
    }
}

#[test]
fn strip_ansi_option_writes_plain_text() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.log");
    let mut log = SessionLog::create(&path, "#", LogOptions { strip_ansi: true, ..Default::default() }).unwrap();
    log.write(b"\x1b[31mred\x1b[0m\n").unwrap();
    log.finish().unwrap();
    assert_eq!(read(&path), "#\nred\n");
}

#[test]
fn huge_line_without_newline_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.log");
    let mut log = SessionLog::create(&path, "#", LogOptions::default()).unwrap();
    log.write(&vec![b'y'; 200 * 1024]).unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() > 100 * 1024, "long partial lines are written, not buffered forever");
}
