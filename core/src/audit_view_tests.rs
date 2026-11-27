use std::collections::BTreeMap;

use super::*;
use crate::audit::{AuditLog, Category, Outcome};

fn log_with(n: usize) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut log = AuditLog::open(&path).unwrap();
    for i in 0..n {
        log.record(Category::Connection, &format!("action-{i}"), Some("host"), Outcome::Success, BTreeMap::new()).unwrap();
    }
    (dir, path)
}

#[test]
fn a_missing_log_is_empty_and_intact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    assert_eq!(page(&path, 0, 10).unwrap(), AuditPage { total: 0, records: vec![] });
    assert_eq!(check(&path).unwrap(), AuditCheck { intact: true, records: 0, changed_at: None });
}

#[test]
fn pages_are_newest_first() {
    let (_d, path) = log_with(5);
    let p = page(&path, 0, 2).unwrap();
    assert_eq!(p.total, 5);
    assert_eq!(p.records.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(), ["action-4", "action-3"]);
    let p = page(&path, 4, 10).unwrap();
    assert_eq!(p.records.iter().map(|e| e.action.as_str()).collect::<Vec<_>>(), ["action-0"]);
}

#[test]
fn a_page_is_capped() {
    let (_d, path) = log_with(3);
    assert_eq!(page(&path, 0, usize::MAX).unwrap().records.len(), 3);
    assert_eq!(MAX_PAGE, 500);
}

#[test]
fn an_untouched_log_is_intact() {
    let (_d, path) = log_with(4);
    assert_eq!(check(&path).unwrap(), AuditCheck { intact: true, records: 4, changed_at: None });
}

#[test]
fn one_changed_byte_names_the_next_record() {
    let (_d, path) = log_with(4);
    let text = std::fs::read_to_string(&path).unwrap();
    // Record 2's action changes: its own line still parses, so record 3 is the first whose
    // prev_hash no longer matches.
    std::fs::write(&path, text.replacen("action-1", "action-X", 1)).unwrap();
    assert_eq!(check(&path).unwrap(), AuditCheck { intact: false, records: 4, changed_at: Some(3) });
}

#[test]
fn a_deleted_record_is_found() {
    let (_d, path) = log_with(4);
    let text = std::fs::read_to_string(&path).unwrap();
    let kept: Vec<&str> = text.lines().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| l).collect();
    std::fs::write(&path, kept.join("\n") + "\n").unwrap();
    assert_eq!(check(&path).unwrap().changed_at, Some(2));
}

#[test]
fn a_line_that_is_not_a_record_is_named_and_left_out_of_pages() {
    let (_d, path) = log_with(2);
    let mut text = std::fs::read_to_string(&path).unwrap();
    text.push_str("not json\n");
    std::fs::write(&path, &text).unwrap();
    assert_eq!(check(&path).unwrap(), AuditCheck { intact: false, records: 3, changed_at: Some(3) });
    let p = page(&path, 0, 10).unwrap();
    assert_eq!((p.total, p.records.len()), (3, 2));
}

#[test]
fn reading_changes_nothing() {
    let (_d, path) = log_with(3);
    let before = std::fs::read(&path).unwrap();
    page(&path, 0, 10).unwrap();
    check(&path).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
