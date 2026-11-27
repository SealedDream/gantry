//! Triggers: validation, bounded matching, store round-trips, hostile files, and terminal
//! highlighting and notifications (no lag with 200k lines of scrollback).
use std::sync::Arc;
use std::time::{Duration, Instant};

use bastion_core::triggers::{Highlight, LineScanner, Notifier, Trigger, TriggerSet, TriggerStore, MAX_TRIGGERS};
use uuid::Uuid;

const RED: u32 = 0xff_0000;

fn hl(name: &str, pattern: &str) -> Trigger {
    Trigger { highlight: Some(Highlight { fg: Some(RED), bg: None, bold: true }), ..Trigger::new(name, pattern) }
}

fn notify(name: &str, pattern: &str) -> Trigger {
    Trigger { notify: true, ..Trigger::new(name, pattern) }
}

#[test]
fn invalid_triggers_are_refused_with_a_reason() {
    assert!(hl("ok", r"\bERROR\b").validate().is_ok());
    for (t, why) in [
        (hl("", "x"), "name"),
        (hl("n", ""), "pattern"),
        (hl("n", &"a".repeat(300)), "pattern"),
        (hl("n", "(unclosed"), "pattern"),
        (hl("n", "a*"), "empty"),
        (hl("n", "^"), "empty"),
        (Trigger::new("nothing", "x"), "highlight"),
        (Trigger { highlight: Some(Highlight { fg: Some(0x1_000000), bg: None, bold: false }), ..Trigger::new("n", "x") }, "0xRRGGBB"),
        // Huge counted repetition: over the compiled size limit, refused instead of using memory.
        (hl("n", r"(\w{1000}){1000}"), "pattern"),
    ] {
        let e = t.validate().unwrap_err().to_string();
        assert!(e.contains(why), "{e} should mention {why}");
    }
}

#[test]
fn spans_follow_the_patterns_and_disabled_or_notify_only_triggers_do_not_highlight() {
    let off = Trigger { enabled: false, ..hl("off", "line") };
    let set = TriggerSet::compile(&[hl("err", "ERROR"), Trigger { case_insensitive: true, ..hl("warn", "warn") }, off, notify("n", "line")]).unwrap();
    let spans = set.spans("ERROR on line 3, WARN twice: Warn");
    let ranges: Vec<_> = spans.iter().map(|s| (s.start, s.end)).collect();
    assert_eq!(ranges, [(0, 5), (17, 21), (29, 33)]);
    assert!(set.spans("nothing here").is_empty());
    assert!(TriggerSet::compile(&[]).unwrap().is_empty());
}

#[test]
fn scanner_strips_escapes_and_splits_lines_across_chunks() {
    let mut lines = Vec::new();
    let mut sc = LineScanner::default();
    for chunk in [&b"\x1b[31mERR"[..], b"OR\x1b[0m one\r\n\x1b]0;title\x07two", b"\n\x1bP+q\x1b\\three\n"] {
        sc.feed(chunk, |l| lines.push(l.to_string()));
    }
    assert_eq!(lines, ["ERROR one", "two", "three"]);
}

#[test]
fn notifications_have_a_cooldown_and_a_bounded_queue() {
    let set = TriggerSet::compile(&[notify("disk", "No space left"), notify("any", "line")]).unwrap();
    let mut n = Notifier::default();
    n.feed(&set, b"write: No space left on device\nNo space left again\n");
    let ev = n.take();
    assert_eq!(ev.len(), 1, "second match inside the cooldown is dropped");
    assert_eq!((ev[0].name.as_str(), ev[0].line.as_str()), ("disk", "write: No space left on device"));
    n.reset();
    let many: String = (0..100).map(|i| format!("line {i}\n")).collect();
    n.feed(&set, many.as_bytes());
    assert!(n.take().len() <= bastion_core::triggers::MAX_EVENTS);
}

#[test]
fn two_hundred_thousand_lines_scan_quickly() {
    let triggers: Vec<Trigger> = (0..10).map(|i| hl(&format!("t{i}"), &format!(r"\bcode{i}\b"))).chain([notify("fail", "FAILED")]).collect();
    let set = TriggerSet::compile(&triggers).unwrap();
    let text: String = (0..200_000).map(|i| format!("2026-11-04 12:00:{:02} host{} service code{} ok\n", i % 60, i % 7, i % 13)).collect();
    // New output: every line passes the notification scan once.
    let start = Instant::now();
    let mut n = Notifier::default();
    n.feed(&set, text.as_bytes());
    let scan = start.elapsed();
    // Highlights run on visible rows only; 200k lines is ~4000 full redraws of a 50-row screen.
    let start = Instant::now();
    let spans: usize = text.lines().map(|l| set.spans(l).len()).sum();
    let highlight = start.elapsed();
    assert!(spans > 0);
    eprintln!("200k lines, 11 triggers: notify scan {scan:?}, highlight {highlight:?}");
    // Debug-build budgets; release is several times faster.
    assert!(scan < Duration::from_secs(10), "notify scan took {scan:?}");
    assert!(highlight < Duration::from_secs(30), "highlight took {highlight:?}");
}

#[test]
fn store_round_trips_imports_without_duplicates_and_rejects_hostile_files() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("triggers.json");
    let mut s = TriggerStore::open(&path).unwrap();
    let err = hl("Errors", "ERROR");
    s.save(err.clone()).unwrap();
    s.save(notify("Done", "build finished")).unwrap();
    assert!(s.save(hl("errors", "x")).is_err(), "names are unique");
    let exported = s.export_json();
    assert_eq!(TriggerStore::open(&path).unwrap().list(), s.list());

    let other = d.path().join("other.json");
    let mut t = TriggerStore::open(&other).unwrap();
    assert_eq!(t.import_json(&exported).unwrap(), 2);
    assert_eq!(t.import_json(&exported).unwrap(), 2);
    assert_eq!(t.list().len(), 2, "importing twice adds nothing");
    assert_eq!(t.list(), s.list());

    // Hostile or broken files fail safely and change nothing.
    let bad_pattern = format!(r#"{{"triggers":[{{"id":"{}","name":"x","pattern":"(","highlight":{{"fg":1}}}}]}}"#, Uuid::new_v4());
    let too_many = format!(r#"{{"triggers":[{}]}}"#, (0..=MAX_TRIGGERS).map(|i| format!(r#"{{"id":"{}","name":"t{i}","pattern":"x{i}","notify":true}}"#, Uuid::new_v4())).collect::<Vec<_>>().join(","));
    for bad in [bad_pattern.as_str(), "not json", "\u{0}\u{1}", too_many.as_str(), &"x".repeat(2 << 20)] {
        assert!(t.import_json(bad).is_err());
    }
    assert_eq!(t.list().len(), 2);
    std::fs::write(&other, b"{\"triggers\":[{\"id\":\"nope\"}]}").unwrap();
    assert!(TriggerStore::open(&other).is_err(), "a broken file is an error, not an empty list");
    std::fs::write(&other, [0xff, 0xfe, 0x00]).unwrap();
    assert!(TriggerStore::open(&other).is_err());

    s.remove(err.id).unwrap();
    assert!(s.remove(err.id).is_err());
}

#[cfg(unix)]
mod terminal {
    use super::*;
    use bastion_core::terminal::TerminalSession;

    fn wait(t: &TerminalSession, what: &str, pred: impl Fn(&TerminalSession) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !pred(t) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}:\n{}", t.screen().text());
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn matches_are_highlighted_on_screen_and_notifications_raised() {
        let t = TerminalSession::spawn_program("/bin/sh", &["-c", "sleep 0.3; printf 'ok\\nfatal ERROR here\\n\\033[32mdone\\033[0m 日本 ERROR\\n'; sleep 5"], 40, 6).unwrap();
        t.set_triggers(Some(Arc::new(TriggerSet::compile(&[hl("err", "ERROR"), notify("fatal", "^fatal")]).unwrap())));
        wait(&t, "output", |t| t.screen().text().contains("done"));
        let s = t.screen();
        let row = (0..s.rows).find(|r| s.row_text(*r).starts_with("fatal")).unwrap();
        let cell = |r: u16, c: usize| &s.cells[r as usize * s.cols as usize + c];
        assert_eq!((cell(row, 6).style.fg, cell(row, 6).style.bold), (RED, true), "E of ERROR");
        assert_ne!(cell(row, 0).style.fg, RED, "f of fatal");
        // After two wide characters (4 columns), ERROR starts at column 10 of the last row.
        assert_eq!(cell(row + 1, 10).style.fg, RED);
        assert_ne!(cell(row + 1, 9).style.fg, RED);
        let ev = t.take_trigger_events();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].line, "fatal ERROR here");
        t.set_triggers(None);
        assert_ne!(t.screen().cells[row as usize * 40 + 6].style.fg, RED, "off again");
        t.close();
    }

    #[test]
    fn drawing_does_not_slow_down_with_200k_lines_of_scrollback() {
        let t = TerminalSession::spawn_program("/bin/sh", &["-c", "seq 1 200000 | sed 's/$/ ERROR line/'; echo END; sleep 5"], 100, 50).unwrap();
        let set = Arc::new(TriggerSet::compile(&[hl("err", "ERROR"), hl("num", r"\b\d+5\b"), notify("end", "^END$")]).unwrap());
        t.set_triggers(Some(set));
        wait(&t, "200k lines", |t| t.screen().text().contains("END"));
        let start = Instant::now();
        for _ in 0..20 {
            t.screen();
        }
        let per_frame = start.elapsed() / 20;
        assert!(per_frame < Duration::from_millis(50), "screen() with triggers took {per_frame:?}");
        assert_eq!(t.take_trigger_events().len(), 1);
        t.close();
    }
}
