//! Terminal sessions through the C ABI, driven the way a P/Invoke host does: raw handles, flat
//! snapshots, explicit frees. Uses the real local shell (cmd.exe on Windows, sh on Unix).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};

use bastion_cabi::*;

struct Snap {
    cols: u16,
    rows: u16,
    rows_text: Vec<String>,
    cells: Vec<BastionCell>,
    generation: u64,
    alive: bool,
}

unsafe fn snap(t: *const BastionTerminal) -> Snap {
    let mut err: *mut c_char = null_mut();
    let s = bastion_terminal_screen(t, &mut err);
    assert!(!s.is_null(), "screen failed");
    let r = &*s;
    assert_eq!(r.cell_count as usize, r.cols as usize * r.rows as usize, "one cell per grid position");
    let cells = std::slice::from_raw_parts(r.cells, r.cell_count as usize).to_vec();
    let text = std::slice::from_raw_parts(r.text, r.text_len as usize);
    let mut rows_text = Vec::new();
    for row in 0..r.rows as usize {
        let mut line = String::new();
        for c in &cells[row * r.cols as usize..(row + 1) * r.cols as usize] {
            let end = (c.ch_offset + c.ch_len as u32) as usize;
            assert!(end <= text.len(), "cell text inside the buffer");
            line.push_str(std::str::from_utf8(&text[c.ch_offset as usize..end]).expect("UTF-8"));
        }
        rows_text.push(line.trim_end().to_string());
    }
    let out = Snap { cols: r.cols, rows: r.rows, rows_text, cells, generation: r.generation, alive: r.alive != 0 };
    bastion_screen_free(s);
    out
}

unsafe fn wait_for(t: *const BastionTerminal, what: &str, pred: impl Fn(&Snap) -> bool) -> Snap {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let s = snap(t);
        if pred(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}:\n{}", s.rows_text.join("\n"));
        std::thread::sleep(Duration::from_millis(30));
    }
}

unsafe fn write(t: *const BastionTerminal, s: &str) {
    let mut err = null_mut();
    assert_eq!(bastion_terminal_write(t, s.as_ptr(), s.len(), &mut err), 0);
}

unsafe fn shell(cols: u16, rows: u16) -> *mut BastionTerminal {
    let mut err: *mut c_char = null_mut();
    let t = bastion_terminal_local_shell(cols, rows, &mut err);
    assert!(!t.is_null(), "spawn failed: {}", if err.is_null() { String::new() } else { CStr::from_ptr(err).to_string_lossy().into_owned() });
    t
}

/// A command whose output differs from its echo, and the text that output contains.
fn probe_command() -> (&'static str, &'static str) {
    if cfg!(windows) {
        ("echo cabi-%OS%\r", "cabi-Windows_NT")
    } else {
        ("echo cabi-$((40+2))\r", "cabi-42")
    }
}

unsafe fn wait_ready(t: *const BastionTerminal) {
    // cmd.exe does not reliably run input sent before its prompt appears.
    if cfg!(windows) {
        wait_for(t, "prompt", |s| s.rows_text.iter().any(|r| r.ends_with('>')));
    } else {
        std::thread::sleep(Duration::from_millis(500));
    }
}

#[test]
fn abi_version_includes_terminal() {
    assert!(bastion_abi_version() >= 2);
}

#[test]
fn shell_round_trip_snapshot_resize_and_close() {
    unsafe {
        let t = shell(80, 24);
        assert_eq!(bastion_terminal_is_alive(t), 1);
        wait_ready(t);
        let g0 = bastion_terminal_generation(t);
        let (cmd, expect) = probe_command();
        write(t, cmd);
        let s = wait_for(t, "command output", |s| s.rows_text.iter().any(|r| r.contains(expect)));
        assert!(s.generation > g0, "generation moves when output arrives");
        assert_eq!((s.cols, s.rows), (80, 24));
        assert!(s.alive);

        let mut err = null_mut();
        assert_eq!(bastion_terminal_resize(t, 100, 30, &mut err), 0);
        let s = snap(t);
        assert_eq!((s.cols, s.rows, s.cells.len()), (100, 30, 3000));
        assert_eq!(bastion_terminal_resize(t, 0, 30, &mut err), -1);
        let msg = CStr::from_ptr(err).to_string_lossy().into_owned();
        bastion_string_free(err);
        assert!(msg.contains("out of range"), "{msg}");

        bastion_terminal_close(t);
        let deadline = Instant::now() + Duration::from_secs(10);
        while bastion_terminal_is_alive(t) == 1 {
            assert!(Instant::now() < deadline, "closed session must stop reporting alive");
            std::thread::sleep(Duration::from_millis(30));
        }
        // A closed handle is still safe to query until freed.
        let _ = snap(t);
        bastion_terminal_free(t);
    }
}

#[test]
fn selection_and_search_through_the_boundary() {
    unsafe {
        let t = shell(80, 24);
        wait_ready(t);
        let (cmd, expect) = probe_command();
        write(t, cmd);
        let s = wait_for(t, "output", |s| s.rows_text.iter().filter(|r| r.contains(expect)).count() >= 1);
        // Select the output row by triple click and read it back.
        let row = s.rows_text.iter().rposition(|r| r.contains(expect)).unwrap() as u16;
        bastion_terminal_select_start(t, row, 0, 3);
        let sel = bastion_terminal_selection_text(t);
        assert!(!sel.is_null());
        let text = CStr::from_ptr(sel).to_string_lossy().into_owned();
        bastion_string_free(sel);
        assert!(text.contains(expect), "selection {text:?}");
        assert!(snap(t).cells.iter().any(|c| c.flags & CELL_SELECTED != 0), "selected cells are flagged");
        bastion_terminal_clear_selection(t);
        assert!(bastion_terminal_selection_text(t).is_null());

        let mut err = null_mut();
        let pat = c(expect);
        assert_eq!(bastion_terminal_search(t, pat.as_ptr(), 0, &mut err), 1);
        assert!(snap(t).cells.iter().any(|c| c.flags & CELL_MATCHED != 0), "matched cells are flagged");
        assert_eq!(bastion_terminal_search(t, c("no such text anywhere").as_ptr(), 1, &mut err), 0);
        assert_eq!(bastion_terminal_search(t, c("([unclosed").as_ptr(), 1, &mut err), -1);
        assert!(!err.is_null());
        bastion_string_free(err);
        // Find bar: plain text, match count as JSON; "([unclosed" is literal text, not an error.
        err = null_mut();
        let found = bastion_terminal_find_json(t, pat.as_ptr(), 0, 0, 0, &mut err);
        assert!(!found.is_null());
        let v: serde_json::Value = serde_json::from_str(std::ffi::CStr::from_ptr(found).to_str().unwrap()).unwrap();
        assert!(v["total"].as_u64().unwrap() >= 1 && v["index"].as_u64().unwrap() >= 1, "{v}");
        bastion_string_free(found);
        let none = bastion_terminal_find_json(t, c("([unclosed").as_ptr(), 1, 0, 0, &mut err);
        assert!(std::ffi::CStr::from_ptr(none).to_str().unwrap().contains("\"total\":0"));
        bastion_string_free(none);
        assert!(bastion_terminal_find_json(t, c("([unclosed").as_ptr(), 1, 0, 1, &mut err).is_null());
        assert!(!err.is_null());
        bastion_string_free(err);
        bastion_terminal_clear_search(t);
        bastion_terminal_scroll(t, 5);
        bastion_terminal_scroll(t, -5);
        bastion_terminal_free(t);
    }
}

#[test]
fn paste_and_bracketed_mode_report() {
    unsafe {
        // Wide enough that a long CI hostname prompt plus the command never wraps.
        let t = shell(240, 24);
        wait_ready(t);
        // cmd.exe under Windows 10 ConPTY never enables bracketed paste; a Unix login shell
        // such as zsh may, so there only the value range is checked.
        let mode = bastion_terminal_bracketed_paste(t);
        if cfg!(windows) { assert_eq!(mode, 0) } else { assert!(mode == 0 || mode == 1) }
        let mut err = null_mut();
        assert_eq!(bastion_terminal_paste(t, c("echo pasted-ok").as_ptr(), &mut err), 0);
        write(t, "\r");
        wait_for(t, "pasted command", |s| s.rows_text.iter().filter(|r| r.contains("pasted-ok")).count() >= 2);
        assert_eq!(bastion_terminal_paste(t, null(), &mut err), -1);
        bastion_string_free(err);
        err = null_mut();
        assert_eq!(bastion_terminal_background(t), 0x1c1c1e);
        assert_eq!(bastion_terminal_set_theme(t, c("high-contrast").as_ptr(), &mut err), 0);
        assert_eq!(bastion_terminal_background(t), 0x000000);
        assert_eq!(bastion_terminal_set_theme(t, c("nope").as_ptr(), &mut err), -1);
        assert!(CStr::from_ptr(err).to_string_lossy().contains("unknown terminal theme"));
        bastion_string_free(err);
        bastion_terminal_free(t);
    }
}

#[test]
fn null_handles_and_bad_arguments_never_crash() {
    unsafe {
        let mut err: *mut c_char = null_mut();
        assert!(bastion_terminal_local_shell(0, 10, &mut err).is_null());
        assert!(CStr::from_ptr(err).to_string_lossy().contains("out of range"));
        bastion_string_free(err);
        err = null_mut();
        assert!(bastion_terminal_local_shell(10, 5000, &mut err).is_null());
        bastion_string_free(err);

        let n: *const BastionTerminal = null();
        assert_eq!(bastion_terminal_generation(n), 0);
        assert_eq!(bastion_terminal_is_alive(n), 0);
        assert_eq!(bastion_terminal_bracketed_paste(n), 0);
        assert_eq!(bastion_terminal_background(n), 0);
        assert_eq!(bastion_terminal_set_theme(n, c("bastion-dark").as_ptr(), null_mut()), -1);
        err = null_mut();
        assert!(bastion_terminal_screen(n, &mut err).is_null());
        assert!(CStr::from_ptr(err).to_string_lossy().contains("NULL"));
        bastion_string_free(err);
        assert_eq!(bastion_terminal_write(n, b"x".as_ptr(), 1, null_mut()), -1);
        assert_eq!(bastion_terminal_resize(n, 10, 10, null_mut()), -1);
        bastion_terminal_scroll(n, 1);
        bastion_terminal_select_start(n, 0, 0, 1);
        bastion_terminal_select_extend(n, 0, 0);
        bastion_terminal_clear_selection(n);
        assert!(bastion_terminal_selection_text(n).is_null());
        bastion_terminal_clear_search(n);
        bastion_terminal_close(n);
        bastion_terminal_free(null_mut());
        bastion_screen_free(null_mut());

        // Zero-length write with a NULL pointer is fine; non-zero length with NULL is an error.
        let t = shell(40, 10);
        assert_eq!(bastion_terminal_write(t, null(), 0, null_mut()), 0);
        err = null_mut();
        assert_eq!(bastion_terminal_write(t, null(), 3, &mut err), -1);
        bastion_string_free(err);
        // Out-of-range selection coordinates are clamped, not a crash.
        bastion_terminal_select_start(t, 9999, 9999, 1);
        bastion_terminal_select_extend(t, 9999, 0);
        bastion_terminal_free(t);
    }
}

#[test]
fn concurrent_calls_from_several_threads() {
    unsafe {
        let t = shell(80, 24) as usize;
        wait_ready(t as *const BastionTerminal);
        let workers: Vec<_> = (0..4)
            .map(|i| {
                std::thread::spawn(move || {
                    let t = t as *const BastionTerminal;
                    for n in 0..50 {
                        match (i + n) % 4 {
                            0 => drop(snap(t)),
                            1 => {
                                let _ = bastion_terminal_generation(t);
                            }
                            2 => bastion_terminal_scroll(t, if n % 2 == 0 { 1 } else { -1 }),
                            _ => {
                                let _ = bastion_terminal_resize(t, 60 + (n % 20) as u16, 20, null_mut());
                            }
                        }
                    }
                })
            })
            .collect();
        for w in workers {
            w.join().expect("no worker panicked");
        }
        assert_eq!(bastion_terminal_is_alive(t as *const BastionTerminal), 1);
        bastion_terminal_free(t as *mut BastionTerminal);
    }
}

#[test]
fn spawn_specific_program_with_json_args() {
    unsafe {
        let (prog, args, expect) = if cfg!(windows) {
            ("powershell.exe", r#"["-NoLogo","-NoProfile","-Command","Write-Output ('spawn-' + (6*7)); Start-Sleep 5"]"#, "spawn-42")
        } else {
            ("/bin/sh", r#"["-c","echo spawn-$((6*7)); sleep 5"]"#, "spawn-42")
        };
        let mut err: *mut c_char = null_mut();
        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(args).as_ptr(), 80, 24, &mut err);
        assert!(!t.is_null(), "spawn failed");
        wait_for(t, "program output", |s| s.rows_text.iter().any(|r| r.contains(expect)));
        bastion_terminal_free(t);

        for bad in ["not json", r#"{"a":1}"#, "[1,2]"] {
            err = null_mut();
            assert!(bastion_terminal_spawn(c(prog).as_ptr(), c(bad).as_ptr(), 80, 24, &mut err).is_null(), "{bad}");
            assert!(CStr::from_ptr(err).to_string_lossy().contains("JSON array"));
            bastion_string_free(err);
        }
        err = null_mut();
        assert!(bastion_terminal_spawn(c("  ").as_ptr(), null(), 80, 24, &mut err).is_null());
        bastion_string_free(err);
        err = null_mut();
        assert!(bastion_terminal_spawn(c("definitely-not-a-program-xyz").as_ptr(), null(), 80, 24, &mut err).is_null(), "a missing program is an error");
        bastion_string_free(err);
    }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn wsl_lists_distros_and_refuses_option_like_names() {
    unsafe {
        let mut err: *mut c_char = null_mut();
        let json = bastion_wsl_distros_json(&mut err);
        assert!(!json.is_null(), "listing never fails just because WSL is missing");
        let names: Vec<String> = serde_json::from_str(CStr::from_ptr(json).to_str().unwrap()).unwrap();
        bastion_string_free(json);
        if !cfg!(windows) {
            assert!(names.is_empty());
        }
        let bad = CString::new("--exec").unwrap();
        let t = bastion_terminal_wsl(bad.as_ptr(), 80, 24, &mut err);
        assert!(t.is_null() && !err.is_null(), "an option-like name must not reach wsl.exe");
        bastion_string_free(err);
        // On the Windows test PC, open the default distro and see a Linux prompt answer.
        if cfg!(windows) && std::env::var("BASTION_WSL_TEST").is_ok() {
            let name = CString::new(names.first().expect("a WSL distribution is installed").as_str()).unwrap();
            let mut err: *mut c_char = null_mut();
            let t = bastion_terminal_wsl(name.as_ptr(), 100, 30, &mut err);
            assert!(!t.is_null(), "wsl tab failed to start");
            let cmd = b"echo wsl-$((40+2)) $(uname -s)\r";
            assert_eq!(bastion_terminal_write(t, cmd.as_ptr(), cmd.len(), &mut err), 0);
            let deadline = Instant::now() + Duration::from_secs(30);
            while !snap(t).rows_text.iter().any(|r| r.contains("wsl-42 Linux")) {
                assert!(Instant::now() < deadline, "no answer from the WSL shell:\n{}", snap(t).rows_text.join("\n"));
                std::thread::sleep(Duration::from_millis(100));
            }
            bastion_terminal_free(t);
        }
    }
}

#[test]
fn sibling_of_a_local_shell_is_an_independent_shell() {
    unsafe {
        let t = shell(80, 24);
        let mut err: *mut c_char = null_mut();
        let s = bastion_terminal_open_sibling(t, 60, 20, &mut err);
        assert!(!s.is_null(), "sibling failed");
        wait_ready(s);
        let (cmd, expect) = probe_command();
        write(s, cmd);
        let snap_s = wait_for(s, "sibling output", |x| x.rows_text.iter().any(|r| r.contains(expect)));
        assert_eq!((snap_s.cols, snap_s.rows), (60, 20));
        // Closing the sibling leaves the first shell running.
        bastion_terminal_free(s);
        assert_eq!(bastion_terminal_is_alive(t), 1);
        bastion_terminal_free(t);

        assert!(bastion_terminal_open_sibling(null(), 80, 24, &mut err).is_null());
        assert!(CStr::from_ptr(err).to_string_lossy().contains("NULL"));
        bastion_string_free(err);
        err = null_mut();
        let t = shell(80, 24);
        assert!(bastion_terminal_open_sibling(t, 0, 24, &mut err).is_null());
        bastion_string_free(err);
        bastion_terminal_free(t);
    }
}

#[test]
fn osc52_copy_follows_the_clipboard_policy() {
    // "osc52-ok" in base64; a program may only offer text, never read the clipboard.
    let (prog, args) = if cfg!(windows) {
        ("powershell.exe", r#"["-NoLogo","-NoProfile","-Command","[Console]::Write([char]27 + ']52;c;b3NjNTItb2s=' + [char]7 + 'printed'); Start-Sleep 5"]"#)
    } else {
        ("/bin/sh", r#"["-c","printf '\\033]52;c;b3NjNTItb2s=\\007printed'; sleep 5"]"#)
    };
    unsafe {
        let mut err: *mut c_char = null_mut();
        assert_ne!(bastion_terminal_set_clipboard_policy(null(), c("allow").as_ptr(), &mut err), 0);
        bastion_string_free(err);
        assert!(bastion_terminal_take_clipboard_json(null()).is_null());

        for (policy, expect) in [("allow", Some(r#"{"ask":false,"text":"osc52-ok"}"#)), ("ask", Some(r#"{"ask":true,"text":"osc52-ok"}"#)), ("off", None)] {
            err = null_mut();
            let t = bastion_terminal_spawn(c(prog).as_ptr(), c(args).as_ptr(), 80, 24, &mut err);
            assert!(!t.is_null(), "spawn failed");
            assert_eq!(bastion_terminal_set_clipboard_policy(t, c(policy).as_ptr(), &mut err), 0);
            wait_for(t, "program output", |s| s.rows_text.iter().any(|r| r.contains("printed")));
            let json = bastion_terminal_take_clipboard_json(t);
            match expect {
                Some(want) => {
                    assert!(!json.is_null(), "{policy}: no request");
                    let got: serde_json::Value = serde_json::from_str(&CStr::from_ptr(json).to_string_lossy()).unwrap();
                    assert_eq!(got, serde_json::from_str::<serde_json::Value>(want).unwrap(), "{policy}");
                    bastion_string_free(json);
                    assert!(bastion_terminal_take_clipboard_json(t).is_null(), "taken once");
                }
                None => assert!(json.is_null(), "off drops the request"),
            }
            bastion_terminal_free(t);
        }
        err = null_mut();
        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(args).as_ptr(), 80, 24, &mut err);
        assert_ne!(bastion_terminal_set_clipboard_policy(t, c("sometimes").as_ptr(), &mut err), 0, "unknown policy refused");
        bastion_string_free(err);
        bastion_terminal_free(t);
    }
}

#[test]
fn bell_is_taken_once_and_scrollback_clears() {
    let (prog, args) = if cfg!(windows) {
        ("powershell.exe", r#"["-NoLogo","-NoProfile","-Command","1..200 | % { \"line$_\" }; [Console]::Write([char]7 + 'rang'); Start-Sleep 5"]"#)
    } else {
        ("/bin/sh", r#"["-c","i=1; while [ $i -le 200 ]; do echo line$i; i=$((i+1)); done; printf '\\007rang'; sleep 5"]"#)
    };
    unsafe {
        assert_eq!(bastion_terminal_take_bell(null()), 0);
        bastion_terminal_clear_scrollback(null());
        let mut err: *mut c_char = null_mut();
        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(args).as_ptr(), 80, 24, &mut err);
        assert!(!t.is_null(), "spawn failed");
        wait_for(t, "program output", |s| s.rows_text.iter().any(|r| r.contains("rang")));
        assert_eq!(bastion_terminal_take_bell(t), 1, "BEL rang");
        assert_eq!(bastion_terminal_take_bell(t), 0, "taken once");
        bastion_terminal_scroll(t, 50);
        wait_for(t, "scrolled into history", |s| !s.rows_text.iter().any(|r| r.contains("rang")));
        bastion_terminal_clear_scrollback(t);
        wait_for(t, "history gone", |s| s.rows_text.iter().any(|r| r.contains("rang")));
        bastion_terminal_scroll(t, 50);
        wait_for(t, "nothing above the screen", |s| s.rows_text.iter().any(|r| r.contains("rang")));
        bastion_terminal_free(t);
    }
}

#[test]
fn scrollback_size_caps_the_history_and_rejects_zero() {
    let (prog, args) = if cfg!(windows) {
        ("powershell.exe", r#"["-NoLogo","-NoProfile","-Command","1..200 | % { \"line$_\" }; [Console]::Write('done'); Start-Sleep 5"]"#)
    } else {
        ("/bin/sh", r#"["-c","i=1; while [ $i -le 200 ]; do echo line$i; i=$((i+1)); done; printf done; sleep 5"]"#)
    };
    unsafe {
        let mut err: *mut c_char = null_mut();
        assert_eq!(bastion_terminal_set_scrollback(null(), 10, &mut err), -1);
        bastion_string_free(err);
        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(args).as_ptr(), 80, 24, &mut err);
        assert!(!t.is_null(), "spawn failed");
        wait_for(t, "program output", |s| s.rows_text.iter().any(|r| r.contains("done")));
        let mut err: *mut c_char = null_mut();
        assert_eq!(bastion_terminal_set_scrollback(t, 0, &mut err), -1, "0 lines is refused");
        bastion_string_free(err);
        assert_eq!(bastion_terminal_set_scrollback(t, 10, &mut null_mut()), 0);
        // With 10 lines of history, scrolling 50 up stops 10 lines above the screen: line150 is gone.
        bastion_terminal_scroll(t, 50);
        let s = wait_for(t, "scrolled to the top of the history", |s| !s.rows_text.iter().any(|r| r.contains("done")));
        assert!(!s.rows_text.iter().any(|r| r.trim() == "line150"), "history kept more than 10 lines: {:?}", s.rows_text);
        bastion_terminal_free(t);
    }
}

#[test]
fn select_all_takes_the_scrollback_and_the_screen() {
    let (prog, args) = if cfg!(windows) {
        ("powershell.exe", r#"["-NoLogo","-NoProfile","-Command","1..60 | % { \"row$_\" }; [Console]::Write('end'); Start-Sleep 5"]"#)
    } else {
        ("/bin/sh", r#"["-c","i=1; while [ $i -le 60 ]; do echo row$i; i=$((i+1)); done; printf end; sleep 5"]"#)
    };
    unsafe {
        bastion_terminal_select_all(null());
        let mut err: *mut c_char = null_mut();
        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(args).as_ptr(), 80, 24, &mut err);
        assert!(!t.is_null(), "spawn failed");
        wait_for(t, "program output", |s| s.rows_text.iter().any(|r| r.contains("end")));
        bastion_terminal_select_all(t);
        let text = owned(bastion_terminal_selection_text(t));
        assert!(text.contains("row1\n") || text.contains("row1\r\n"), "first scrollback line selected: {text:?}");
        assert!(text.contains("end"), "screen selected too");
        bastion_terminal_free(t);
    }
}

unsafe fn owned(p: *mut c_char) -> String {
    assert!(!p.is_null(), "call failed");
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    s
}

#[test]
fn wsl_details_and_availability_are_json() {
    unsafe {
        let mut err: *mut c_char = null_mut();
        let list: Vec<serde_json::Value> = serde_json::from_str(&owned(bastion_wsl_distros_detail_json(&mut err))).unwrap();
        for d in &list {
            assert!(d["name"].is_string() && d["hidden"].is_boolean() && d["state"].is_string(), "{d}");
            assert_eq!(d["hidden"].as_bool(), Some(d["name"].as_str().unwrap().to_ascii_lowercase().starts_with("docker-desktop")));
        }
        let a: serde_json::Value = serde_json::from_str(&owned(bastion_wsl_availability_json(c("No-Such-Distro-xyz").as_ptr(), &mut err))).unwrap();
        let kind = a["kind"].as_str().unwrap();
        assert!(kind == "removed" || kind == "wsl_missing", "{a}");
        if !cfg!(windows) {
            assert_eq!(kind, "wsl_missing");
        }
        // On the Windows test PC the named distro is ready and reports its WSL version.
        if let (true, Ok(name)) = (cfg!(windows), std::env::var("BASTION_TEST_WSL_DISTRO")) {
            let a: serde_json::Value = serde_json::from_str(&owned(bastion_wsl_availability_json(c(&name).as_ptr(), &mut err))).unwrap();
            assert_eq!(a["kind"], "ready", "{a}");
            let d = list.iter().find(|d| d["name"] == name.as_str()).expect("distro listed");
            if let Ok(v) = std::env::var("BASTION_TEST_WSL_VERSION") {
                assert_eq!(d["version"].as_u64(), v.parse::<u64>().ok());
            }
        }
    }
}

#[test]
fn saved_local_connection_opens_its_shell_in_its_start_folder() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(c(dir.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let id = owned(bastion_library_add_connection(lib, null(), c("here").as_ptr(), c("local").as_ptr(), c("").as_ptr(), -1, null(), &mut err));
        let set = |k: &str, v: &str| {
            let mut err: *mut c_char = null_mut();
            assert_eq!(bastion_library_set_property(lib, c(&id).as_ptr(), c(k).as_ptr(), c(v).as_ptr(), &mut err), 0, "{k}={v}");
        };
        let start = dir.path().canonicalize().unwrap();
        if cfg!(windows) {
            set("local.shell", "cmd");
        } else {
            set("local.shell", "custom");
            set("local.path", "/bin/sh");
        }
        set("local.cwd", start.to_str().unwrap());
        let t = bastion_terminal_open_local(lib, c(&id).as_ptr(), 100, 30, &mut err);
        assert!(!t.is_null(), "open failed: {}", if err.is_null() { String::new() } else { owned(err) });
        let marker = dir.path().file_name().unwrap().to_string_lossy().into_owned();
        write(t, if cfg!(windows) { "cd\r" } else { "pwd\r" });
        wait_for(t, "start folder", |s| s.rows_text.iter().filter(|r| r.contains(&marker)).count() >= 1);
        bastion_terminal_free(t);

        // Bad ids and non-local connections are errors, never a crash.
        assert!(bastion_terminal_open_local(lib, c("not-an-id").as_ptr(), 80, 24, &mut err).is_null());
        bastion_string_free(err);
        let ssh = owned(bastion_library_add_connection(lib, null(), c("s").as_ptr(), c("ssh").as_ptr(), c("h").as_ptr(), -1, null(), &mut err));
        assert!(bastion_terminal_open_local(lib, c(&ssh).as_ptr(), 80, 24, &mut err).is_null());
        assert!(owned(err).contains("not a local terminal"));
        assert!(bastion_terminal_open_local(null(), c(&id).as_ptr(), 80, 24, &mut err).is_null());
        bastion_string_free(err);
        bastion_library_free(lib);
    }
}

#[test]
fn selection_exports_to_an_owner_only_log() {
    unsafe {
        let t = shell(80, 24);
        wait_ready(t);
        let dir = tempfile::tempdir().unwrap();
        let cdir = CString::new(dir.path().to_str().unwrap()).unwrap();
        let name = CString::new("host/../x").unwrap();
        let mut err = null_mut();
        assert!(bastion_terminal_export_selection(t, cdir.as_ptr(), name.as_ptr(), null(), &mut err).is_null(), "nothing selected yet");
        bastion_string_free(err);
        let (cmd, expect) = probe_command();
        write(t, cmd);
        let s = wait_for(t, "output", |s| s.rows_text.iter().any(|r| r.contains(expect)));
        let row = s.rows_text.iter().rposition(|r| r.contains(expect)).unwrap() as u16;
        bastion_terminal_select_start(t, row, 0, 3);
        let mut err = null_mut();
        let p = bastion_terminal_export_selection(t, cdir.as_ptr(), name.as_ptr(), null(), &mut err);
        assert!(!p.is_null());
        let path = CStr::from_ptr(p).to_string_lossy().into_owned();
        bastion_string_free(p);
        assert!(path.ends_with("host-..-x.log") && std::path::Path::new(&path).parent().unwrap() == dir.path(), "{path}");
        assert!(std::fs::read_to_string(&path).unwrap().contains(expect));
        bastion_terminal_close(t);
        bastion_terminal_free(t);
    }
}

#[test]
fn session_log_records_output_and_redacts_echoed_password() {
    unsafe {
        let t = shell(80, 24);
        wait_ready(t);
        let dir = tempfile::tempdir().unwrap();
        let cdir = CString::new(dir.path().join("logs").to_str().unwrap()).unwrap();
        let label = CString::new("web 01").unwrap();
        let mut err = null_mut();
        let p = bastion_terminal_start_log(t, cdir.as_ptr(), label.as_ptr(), 0, 3, 1, &mut err);
        assert!(!p.is_null());
        let path = CStr::from_ptr(p).to_string_lossy().into_owned();
        bastion_string_free(p);
        assert_eq!(bastion_terminal_is_logging(t), 1);
        // The program itself prints a prompt and an echoed answer on one line.
        let cmd = if cfg!(windows) { "echo Password: hun^ter2\r" } else { "printf 'Password: %s%s\\n' hun ter2\r" };
        write(t, cmd);
        let (probe, expect) = probe_command();
        write(t, probe);
        wait_for(t, "output", |s| s.rows_text.iter().filter(|r| r.contains(expect)).count() >= 1);
        std::thread::sleep(Duration::from_millis(200));
        bastion_terminal_stop_log(t);
        assert_eq!(bastion_terminal_is_logging(t), 0);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(expect), "{text}");
        assert!(text.contains("Password: [redacted]"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        let mut err = null_mut();
        assert!(bastion_terminal_start_log(t, cdir.as_ptr(), label.as_ptr(), 10, 3, 1, &mut err).is_null(), "tiny rotation size refused");
        bastion_string_free(err);
        bastion_terminal_close(t);
        bastion_terminal_free(t);
    }
}

#[test]
fn mouse_reports_only_once_the_program_enables_mouse_mode() {
    unsafe {
        let (prog, plain, mouse) = if cfg!(windows) {
            ("powershell.exe", r#"["-NoLogo","-NoProfile","-Command","Write-Output plain-ready; Start-Sleep 5"]"#,
             r#"["-NoLogo","-NoProfile","-Command","[Console]::Write([char]27 + '[?1000h' + [char]27 + '[?1006h'); Write-Output mouse-ready; Start-Sleep 5"]"#)
        } else {
            ("/bin/sh", r#"["-c","echo plain-ready; sleep 5"]"#, r#"["-c","printf '\\033[?1000h\\033[?1006h'; echo mouse-ready; sleep 5"]"#)
        };
        let mut err: *mut c_char = null_mut();
        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(plain).as_ptr(), 80, 24, &mut err);
        assert!(!t.is_null(), "spawn failed");
        wait_for(t, "plain output", |s| s.rows_text.iter().any(|r| r.contains("plain-ready")));
        assert_eq!(bastion_terminal_mouse_reporting(t), 0);
        assert_eq!(bastion_terminal_mouse(t, 0, 0, 1, 1, 0, &mut err), 0, "no mouse mode: nothing sent");
        assert!(err.is_null());
        bastion_terminal_free(t);

        let t = bastion_terminal_spawn(c(prog).as_ptr(), c(mouse).as_ptr(), 80, 24, &mut err);
        assert!(!t.is_null(), "spawn failed");
        wait_for(t, "mouse output", |s| s.rows_text.iter().any(|r| r.contains("mouse-ready")));
        // ConPTY (Windows 11, 2026-11-04) does not forward a console program's DECSET 1000 to us, so a local
        // Windows shell never turns reporting on; SSH output reaches the emulator directly, as here on Unix.
        if !cfg!(windows) {
            assert_eq!(bastion_terminal_mouse_reporting(t), 1);
            assert_eq!(bastion_terminal_mouse(t, 0, 0, 2, 3, 4, &mut err), 1, "press sent");
            assert_eq!(bastion_terminal_mouse(t, 0, 1, 2, 3, 0, &mut err), 1, "release sent");
            assert_eq!(bastion_terminal_mouse(t, 5, 2, 2, 3, 0, &mut err), 0, "bare motion needs 1003");
        }
        assert_eq!(bastion_terminal_mouse(t, 9, 0, 0, 0, 0, &mut err), -1);
        assert!(CStr::from_ptr(err).to_string_lossy().contains("unknown mouse button"));
        bastion_string_free(err);
        err = null_mut();
        assert_eq!(bastion_terminal_mouse(t, 0, 7, 0, 0, 0, &mut err), -1);
        bastion_string_free(err);
        bastion_terminal_free(t);
        assert_eq!(bastion_terminal_mouse_reporting(null()), 0);
    }
}

/// H07: the packed snapshot keeps styles, wide characters (trailing half empty) and colours.
#[cfg(unix)]
#[test]
fn snapshot_packs_styles_and_wide_characters() {
    unsafe {
        let t = shell(40, 6);
        write(t, "printf '\\033[1;31mB\\033[0m\\033[4mU\\033[0m\\346\\274\\242x\\n'\r");
        let s = wait_for(t, "styled output", |s| s.rows_text.iter().any(|r| r.starts_with("BU漢x")));
        let row = s.rows_text.iter().position(|r| r.starts_with("BU漢x")).unwrap();
        let cells = &s.cells[row * s.cols as usize..(row + 1) * s.cols as usize];
        assert_ne!(cells[0].flags & CELL_BOLD, 0, "bold kept");
        assert_eq!(cells[0].flags & CELL_UNDERLINE, 0);
        assert_ne!(cells[1].flags & CELL_UNDERLINE, 0, "underline kept");
        assert_ne!(cells[0].fg, cells[2].fg, "red foreground differs from the default");
        assert_eq!(cells[2].ch_len, 3, "wide character is one UTF-8 run");
        assert_eq!(cells[3].ch_len, 0, "its trailing half is empty");
        assert_eq!(cells[4].ch_len, 1);
        bastion_terminal_free(t);
    }
}

#[test]
fn wait_change_wakes_on_output_and_times_out_when_idle() {
    unsafe {
        assert_eq!(bastion_terminal_wait_change(null(), 7, 10), 7, "a NULL handle returns `after`");
        let t = shell(80, 24);
        wait_ready(t);
        // Idle: no change within the timeout returns the same generation, after about the timeout.
        let g = bastion_terminal_generation(t);
        let start = Instant::now();
        let idle = bastion_terminal_wait_change(t, g, 150);
        if idle == g {
            assert!(start.elapsed() >= Duration::from_millis(100), "an idle wait blocks until the timeout");
        }
        // Output: a write moves the generation and wakes the waiter well before a long timeout.
        let now = bastion_terminal_generation(t);
        let waiter = {
            let addr = t as usize;
            std::thread::spawn(move || {
                let start = Instant::now();
                let g = bastion_terminal_wait_change(addr as *const BastionTerminal, now, 5_000);
                (g, start.elapsed())
            })
        };
        std::thread::sleep(Duration::from_millis(50));
        write(t, "echo wake\r");
        let (g, took) = waiter.join().unwrap();
        assert_ne!(g, now, "the generation moved");
        assert!(took < Duration::from_millis(4_000), "woken by the change, not the timeout ({took:?})");
        bastion_terminal_free(t);
    }
}
