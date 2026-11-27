//! Terminal emulator tests. Local PTY tests run on Unix (`/bin/sh`) and on Windows (ConPTY,
//! driving `powershell.exe` and `cmd.exe`); the SSH test needs the Docker server from
//! docs/TESTING.md and `BASTION_SSH_TEST=1` (otherwise it prints SKIPPED).
//!
//! Tests whose assertions are the same everywhere take a POSIX script and a PowerShell script
//! through `run_script`; tests that talk to an interactive shell have a Unix and a Windows
//! version because the shells differ.
use std::time::{Duration, Instant};

use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::terminal::{Screen, SelectKind, TerminalSession, TerminalTheme};
use bastion_core::vault::Secret;

fn wait_for(t: &TerminalSession, what: &str, pred: impl Fn(&Screen) -> bool) -> Screen {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let s = t.screen();
        if pred(&s) {
            return s;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}; screen:\n{}", s.text());
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_until_dead(t: &TerminalSession, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while t.is_alive() {
        assert!(Instant::now() < deadline, "{what}; screen:\n{}", t.screen().text());
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Standard base64, enough for `powershell -EncodedCommand` (avoids quoting the script).
#[cfg(windows)]
fn base64(bytes: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |a, (i, b)| a | (*b as u32) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Run a script in a fresh local PTY: `posix` under `/bin/sh -c` on Unix, `windows` as a
/// PowerShell command (no profile, so the user's setup cannot change the output) on Windows.
#[test]
fn theme_recolours_ansi_and_defaults_but_not_truecolour() {
    let posix = "printf '\\033[31mR\\033[0mD\\033[48;2;1;2;3mB\\033[0m'; sleep 5";
    let windows = "$e=[char]27; [Console]::Out.Write(\"$e[31mR$e[0mD$e[48;2;1;2;3mB$e[0m\"); Start-Sleep 5";
    let t = run_script(posix, windows, 20, 3);
    let before = wait_for(&t, "text", |s| s.row_text(0) == "RDB");
    assert_eq!(before.background, TerminalTheme::BASTION_DARK.background);
    let gen = t.generation();
    let theme = TerminalTheme::preset("solarized-dark").expect("preset");
    t.set_theme(theme);
    assert!(t.generation() > gen, "a theme change redraws");
    let s = t.screen();
    assert_eq!(s.background, theme.background);
    assert_eq!(s.cells[0].style.fg, theme.ansi[1]);
    assert_eq!(s.cells[1].style.fg, theme.foreground);
    assert_eq!(s.cells[1].style.bg, theme.background);
    assert_eq!(s.cells[2].style.bg, 0x010203);
    assert!(TerminalTheme::preset("nope").is_none());
    t.close();
}

#[cfg(unix)]
fn run_script(posix: &str, _windows: &str, cols: u16, rows: u16) -> TerminalSession {
    TerminalSession::spawn_program("/bin/sh", &["-c", posix], cols, rows).unwrap()
}

#[cfg(windows)]
fn run_script(_posix: &str, windows: &str, cols: u16, rows: u16) -> TerminalSession {
    let utf16: Vec<u8> = windows.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let encoded = base64(&utf16);
    TerminalSession::spawn_program("powershell.exe", &["-NoLogo", "-NoProfile", "-EncodedCommand", &encoded], cols, rows).unwrap()
}

#[test]
fn local_pty_renders_program_output_into_grid() {
    let t = run_script("printf 'hello\\r\\nworld'; sleep 5", "[Console]::Out.Write(\"hello`r`nworld\"); Start-Sleep 5", 40, 10);
    let s = wait_for(&t, "output", |s| s.row_text(1) == "world");
    assert_eq!(s.row_text(0), "hello");
    assert_eq!((s.cols, s.rows), (40, 10));
    assert_eq!((s.cursor_row, s.cursor_col), (1, 5));
    t.close();
}

#[test]
fn colours_and_attributes_are_resolved() {
    // red fg (31), truecolor bg, bold; then 256-colour index 196.
    let posix = "printf '\\033[1;31mR\\033[0m\\033[48;2;1;2;3mB\\033[0m\\033[38;5;196mX\\033[0m'; sleep 5";
    let windows = "$e=[char]27; [Console]::Out.Write(\"$e[1;31mR$e[0m$e[48;2;1;2;3mB$e[0m$e[38;5;196mX$e[0m\"); Start-Sleep 5";
    let t = run_script(posix, windows, 20, 3);
    let s = wait_for(&t, "colours", |s| s.row_text(0) == "RBX");
    let r = &s.cells[0].style;
    assert!(r.bold);
    assert_ne!(r.fg, bastion_core::terminal::DEFAULT_FG);
    assert_eq!(s.cells[1].style.bg, 0x010203);
    assert_eq!(s.cells[2].style.fg, 0xff0000);
    t.close();
}

#[cfg(unix)]
#[test]
fn input_reaches_the_program_and_resize_updates_pty() {
    let t = TerminalSession::spawn_program("/bin/sh", &[], 80, 24).unwrap();
    t.resize(100, 30).unwrap();
    t.write(b"stty size; echo done-$((6*7))\r").unwrap();
    let s = wait_for(&t, "stty", |s| s.text().contains("done-42"));
    assert!(s.text().contains("30 100"), "{}", s.text());
    assert_eq!((s.cols, s.rows), (100, 30));
    t.write(b"exit\r").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while t.is_alive() {
        assert!(Instant::now() < deadline, "shell did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Interactive `cmd.exe`: keystrokes reach the program, and `mode con` reports the size ConPTY
/// was resized to.
#[cfg(windows)]
#[test]
fn input_reaches_the_program_and_resize_updates_pty() {
    let t = TerminalSession::spawn_program("cmd.exe", &["/Q", "/K"], 80, 24).unwrap();
    // Input sent before cmd.exe is reading is not reliably executed under ConPTY; wait for the prompt.
    wait_for(&t, "cmd prompt", |s| s.row_text(0).ends_with('>'));
    t.resize(100, 30).unwrap();
    // The typed text never contains "Columns:", so this only matches cmd's own output.
    t.write(b"mode con\r").unwrap();
    let s = wait_for(&t, "mode con", |s| s.text().contains("Columns:") && s.text().contains("Lines:"));
    let value = |key: &str| -> String {
        let line = s.text().lines().find(|l| l.contains(key)).unwrap_or_default().to_string();
        line.split(':').nth(1).unwrap_or_default().trim().to_string()
    };
    assert_eq!(value("Lines:"), "30", "{}", s.text());
    assert_eq!(value("Columns:"), "100", "{}", s.text());
    assert_eq!((s.cols, s.rows), (100, 30));
    t.write(b"exit\r").unwrap();
    wait_until_dead(&t, "shell did not exit");
}

#[test]
fn wide_characters_and_scrollback() {
    let posix = "printf '日本\\r\\n'; for i in $(seq 1 30); do echo line$i; done; sleep 5";
    // The PowerShell script builds 日本 from code points and switches the console to UTF-8.
    let windows = "[Console]::OutputEncoding=[Text.Encoding]::UTF8; [Console]::Out.Write(([string][char]0x65E5+[char]0x672C)+\"`r`n\"); 1..30 | ForEach-Object { [Console]::Out.Write(\"line$_`r`n\") }; Start-Sleep 5";
    let t = run_script(posix, windows, 20, 5);
    let s = wait_for(&t, "lines", |s| s.text().contains("line30"));
    assert!(!s.text().contains("日本"));
    // The second cell of a wide character is an empty spacer.
    t.scroll(100);
    let top = t.screen();
    assert_eq!(top.row_text(0), "日本");
    assert_eq!(top.cells[1].text, "");
    t.close();
}

#[cfg(unix)]
#[test]
fn bracketed_paste_wraps_only_when_requested() {
    // `cat -v` echoes control characters visibly, so we can see what the program received.
    // `ready` follows the mode switch and `stty` in the stream, so once it is on screen the
    // emulator has bracketed paste on and echo is off (H14: no fixed sleep).
    let t = TerminalSession::spawn_program("/bin/sh", &["-c", "printf '\\033[?2004h'; stty -echo; echo ready; cat -v"], 60, 5).unwrap();
    wait_for(&t, "program ready", |s| s.text().contains("ready"));
    // TE-01: the nested payload used to rebuild an end marker once the inner one was removed.
    t.paste("ls\x1b[2\x1b[201~01~evil\n").unwrap();
    let s = wait_for(&t, "paste", |s| s.text().contains("evil"));
    // `cat -v` echoes per line: the payload line holds the start marker and inert text; the
    // outer end marker follows the pasted newline, on the next line.
    assert!(s.text().contains("^[[200~ls[2[201~01~evil"), "inert inner text: {}", s.text());
    assert_eq!(s.text().matches("^[").count(), 1, "no ESC inside the paste: {}", s.text());
    t.close();
}

/// A PowerShell program stands in for `cat -v`: it asks for bracketed paste, then prints every
/// key it receives, showing ESC as `^[`.
///
/// Windows 10's inbox ConPTY does not forward `ESC[?2004h` to the host terminal (checked on
/// 10.0.19045), so the emulator never learns the mode was requested and pastes arrive
/// unwrapped. The test therefore pins what must hold either way: the end marker embedded in
/// the payload never reaches the program, and if the mode *is* forwarded (newer ConPTY) the
/// payload is wrapped in exactly one pair of markers.
#[cfg(windows)]
#[test]
fn bracketed_paste_wraps_only_when_requested() {
    let echo_keys = "$e=[char]27; [Console]::Out.Write(\"$e[?2004h\"); [Console]::Out.Write(\"ready`r`n\"); \
        while($true){ $k=[Console]::ReadKey($true); \
        if($k.KeyChar -eq [char]27){[Console]::Out.Write('^[')} \
        elseif($k.Key -eq 'Enter'){[Console]::Out.Write(\"`r`n\")} \
        else {[Console]::Out.Write($k.KeyChar)} }";
    let t = run_script("", echo_keys, 60, 5);
    wait_for(&t, "program ready", |s| s.text().contains("ready"));
    // TE-01: the nested payload used to rebuild an end marker once the inner one was removed.
    t.paste("ls\x1b[2\x1b[201~01~evil\n").unwrap();
    let s = wait_for(&t, "paste", |s| s.text().contains("evil"));
    let text = s.text();
    assert!(text.contains("ls[2[201~01~evil"), "payload with every ESC removed expected: {text}");
    if text.contains("^[[200~") {
        assert!(text.contains("^[[200~ls[2[201~01~evil^[[201~"), "wrapped paste must be one start and one end marker: {text}");
        assert_eq!(text.matches("^[").count(), 2, "only the outer markers carry ESC: {text}");
    } else {
        assert!(!text.contains("^["), "unwrapped paste must carry no ESC: {text}");
    }
    t.close();
}

#[test]
fn rejects_absurd_sizes() {
    let program = if cfg!(windows) { "cmd.exe" } else { "/bin/true" };
    assert!(TerminalSession::spawn_program(program, &[], 0, 10).is_err());
    assert!(TerminalSession::spawn_program(program, &[], 10, 5000).is_err());
}

#[ignore = "live: needs BASTION_SSH_TEST (docs/TESTING.md); run with --ignored"]
#[test]
fn ssh_shell_in_terminal() {
    assert!(std::env::var_os("BASTION_SSH_TEST").is_some(), "live test run without BASTION_SSH_TEST: start the fixture (docs/TESTING.md)");
    if std::env::var("BASTION_SSH_TEST").is_err() {
        eprintln!("SKIPPED ssh_shell_in_terminal: set BASTION_SSH_TEST=1 with the test server running");
        return;
    }
    let rt = tokio::runtime::Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let params = SshParams {
        host: "127.0.0.1".into(),
        port: 2222,
        username: "tester".into(),
        auth: SshAuth::Password(Secret::new("test-pass-123")),
        known_hosts: dir.path().join("known_hosts"),
        policy: HostKeyPolicy::AcceptNew,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    };
    let session = rt.block_on(SshSession::connect(params)).unwrap();
    let channel = rt.block_on(session.open_shell("xterm-256color", 80, 24)).unwrap();
    let t = TerminalSession::attach_ssh(channel, 80, 24, rt.handle()).unwrap();
    t.resize(120, 33).unwrap();
    t.write(b"stty size; echo remote-$((6*7))\r").unwrap();
    let s = wait_for(&t, "remote", |s| s.text().contains("remote-42"));
    assert!(s.text().contains("33 120"), "{}", s.text());
    t.write(b"exit\r").unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while t.is_alive() {
        assert!(Instant::now() < deadline, "remote shell did not end");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn mouse_selection_copies_text() {
    let t = run_script(
        "printf 'alpha beta gamma\\r\\nsecond line'; sleep 5",
        "[Console]::Out.Write(\"alpha beta gamma`r`nsecond line\"); Start-Sleep 5",
        40,
        5,
    );
    wait_for(&t, "text", |s| s.row_text(1) == "second line");
    t.select_start(0, 6, SelectKind::Cell);
    t.select_extend(0, 9);
    assert_eq!(t.selection_text().as_deref(), Some("beta"));
    let s = t.screen();
    assert!(s.cells[6].selected && s.cells[9].selected && !s.cells[10].selected && !s.cells[5].selected);
    // Across rows.
    t.select_start(0, 11, SelectKind::Cell);
    t.select_extend(1, 5);
    assert_eq!(t.selection_text().as_deref(), Some("gamma\nsecond"));
    // Double click selects the word, triple click the line.
    t.select_start(0, 13, SelectKind::Word);
    assert_eq!(t.selection_text().as_deref(), Some("gamma"));
    t.select_start(1, 2, SelectKind::Line);
    assert_eq!(t.selection_text().as_deref().map(str::trim_end), Some("second line"));
    t.clear_selection();
    assert_eq!(t.selection_text(), None);
    t.close();
}

#[test]
fn regex_search_walks_matches_through_scrollback() {
    let t = run_script(
        "for i in $(seq 1 40); do echo row-$i; done; echo ERROR 7; echo tail; sleep 5",
        "1..40 | ForEach-Object { [Console]::Out.Write(\"row-$_`r`n\") }; [Console]::Out.Write(\"ERROR 7`r`ntail`r`n\"); Start-Sleep 5",
        20,
        5,
    );
    wait_for(&t, "tail", |s| s.text().contains("tail"));
    assert!(t.search("ERROR [0-9]", false).unwrap());
    assert!(t.screen().cells.iter().any(|c| c.matched));
    // row-3 is far up in scrollback: searching scrolls it into view and highlights it.
    t.clear_search();
    assert!(t.search("row-3 ", true).unwrap());
    let s = t.screen();
    let hit = (0..s.rows).find(|r| s.row_text(*r) == "row-3").expect("match scrolled into view");
    assert!(s.cells[hit as usize * s.cols as usize].matched);
    // Next match moves on (row-3 is unique, so it wraps back to itself or reports it again).
    assert!(t.search("row-[0-9]+", true).unwrap());
    assert!(!t.search("no such text", true).unwrap());
    assert!(!t.screen().cells.iter().any(|c| c.matched), "a failed search clears the highlight");
    assert!(t.search("([unclosed", true).is_err());
    t.close();
}

#[test]
fn find_counts_matches_and_honours_case_and_literal_text() {
    use bastion_core::terminal::{find_pattern, FindOptions, FindResult, FIND_QUERY_MAX};
    let t = run_script(
        "echo 'Err one'; echo 'err two'; echo 'ERR three'; echo 'a.b (x'; echo tail; sleep 5",
        "[Console]::Out.Write(\"Err one`r`nerr two`r`nERR three`r`na.b (x`r`ntail`r`n\"); Start-Sleep 5",
        40,
        10,
    );
    wait_for(&t, "tail", |s| s.text().contains("tail"));
    let plain = FindOptions::default();
    // Case ignored by default: three matches, Enter (backwards) starts at the newest.
    // The echoed command line on Unix also contains the words, so count only what is relative.
    let all = t.find("err", false, plain).unwrap();
    assert!(all.total >= 3 && all.index == all.total, "{all:?}");
    let prev = t.find("err", false, plain).unwrap();
    assert_eq!((prev.index, prev.total), (all.total - 1, all.total));
    let next = t.find("err", true, plain).unwrap();
    assert_eq!(next.index, all.total);
    // Match case: only the exact spelling.
    let cased = t.find("Err", false, FindOptions { match_case: true, regex: false }).unwrap();
    assert!(cased.total >= 1 && cased.total < all.total, "{cased:?}");
    // Plain text: regex characters are literal, so "(" is no error and "." is no wildcard.
    let lit = t.find("a.b (x", false, plain).unwrap();
    assert!(lit.total >= 1);
    assert_eq!(t.find("a?b", false, plain).unwrap(), FindResult::default());
    assert!(t.find("([unclosed", false, FindOptions { match_case: false, regex: true }).is_err());
    assert_eq!(t.find("E.R", false, FindOptions { match_case: true, regex: true }).unwrap().total, 1);
    // An empty query clears the highlight.
    assert_eq!(t.find("", true, plain).unwrap(), FindResult::default());
    assert!(!t.screen().cells.iter().any(|c| c.matched));
    assert_eq!(find_pattern("a.b", plain), "(?i)a\\.b");
    // Over-long queries are refused; a catastrophic-backtracking pattern returns at once (the
    // engine is a lazy DFA, linear in the scrollback, which is itself capped).
    assert!(t.find(&"x".repeat(FIND_QUERY_MAX + 1), false, plain).is_err());
    let started = std::time::Instant::now();
    let _ = t.find("(a+)+$", false, FindOptions { match_case: false, regex: true });
    let _ = t.find("(x*)*(y*)*z", true, FindOptions { match_case: false, regex: true });
    assert!(started.elapsed() < std::time::Duration::from_secs(2), "{:?}", started.elapsed());
    t.close();
}

/// OSC 52: a program can offer text for the clipboard (subject to the policy) but never read it.
#[cfg(unix)]
#[test]
fn osc52_copy_follows_the_policy_and_paste_is_never_answered() {
    use bastion_core::terminal::ClipboardPolicy;
    // "hello" in base64; then a paste query, then a marker.
    let script = r"printf '\033]52;c;aGVsbG8=\007'; printf '\033]52;c;?\007'; echo osc-done; sleep 1";
    let t = TerminalSession::spawn_program("/bin/sh", &["-c", script], 80, 24).unwrap();
    wait_for(&t, "marker", |s| s.text().contains("osc-done"));
    let req = t.take_clipboard_request().expect("copy request");
    assert_eq!((req.text.as_str(), req.ask), ("hello", true), "Ask is the default");
    assert!(t.take_clipboard_request().is_none(), "taken once");

    let t = TerminalSession::spawn_program("/bin/sh", &["-c", script], 80, 24).unwrap();
    t.set_clipboard_policy(ClipboardPolicy::Off);
    wait_for(&t, "marker", |s| s.text().contains("osc-done"));
    assert!(t.take_clipboard_request().is_none());

    let t = TerminalSession::spawn_program("/bin/sh", &["-c", script], 80, 24).unwrap();
    t.set_clipboard_policy(ClipboardPolicy::Allow);
    wait_for(&t, "marker", |s| s.text().contains("osc-done"));
    assert_eq!(t.take_clipboard_request().map(|r| r.ask), Some(false));
}

#[cfg(unix)]
#[test]
fn session_log_is_opt_in_owner_only_and_output_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("s.log");
    let t = TerminalSession::spawn_program("/bin/sh", &[], 80, 24).unwrap();
    // Computed values, so the wait sees the program's output and not the echoed command line.
    t.write(b"echo before-$((1+1))\r").unwrap();
    wait_for(&t, "before", |s| s.text().contains("before-2"));
    assert!(!t.is_logging());
    t.start_log(&path, "# Bastion session log: test").unwrap();
    assert!(t.start_log(&path, "x").is_err(), "never overwrites");
    t.write(b"echo in-log-$((6*7))\r").unwrap();
    wait_for(&t, "logged", |s| s.text().contains("in-log-42"));
    t.stop_log();
    t.write(b"echo after-$((2+2))\r").unwrap();
    wait_for(&t, "after", |s| s.text().contains("after-4"));
    // stop_log closes the file synchronously; the log is complete once it is back.
    let log = std::fs::read_to_string(&path).unwrap();
    assert!(log.starts_with("# Bastion session log: test"));
    assert!(log.contains("in-log-42"));
    assert!(!log.contains("before-2") && !log.contains("after-"), "{log}");
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn osc7_from_the_shell_sets_the_follow_folder() {
    let t = run_script(
        "printf '\\033]7;file://h/srv/my%%20app\\007ready'; sleep 5",
        "[Console]::Out.Write(\"$([char]27)]7;file://h/srv/my%20app$([char]7)ready\"); Start-Sleep 5",
        40,
        5,
    );
    wait_for(&t, "osc7", |s| s.text().contains("ready"));
    assert_eq!(t.cwd().as_deref(), Some("/srv/my app"));
    t.close();
}

/// Closing a local shell must not block the caller (the UI thread) for portable-pty's SIGHUP
/// grace period (~200 ms); the shell is still signalled and reaped in the background.
#[cfg(unix)]
#[test]
fn closing_a_local_shell_returns_at_once() {
    let t = TerminalSession::spawn_local(80, 24).expect("spawn");
    assert!(t.is_alive());
    let t0 = Instant::now();
    t.close();
    let took = t0.elapsed();
    assert!(took < Duration::from_millis(50), "close took {took:?}");
    assert!(!t.is_alive());
}
