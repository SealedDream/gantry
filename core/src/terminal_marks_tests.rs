//! Shell marks wired into the emulator: prompt jumps, long-command finish, notifications, unread
//! output and the typed-ssh offer.
use super::*;
use crate::shellmarks::ProgramNotification;

struct NullBackend;
impl Backend for NullBackend {
    fn write(&self, _: &[u8]) -> Result<()> {
        Ok(())
    }
    fn resize(&self, _: Size) -> Result<()> {
        Ok(())
    }
    fn close(&self) {}
}

fn session() -> TerminalSession {
    TerminalSession::new(checked_size(40, 5).unwrap(), Arc::new(NullBackend))
}

fn feed(t: &TerminalSession, bytes: &[u8]) {
    t.sink().output(bytes);
}

fn top_row(t: &TerminalSession) -> String {
    t.screen().row_text(0).trim_end().to_string()
}

/// Three prompts, each followed by 6 output lines, on a 5-row screen.
fn three_prompts(t: &TerminalSession) {
    for p in 1..=3 {
        feed(t, format!("\x1b]133;A\x07$ cmd{p}\r\n").as_bytes());
        for i in 0..6 {
            feed(t, format!("out{p}.{i}\r\n").as_bytes());
        }
    }
}

#[test]
fn jumps_between_prompts_and_back_to_the_bottom() {
    let t = session();
    three_prompts(&t);
    assert!(t.jump_prompt(false));
    assert_eq!(top_row(&t), "$ cmd3");
    assert!(t.jump_prompt(false));
    assert_eq!(top_row(&t), "$ cmd2");
    assert!(t.jump_prompt(false));
    assert_eq!(top_row(&t), "$ cmd1");
    assert!(!t.jump_prompt(false), "no prompt above the first");
    assert!(t.jump_prompt(true));
    assert_eq!(top_row(&t), "$ cmd2");
    assert!(t.jump_prompt(true));
    assert!(t.jump_prompt(true), "past the last prompt goes to the bottom");
    assert_eq!(t.with_term(|e| e.term.grid().display_offset()), 0);
    assert!(!t.jump_prompt(true));
}

#[test]
fn marks_follow_their_lines_when_the_history_is_full() {
    let t = session();
    t.set_scrollback(20);
    three_prompts(&t);
    for i in 0..10 {
        feed(&t, format!("more{i}\r\n").as_bytes());
    }
    // 26 lines written into 25 (20 + 5): cmd1 has scrolled away, cmd2 and cmd3 remain.
    assert!(t.jump_prompt(false));
    assert_eq!(top_row(&t), "$ cmd3");
    assert!(t.jump_prompt(false));
    assert_eq!(top_row(&t), "$ cmd2");
    assert!(!t.jump_prompt(false), "cmd1 dropped with its line");
}

#[test]
fn no_marks_means_no_jump_and_clear_scrollback_forgets_them() {
    let t = session();
    feed(&t, b"a\r\nb\r\nc\r\nd\r\ne\r\nf\r\ng\r\n");
    assert!(!t.jump_prompt(false));
    three_prompts(&t);
    t.clear_scrollback();
    assert!(!t.jump_prompt(false));
}

#[test]
fn long_commands_announce_their_finish_short_ones_do_not() {
    let t = session();
    feed(&t, b"\x1b]133;C\x07sleep\r\n\x1b]133;D;0\x07");
    assert_eq!(t.take_events().finished, None, "short command");
    feed(&t, b"\x1b]133;C\x07");
    t.with_term(|e| e.marks.command_start = Some(std::time::Instant::now() - std::time::Duration::from_secs(12)));
    feed(&t, b"make\r\n\x1b]133;D;2\x1b\\");
    let fin = t.take_events().finished.expect("finished");
    assert_eq!(fin.exit_code, Some(2));
    assert!(fin.duration_ms >= 12_000);
    assert_eq!(t.take_events().finished, None, "taken once");
    feed(&t, b"\x1b]133;D;1\x07");
    assert_eq!(t.take_events().finished, None, "D without C");
}

#[test]
fn notifications_are_rate_limited() {
    let t = session();
    feed(&t, b"\x1b]777;notify;Build;done\x07\x1b]9;second\x07");
    assert_eq!(t.take_events().notification, Some(ProgramNotification { title: "Build".into(), body: "done".into() }));
    assert_eq!(t.take_events().notification, None, "second within the interval dropped");
    t.with_term(|e| e.marks.last_notification = Some(std::time::Instant::now() - std::time::Duration::from_secs(5)));
    feed(&t, b"\x1b]9;third\x07");
    assert_eq!(t.take_events().notification.map(|n| n.body), Some("third".into()));
}

#[test]
fn activity_is_set_by_output_and_taken_once() {
    let t = session();
    assert!(!t.take_events().activity);
    feed(&t, b"x");
    assert!(t.take_events().activity);
    assert!(!t.take_events().activity);
}

#[test]
fn typed_ssh_only_in_the_local_shell() {
    let mut t = session();
    t.write(b"ssh root@web1\r").unwrap();
    assert_eq!(t.take_events().typed_ssh, None, "not a local shell");
    t.typed = Some(Arc::new(Mutex::new(Default::default())));
    t.write(b"ssh root@web1:2222").unwrap();
    assert_eq!(t.take_events().typed_ssh, None, "before Enter");
    t.write(b"\r").unwrap();
    let s = t.take_events().typed_ssh.expect("typed ssh");
    assert_eq!((s.host.as_str(), s.user.as_deref(), s.port), ("web1", Some("root"), Some(2222)));
    assert_eq!(t.take_events().typed_ssh, None);
}

/// Throughput with and without prompt marks (run with `--ignored --nocapture` for the evidence file).
#[test]
#[ignore]
fn feed_throughput() {
    let line = b"drwxr-xr-x  12 user staff   384 Nov 17 10:00 some-directory-name\r\n".repeat(16_000);
    for marks in [false, true] {
        let t = session();
        if marks {
            feed(&t, b"\x1b]133;A\x07$ ls\r\n");
        }
        let start = std::time::Instant::now();
        for _ in 0..10 {
            feed(&t, &line);
        }
        let mb = (line.len() * 10) as f64 / 1e6;
        println!("marks={marks}: {:.0} MB/s", mb / start.elapsed().as_secs_f64());
    }
}

/// Windows: do OSC 133 / 9 / 777 survive ConPTY from a local program? Prints what arrived (diagnostic for #1262).
#[cfg(windows)]
#[test]
fn conpty_passes_marks_and_notifications() {
    let script = "$E=[char]27;$B=[char]7; 1..3 | ForEach-Object { Write-Host ($E+']133;A'+$B+'PROMPT '+$_); 1..30 | ForEach-Object { Write-Host out } }; Write-Host ($E+']9;hello-osc9'+$B); Write-Host DONE";
    let t = TerminalSession::spawn_program("powershell.exe", &["-NoProfile", "-Command", script], 80, 10).unwrap();
    let end = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < end && t.is_alive() {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    std::thread::sleep(std::time::Duration::from_millis(500));
    let prompts = t.with_term(|e| e.marks.prompts.len());
    let note = t.take_events().notification;
    println!("conpty: prompt marks recorded = {prompts}, osc9 = {note:?}");
    assert!(prompts >= 3, "ConPTY dropped OSC 133 ({prompts} marks)");
    assert!(note.is_some(), "ConPTY dropped OSC 9");
}
