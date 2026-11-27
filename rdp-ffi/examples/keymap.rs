//! Owner point 29: every key a Mac types must reach Windows unchanged.
//! `cargo run --example keymap -- <host> <port> <user> <table> <expected-out> <windows-file>` with the password in
//! `BASTION_RDP_PASSWORD`. `<table>` comes from `swift examples/mac-layout-table.swift <input source>`: the
//! character each Mac key types with no modifier, Shift, Option and Shift+Option on that layout.
//!
//! The example sends exactly what the Mac RDP view sends (`RdpView.swift`): Shift goes down as a scancode when
//! pressed, is released before a typed character (which goes out as a Unicode event), Option sends nothing on its
//! own; non-text keys are scancodes. It types into Notepad (opened on `<windows-file>`),
//! one `<key><n|s|o|b>=<char>|` line per entry, then a navigation / editing / function-key line, saves with
//! Ctrl+S and writes the text it expects Notepad to hold to `<expected-out>`. `scripts/rdp-keymap-test.sh` reads
//! the file back over SSH and diffs it.
use bastion_rdp::{RdpError, RdpSession, RdpTarget};
use std::time::Duration;

const LSHIFT: u8 = 0x2A;
const LCTRL: u8 = 0x1D;
const LWIN: u8 = 0x5B; // E0
const ENTER: u8 = 0x1C;
const R: u8 = 0x13;
const A: u8 = 0x1E;
const S: u8 = 0x1F;
const W: u8 = 0x11;
const BACKSPACE: u8 = 0x0E;
const TAB: u8 = 0x0F;
const ESC: u8 = 0x01;
// E0-prefixed navigation keys
const HOME: u8 = 0x47;
const END: u8 = 0x4F;
const LEFT: u8 = 0x4B;
const UP: u8 = 0x48;
const DOWN: u8 = 0x50;
const DELETE: u8 = 0x53;
const F5: u8 = 0x3F;
/// About 16 keys a second: faster than fast human typing.
const PAUSE_MS: u64 = 40;

fn pause(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

fn key(s: &RdpSession, code: u8, extended: bool, down: bool) {
    s.key(code, extended, down);
    pause(PAUSE_MS);
}

fn tap(s: &RdpSession, code: u8, extended: bool) {
    key(s, code, extended, true);
    key(s, code, extended, false);
}

fn chord(s: &RdpSession, held: u8, held_extended: bool, code: u8, extended: bool) {
    key(s, held, held_extended, true);
    tap(s, code, extended);
    key(s, held, held_extended, false);
}

/// Types `t` one keystroke at a time, as the view does (one `type_text` per key press).
fn text(s: &RdpSession, t: &str) {
    for ch in t.chars() {
        s.type_text(ch.to_string());
        pause(PAUSE_MS);
    }
}

/// One table entry, sent as the Mac view sends it.
fn mac_key(s: &RdpSession, modifier: &str, ch: &str) {
    let shift = modifier.contains("shift");
    if shift {
        key(s, LSHIFT, false, true); // flagsChanged: Shift down
        key(s, LSHIFT, false, false); // liftTypingModifiers before the text
    }
    text(s, ch); // Option: nothing goes out for the modifier itself
    if shift {
        key(s, LSHIFT, false, false); // flagsChanged: Shift up
    }
}

/// With `KEYMAP_SHOTS=<dir>`, saves the desktop as `<dir>/<name>.ppm` (to see where keys went).
fn shot(s: &RdpSession, name: &str) {
    let Ok(dir) = std::env::var("KEYMAP_SHOTS") else { return };
    let Some(f) = s.frame(0) else { return };
    let mut out = format!("P6 {} {} 255\n", f.width, f.height).into_bytes();
    for px in f.bgra.chunks_exact(4) {
        out.extend_from_slice(&[px[2], px[1], px[0]]);
    }
    let _ = std::fs::write(format!("{dir}/{name}.ppm"), out);
}

fn hex_utf8(h: &str) -> String {
    let bytes: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect();
    String::from_utf8(bytes).unwrap()
}

/// Home, End, arrows, Backspace, Delete, Tab, Shift+Home selection and F5 (Notepad's time/date).
/// Returns the lines Notepad should hold afterwards; the F5 line is checked by pattern (`@F5`).
fn navigation(s: &RdpSession) -> Vec<String> {
    text(s, "abc");
    tap(s, HOME, true);
    text(s, "X");
    tap(s, END, true);
    text(s, "Y"); // XabcY
    tap(s, LEFT, true);
    tap(s, LEFT, true); // Xab|cY
    tap(s, BACKSPACE, false); // Xa|cY
    tap(s, DELETE, true); // Xa|Y
    text(s, "Z"); // XaZ|Y
    key(s, LSHIFT, false, true);
    tap(s, HOME, true);
    key(s, LSHIFT, false, false);
    text(s, "Q"); // Q|Y
    tap(s, TAB, false); // Q\t|Y
    tap(s, ENTER, false); // Enter splits the line: "Q\t" / "|Y"
    text(s, "L2"); // L2|Y
    tap(s, UP, true);
    tap(s, END, true);
    text(s, "U"); // Q\tU
    tap(s, DOWN, true);
    tap(s, END, true);
    text(s, "D"); // L2YD
    tap(s, ENTER, false);
    tap(s, F5, false);
    tap(s, ENTER, false);
    // Escape must do nothing in the editor; a "." after it proves no modifier is left down.
    tap(s, ESC, false);
    text(s, ".");
    vec!["Q\tU".into(), "L2YD".into(), "@F5".into(), ".".into()]
}

fn connect(a: &[String]) -> std::sync::Arc<RdpSession> {
    let pw = std::env::var("BASTION_RDP_PASSWORD").expect("BASTION_RDP_PASSWORD");
    let mut t = RdpTarget { nla_only: true, via_loopback_port: None, clipboard: false, shared_folder: None, audio: false, color_depth: 32, host: a[1].clone(), port: a[2].parse().unwrap(), username: a[3].clone(), domain: None, width: 1280, height: 800, trusted_fingerprint: None };
    let s = RdpSession::new().unwrap();
    if let Err(RdpError::CertificateUnknown { fingerprint }) = s.connect(t.clone(), pw.clone()) {
        t.trusted_fingerprint = Some(fingerprint);
        s.connect(t, pw).expect("pinned connect");
    }
    s
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let table = std::fs::read_to_string(&a[4]).expect("table");
    let s = connect(&a);
    // Taking over the session shows the lock screen for several seconds first.
    pause(15000);
    tap(&s, ESC, false);
    chord(&s, LWIN, true, R, false);
    pause(4000);
    shot(&s, "1-run");
    text(&s, &format!("notepad {}", a[6]));
    tap(&s, ENTER, false);
    pause(5000);
    shot(&s, "2-notepad");
    chord(&s, LCTRL, false, A, false);
    tap(&s, DELETE, true);

    let mut expected = Vec::new();
    for line in table.lines() {
        let mut f = line.split(' ');
        let (code, modifier, hex) = (f.next().unwrap(), f.next().unwrap(), f.next().unwrap());
        let ch = hex_utf8(hex);
        // Short labels keep a full layout under the 10-minute cap: n, s, o, b(oth) for the modifiers.
        let label = format!("{code}{}=", match modifier { "none" => "n", "shift" => "s", "option" => "o", _ => "b" });
        text(&s, &label);
        mac_key(&s, modifier, &ch);
        // A trailing "|" stops Notepad's autocorrect treating the character as a word ("i" → "I").
        text(&s, "|");
        tap(&s, ENTER, false);
        expected.push(format!("{label}{ch}|"));
    }
    expected.extend(navigation(&s));
    shot(&s, "3-typed");
    chord(&s, LCTRL, false, S, false);
    pause(2000);
    shot(&s, "4-saved");
    chord(&s, LCTRL, false, W, false); // close this tab only; other Notepad tabs stay
    pause(1000);
    std::fs::write(&a[5], expected.join("\n")).unwrap();
    println!("typed {} lines, state {:?}", expected.len(), s.state());
    s.close();
    pause(500);
}
