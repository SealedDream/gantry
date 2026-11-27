//! Keyboard check against a real Windows server: `cargo run --example keys -- <host> <port> <user> <out-prefix>`
//! with the password in `BASTION_RDP_PASSWORD`. Accepts the certificate on first use (test only).
//!
//! Each step writes `<prefix>-<step>.ppm`, so a missing keystroke shows as an unchanged frame:
//! `0-desktop`, then Escape and the Windows key (`1-start`, the Start menu should be open), Escape, then Win+R
//! (`2-run`, the Run dialog) and `bastion keys ok` typed into it (`3-typed`). Escape closes the dialog again, so
//! nothing is typed into whatever window had focus.
use bastion_rdp::{RdpError, RdpSession, RdpTarget};
use std::time::Duration;

const LWIN: u8 = 0x5B; // E0-prefixed
const ESC: u8 = 0x01;
const R: u8 = 0x13;

fn dump(s: &RdpSession, path: &str) {
    let f = s.frame(0).expect("frame");
    let mut out = format!("P6 {} {} 255\n", f.width, f.height).into_bytes();
    for px in f.bgra.chunks_exact(4) {
        out.extend_from_slice(&[px[2], px[1], px[0]]);
    }
    std::fs::write(path, out).unwrap();
    println!("wrote {path}");
}

fn tap(s: &RdpSession, code: u8, extended: bool) {
    s.key(code, extended, true);
    std::thread::sleep(Duration::from_millis(40));
    s.key(code, extended, false);
    std::thread::sleep(Duration::from_millis(40));
}

/// Set-1 scancodes for lower-case letters and space (the same on US and UK keyboards).
fn scancode(c: char) -> u8 {
    if c == ' ' {
        return 0x39;
    }
    for (row, base) in [("qwertyuiop", 0x10u8), ("asdfghjkl", 0x1E), ("zxcvbnm", 0x2C)] {
        if let Some(i) = row.find(c) {
            return base + i as u8;
        }
    }
    panic!("no scancode for {c:?}")
}

fn type_text(s: &RdpSession, text: &str) {
    for c in text.chars() {
        tap(s, scancode(c), false);
    }
}

fn chord(s: &RdpSession, held: u8, held_extended: bool, code: u8) {
    s.key(held, held_extended, true);
    std::thread::sleep(Duration::from_millis(40));
    tap(s, code, false);
    s.key(held, held_extended, false);
}

fn pause(ms: u64) {
    std::thread::sleep(Duration::from_millis(ms));
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let pw = std::env::var("BASTION_RDP_PASSWORD").expect("BASTION_RDP_PASSWORD");
    let mut t = RdpTarget { nla_only: true, via_loopback_port: None, clipboard: false, shared_folder: None, audio: false, color_depth: 32, host: a[1].clone(), port: a[2].parse().unwrap(), username: a[3].clone(), domain: None, width: 1280, height: 800, trusted_fingerprint: None };
    let s = RdpSession::new().unwrap();
    let first = s.connect(t.clone(), pw.clone());
    println!("first: {first:?}");
    if let Err(RdpError::CertificateUnknown { fingerprint }) = first {
        t.trusted_fingerprint = Some(fingerprint);
        s.connect(t, pw).expect("pinned connect");
    }
    // Taking over a session shows the lock screen for several seconds before the desktop, and keys sent meanwhile
    // go to the lock screen; that is what made the first Windows 11 run look like keys never arrived.
    pause(15000);
    println!("state {:?} {:?}", s.state(), s.close_reason());
    let p = &a[4];
    dump(&s, &format!("{p}-0-desktop.ppm"));
    tap(&s, ESC, false);
    pause(300);
    tap(&s, LWIN, true);
    pause(2500);
    dump(&s, &format!("{p}-1-start.ppm"));
    tap(&s, ESC, false);
    pause(800);
    chord(&s, LWIN, true, R);
    // The Run dialog can take seconds to take focus on a busy machine; letters typed before then land elsewhere.
    pause(5000);
    dump(&s, &format!("{p}-2-run.ppm"));
    type_text(&s, "bastion keys ok");
    pause(1500);
    dump(&s, &format!("{p}-3-typed.ppm"));
    tap(&s, ESC, false);
    pause(800);
    println!("state {:?}", s.state());
    s.close();
    pause(500);
}
