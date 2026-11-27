use super::*;

const IAC_: u8 = 255;

fn codec() -> TelnetCodec {
    TelnetCodec::new(80, 24, "XTERM-256COLOR")
}

#[test]
fn plain_data_passes_and_doubled_iac_is_one_byte() {
    let mut c = codec();
    let d = c.decode(b"hello").unwrap();
    assert_eq!(d.data, b"hello");
    assert!(d.reply.is_empty());
    let d = c.decode(&[b'a', IAC_, IAC_, b'b']).unwrap();
    assert_eq!(d.data, vec![b'a', 255, b'b']);
}

#[test]
fn commands_split_across_reads_are_handled() {
    let mut c = codec();
    let a = c.decode(&[b'x', IAC_]).unwrap();
    assert_eq!(a.data, b"x");
    let b = c.decode(&[DO]).unwrap();
    assert!(b.reply.is_empty());
    let d = c.decode(&[OPT_TTYPE, b'y']).unwrap();
    assert_eq!(d.reply, vec![IAC, WILL, OPT_TTYPE]);
    assert_eq!(d.data, b"y");
}

#[test]
fn supported_options_are_accepted_once_and_others_refused() {
    let mut c = codec();
    let d = c.decode(&[IAC, DO, OPT_TTYPE, IAC, DO, OPT_TTYPE]).unwrap();
    assert_eq!(d.reply, vec![IAC, WILL, OPT_TTYPE], "no second WILL for an option already on");
    let d = c.decode(&[IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA]).unwrap();
    assert_eq!(d.reply, vec![IAC, DO, OPT_ECHO, IAC, DO, OPT_SGA]);
    assert!(c.server_echoes());
    // Linemode (34), environment (39), anything else: refused.
    let d = c.decode(&[IAC, DO, 34, IAC, WILL, 39]).unwrap();
    assert_eq!(d.reply, vec![IAC, WONT, 34, IAC, DONT, 39]);
    let d = c.decode(&[IAC, WONT, OPT_ECHO]).unwrap();
    assert_eq!(d.reply, vec![IAC, DONT, OPT_ECHO]);
    assert!(!c.server_echoes());
    let d = c.decode(&[IAC, DONT, OPT_TTYPE]).unwrap();
    assert_eq!(d.reply, vec![IAC, WONT, OPT_TTYPE]);
}

#[test]
fn naws_is_sent_when_agreed_and_on_resize() {
    let mut c = codec();
    assert_eq!(c.resize(100, 30), None, "no NAWS before the server asks");
    let d = c.decode(&[IAC, DO, OPT_NAWS]).unwrap();
    assert_eq!(d.reply, vec![IAC, WILL, OPT_NAWS, IAC, SB, OPT_NAWS, 0, 100, 0, 30, IAC, SE]);
    assert_eq!(c.resize(132, 50), Some(vec![IAC, SB, OPT_NAWS, 0, 132, 0, 50, IAC, SE]));
    // A size byte equal to IAC is doubled.
    assert_eq!(c.resize(255, 24), Some(vec![IAC, SB, OPT_NAWS, 0, 255, 255, 0, 24, IAC, SE]));
}

#[test]
fn terminal_type_is_sent_on_request() {
    let mut c = codec();
    c.decode(&[IAC, DO, OPT_TTYPE]).unwrap();
    let d = c.decode(&[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE]).unwrap();
    let mut want = vec![IAC, SB, OPT_TTYPE, TTYPE_IS];
    want.extend_from_slice(b"XTERM-256COLOR");
    want.extend_from_slice(&[IAC, SE]);
    assert_eq!(d.reply, want);
}

#[test]
fn terminal_type_is_not_sent_unless_agreed() {
    let mut c = codec();
    let d = c.decode(&[IAC, SB, OPT_TTYPE, TTYPE_SEND, IAC, SE]).unwrap();
    assert!(d.reply.is_empty());
}

#[test]
fn a_negotiation_loop_closes_the_connection() {
    let mut c = codec();
    let mut flood = Vec::new();
    for _ in 0..=MAX_NEGOTIATIONS_WITHOUT_DATA {
        flood.extend_from_slice(&[IAC, DO, 34]);
    }
    assert!(c.decode(&flood).is_err());
    // Data in between resets the count.
    let mut c = codec();
    for _ in 0..(MAX_NEGOTIATIONS_WITHOUT_DATA * 3) {
        c.decode(&[IAC, DO, 34, b'.']).unwrap();
    }
}

#[test]
fn an_oversized_subnegotiation_closes_the_connection() {
    let mut c = codec();
    let mut big = vec![IAC, SB, OPT_TTYPE];
    big.extend(std::iter::repeat(b'a').take(MAX_SUBNEGOTIATION + 1));
    assert!(c.decode(&big).is_err());
}

#[test]
fn input_is_escaped_for_the_wire() {
    assert_eq!(TelnetCodec::encode_input(&[b'a', 255, b'b']), vec![b'a', 255, 255, b'b']);
    assert_eq!(TelnetCodec::encode_input(b"ls\r"), b"ls\r\0".to_vec());
    assert_eq!(TelnetCodec::encode_input(b"ls\r\n"), b"ls\r\n".to_vec());
}

fn login() -> AutoLogin {
    AutoLogin { username: "admin".into(), password: Secret::new("hunter2-secret") }
}

#[test]
fn auto_login_types_username_then_password_once() {
    let t0 = Instant::now();
    let mut w = LoginWatcher::with_timeout(login(), Duration::from_secs(10), t0);
    assert_eq!(w.feed(b"Welcome\r\n", t0), None);
    assert_eq!(w.feed(b"router login: ", t0), Some(b"admin\r".to_vec()));
    assert_eq!(w.feed(b"admin\r\n", t0), None, "the echo of the username is not a prompt");
    assert_eq!(w.feed(b"Password: ", t0), Some(b"hunter2-secret\r".to_vec()));
    assert!(w.done());
    assert_eq!(w.feed(b"\r\nlogin: ", t0), None, "never twice per connect");
    assert_eq!(w.feed(b"Password: ", t0), None);
}

#[test]
fn a_password_prompt_before_the_login_prompt_is_ignored() {
    let t0 = Instant::now();
    let mut w = LoginWatcher::with_timeout(login(), Duration::from_secs(10), t0);
    assert_eq!(w.feed(b"Password: ", t0), None, "a fake early prompt gets nothing");
    assert_eq!(w.feed(b"\r\nlogin: ", t0), Some(b"admin\r".to_vec()));
}

#[test]
fn prompts_split_across_reads_and_coloured_prompts_match() {
    let t0 = Instant::now();
    let mut w = LoginWatcher::with_timeout(login(), Duration::from_secs(10), t0);
    assert_eq!(w.feed(b"\x1b[1mLog", t0), None);
    assert_eq!(w.feed(b"in:\x1b[0m ", t0), Some(b"admin\r".to_vec()));
}

#[test]
fn auto_login_gives_up_after_the_timeout() {
    let t0 = Instant::now();
    let mut w = LoginWatcher::with_timeout(login(), Duration::from_secs(10), t0);
    assert_eq!(w.feed(b"login: ", t0 + Duration::from_secs(11)), None);
    assert!(w.done());
    // The password wait has its own limit from when the username was sent.
    let mut w = LoginWatcher::with_timeout(login(), Duration::from_secs(10), t0);
    let t1 = t0 + Duration::from_secs(9);
    assert!(w.feed(b"login: ", t1).is_some());
    assert_eq!(w.feed(b"Password: ", t1 + Duration::from_secs(11)), None);
}

#[test]
fn the_password_is_never_in_debug_output() {
    let opts = TelnetOptions { auto_login: Some(login()), ..TelnetOptions::new("h", 23) };
    let shown = format!("{opts:?} {:?}", LoginWatcher::new(login()));
    assert!(!shown.contains("hunter2"), "{shown}");
    assert!(shown.contains("admin"));
}
