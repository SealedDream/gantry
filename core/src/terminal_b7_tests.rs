use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::*;
use crate::telnet::AutoLogin;
use crate::vault::Secret;

const IAC: u8 = 255;

async fn read_until(s: &mut TcpStream, needle: &[u8]) -> Vec<u8> {
    let mut got = Vec::new();
    let mut buf = [0u8; 256];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !got.windows(needle.len()).any(|w| w == needle) {
        let n = tokio::time::timeout_at(deadline, s.read(&mut buf)).await.expect("server waited too long").unwrap();
        assert!(n > 0, "client closed early; got {got:?}");
        got.extend_from_slice(&buf[..n]);
    }
    got
}

fn wait_for(term: &TerminalSession, text: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !term.screen().text().contains(text) {
        assert!(Instant::now() < deadline, "screen never showed {text:?}: {}", term.screen().text());
        term.wait_change(term.generation(), Duration::from_millis(100));
    }
}

/// A fake Telnet server: asks for NAWS, shows a login prompt, checks the typed login, echoes.
#[test]
fn telnet_session_logs_in_echoes_resizes_and_keeps_the_password_out_of_the_log() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    // The server sends nothing until the log has started, so the log holds the whole session (the login prompt
    // included) however the threads are scheduled.
    let (log_started, log_started_rx) = tokio::sync::oneshot::channel::<()>();
    let server = rt.spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        log_started_rx.await.unwrap();
        s.write_all(&[IAC, 253, 31]).await.unwrap(); // DO NAWS
        let got = read_until(&mut s, &[IAC, 250, 31]).await; // WILL NAWS + first size
        assert!(got.windows(3).any(|w| w == [IAC, 251, 31]));
        s.write_all(b"Welcome\r\nrouter login: ").await.unwrap();
        read_until(&mut s, b"admin\r\0").await;
        s.write_all(b"admin\r\nPassword: ").await.unwrap();
        read_until(&mut s, b"s3cret-pw\r\0").await;
        s.write_all(b"\r\nrouter# ").await.unwrap();
        // Typing is echoed by the server.
        read_until(&mut s, b"show\r\0").await;
        s.write_all(b"show\r\nok\r\nrouter# ").await.unwrap();
        // The resize arrives as a NAWS block with the new size.
        read_until(&mut s, &[IAC, 250, 31, 0, 100, 0, 30, IAC, 240]).await;
        s.write_all(b"resized\r\n").await.unwrap();
        s.shutdown().await.unwrap();
        // Read what the client still sends until it closes. On Windows, closing a socket with unread bytes in its
        // receive buffer sends a reset instead of a normal close, and the client would see a lost link.
        let mut rest = [0u8; 256];
        let _ = tokio::time::timeout(Duration::from_secs(5), async { while matches!(s.read(&mut rest).await, Ok(n) if n > 0) {} }).await;
    });
    let mut opts = TelnetOptions::new("127.0.0.1", port);
    opts.auto_login = Some(AutoLogin { username: "admin".into(), password: Secret::new("s3cret-pw") });
    let stream = rt.block_on(connect_telnet_stream(&opts)).unwrap();
    let (term, end) = TerminalSession::attach_telnet(stream, &opts, 80, 24, rt.handle()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("telnet.log");
    term.start_log(&log, "test").unwrap();
    log_started.send(()).unwrap();
    wait_for(&term, "router#");
    term.write(b"show\r").unwrap();
    wait_for(&term, "ok");
    term.resize(100, 30).unwrap();
    wait_for(&term, "resized");
    rt.block_on(server).unwrap();
    assert_eq!(rt.block_on(end).unwrap(), LinkEnd::Finished, "the server closing is a normal end");
    assert!(!term.is_alive());
    drop(term);
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(logged.contains("router login:"));
    assert!(!logged.contains("s3cret-pw"), "{logged}");
}

#[test]
fn without_the_opt_in_nothing_is_typed() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = rt.spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"login: ").await.unwrap();
        let mut buf = [0u8; 64];
        let r = tokio::time::timeout(Duration::from_millis(500), s.read(&mut buf)).await;
        assert!(r.is_err(), "the client typed something without the opt-in");
    });
    let opts = TelnetOptions::new("127.0.0.1", port);
    let stream = rt.block_on(connect_telnet_stream(&opts)).unwrap();
    let (term, _end) = TerminalSession::attach_telnet(stream, &opts, 80, 24, rt.handle()).unwrap();
    wait_for(&term, "login:");
    rt.block_on(server).unwrap();
}

#[test]
fn a_dropped_telnet_link_is_lost_and_reattaches_on_the_same_screen() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let listener = rt.block_on(TcpListener::bind("127.0.0.1:0")).unwrap();
    let port = listener.local_addr().unwrap().port();
    let opts = TelnetOptions::new("127.0.0.1", port);
    let first = rt.spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        // Let the client's connect finish before the reset (it can otherwise fail the connect itself).
        tokio::time::sleep(Duration::from_millis(200)).await;
        s.write_all(b"first\r\n").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Reset the connection instead of a clean close.
        #[allow(deprecated)]
        s.set_linger(Some(Duration::ZERO)).unwrap();
        drop(s);
        listener
    });
    let stream = rt.block_on(connect_telnet_stream(&opts)).unwrap();
    let (term, end) = TerminalSession::attach_telnet(stream, &opts, 80, 24, rt.handle()).unwrap();
    wait_for(&term, "first");
    let listener = rt.block_on(first).unwrap();
    let ended = rt.block_on(end).unwrap();
    // A reset reads as an error (Lost) or, on some systems, as a plain close (Finished).
    if let LinkEnd::Lost(_) = ended {
        assert!(term.is_alive(), "a lost link keeps the screen open for reconnect");
    }
    let second = rt.spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        s.write_all(b"second\r\n").await.unwrap();
        s
    });
    let stream = rt.block_on(connect_telnet_stream(&opts)).unwrap();
    let _end2 = term.reattach_telnet(stream, &opts, rt.handle()).unwrap();
    wait_for(&term, "second");
    assert!(term.screen().text().contains("first"), "scrollback kept");
    drop(rt.block_on(second).unwrap());
}

#[test]
fn connecting_to_a_closed_port_fails_in_words() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    let mut opts = TelnetOptions::new("127.0.0.1", port);
    opts.connect_timeout = Duration::from_secs(2);
    let e = rt.block_on(connect_telnet_stream(&opts)).unwrap_err().to_string();
    assert!(e.contains("127.0.0.1"), "{e}");
}

fn sink_for_test() -> (TerminalSession, OutputSink) {
    let t = TerminalSession::spawn_program(if cfg!(windows) { "cmd.exe" } else { "sh" }, &[], 80, 24).unwrap();
    let s = t.sink();
    (t, s)
}

#[test]
fn serial_reader_keeps_reading_through_timeouts_and_stops_at_once_on_a_lost_device() {
    use std::io::{Error, ErrorKind};
    let (_t, sink) = sink_for_test();
    let mut buf = [0u8; 16];
    let mut script = vec![Err(Error::from(ErrorKind::TimedOut)), Ok(b"hi".to_vec()), Err(Error::from(ErrorKind::TimedOut)), Err(Error::other("device gone"))].into_iter();
    let mut calls = 0;
    let end = pump_reads(
        |b| {
            calls += 1;
            match script.next().expect("read again after the device was lost") {
                Ok(v) => {
                    b[..v.len()].copy_from_slice(&v);
                    Ok(v.len())
                }
                Err(e) => Err(e),
            }
        },
        &mut buf,
        &sink,
        || false,
        || false,
    );
    assert_eq!(end, Some(LinkEnd::Lost(PORT_DISCONNECTED.into())));
    assert_eq!(calls, 4, "no retry after the error");
}

#[test]
fn serial_reader_reports_close_and_replace() {
    let (_t, sink) = sink_for_test();
    let mut buf = [0u8; 4];
    assert_eq!(pump_reads(|_| Ok(1), &mut buf, &sink, || true, || false), Some(LinkEnd::Finished));
    assert_eq!(pump_reads(|_| Ok(1), &mut buf, &sink, || false, || true), None);
    // End of file means the device is gone.
    assert_eq!(pump_reads(|_| Ok(0), &mut buf, &sink, || false, || false), Some(LinkEnd::Lost(PORT_DISCONNECTED.into())));
}

#[test]
fn opening_a_port_that_does_not_exist_fails_in_words() {
    let s = SerialSettings::from_settings(&crate::model::Settings {
        serial_port: Some(if cfg!(windows) { "COM250".into() } else { "/dev/cu.bastion-missing".into() }),
        ..Default::default()
    })
    .unwrap();
    let e = TerminalSession::open_serial(&s, 80, 24).err().expect("no such port").to_string();
    assert!(e.contains("not found") || e.contains("Port"), "{e}");
}

/// A real pty pair (`socat`) stands in for a cable: what one end types arrives at the terminal,
/// at 9600 and 115200 baud, and closing the tab releases the port so it can be opened again.
/// Skipped where socat is not installed.
#[cfg(unix)]
#[test]
fn serial_terminal_over_a_socat_pty_pair() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let (a, b) = (dir.path().join("ttyA"), dir.path().join("ttyB"));
    let Ok(mut socat) = std::process::Command::new("socat")
        .arg(format!("pty,raw,echo=0,link={}", a.display()))
        .arg(format!("pty,raw,echo=0,link={}", b.display()))
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        eprintln!("socat not installed: skipped");
        return;
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !(a.exists() && b.exists()) {
        assert!(Instant::now() < deadline, "socat did not create the pair");
        std::thread::sleep(Duration::from_millis(50));
    }
    // The pty pair lives under /dev/pts (Linux) or /dev/ttys* (macOS), not /dev/cu.*, so this test
    // opens it through the crate directly with the same settings code and reader.
    let real_a = std::fs::canonicalize(&a).unwrap();
    for baud in [9600, 115200] {
        let s = SerialSettings {
            port: real_a.to_string_lossy().into(),
            baud,
            data_bits: 8,
            parity: crate::serial::Parity::None,
            stop_bits: 1,
            flow: crate::serial::Flow::None,
            local_echo: false,
            enter: crate::serial::LineEnding::Cr,
        };
        let port = serialport::new(&s.port, baud).timeout(crate::serial::SERIAL_READ_TIMEOUT).open().unwrap();
        let backend = Arc::new(SerialBackend { settings: s.clone(), port: Mutex::new(None), epoch: Arc::new(AtomicU64::new(0)), closed: Arc::new(AtomicBool::new(false)) });
        let mut term = TerminalSession::new(checked_size(80, 24).unwrap(), backend.clone());
        term.serial = Some(backend.clone());
        let end = backend.start(port, term.sink()).unwrap();
        assert_eq!(term.serial_status().unwrap(), format!("{} · {baud} 8N1", real_a.file_name().unwrap().to_string_lossy()));
        let mut far = std::fs::OpenOptions::new().read(true).write(true).open(&b).unwrap();
        far.write_all(format!("hello at {baud}\r\n").as_bytes()).unwrap();
        wait_for(&term, &format!("hello at {baud}"));
        term.write(b"x\r").unwrap();
        let mut got = [0u8; 2];
        std::io::Read::read_exact(&mut far, &mut got).unwrap();
        assert_eq!(&got, b"x\r");
        term.close();
        let rt = tokio::runtime::Runtime::new().unwrap();
        assert_eq!(rt.block_on(end).unwrap(), LinkEnd::Finished);
    }
    // Released: the port opens again after close.
    assert!(serialport::new(real_a.to_string_lossy(), 9600).open().is_ok());
    let _ = socat.kill();
    let _ = socat.wait();
}
