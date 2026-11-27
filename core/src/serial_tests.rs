use super::*;

#[test]
fn windows_port_names() {
    assert_eq!(validate_windows_port("COM3").unwrap(), r"\\.\COM3");
    assert_eq!(validate_windows_port(" com12 ").unwrap(), r"\\.\COM12");
    assert_eq!(validate_windows_port(r"\\.\COM256").unwrap(), r"\\.\COM256");
    for bad in ["COM0", "COM257", "COM", "COM01", "LPT1", "C:\\x", "COM3:", "NUL", r"\\.\PhysicalDrive0"] {
        assert!(validate_windows_port(bad).is_err(), "{bad}");
    }
}

#[test]
fn unix_name_rule() {
    for ok in ["/dev/cu.usbserial-A1", "/dev/tty.usbmodem14101", "/dev/ttyUSB0", "/dev/ttyS1", "/dev/ttyACM0"] {
        assert!(is_serial_device_path(ok), "{ok}");
    }
    for bad in ["/dev/disk0", "/dev/null", "/dev/random", "/dev/cu.", "/dev/tty", "/dev/pts/3", "/etc/passwd", "/dev/../etc/passwd", "cu.x", "/dev/cu.x/y"] {
        assert!(!is_serial_device_path(bad), "{bad}");
    }
}

#[cfg(unix)]
#[test]
fn typed_unix_ports_are_checked_after_resolving_links() {
    assert!(validate_unix_port("/dev/null").is_err());
    assert!(validate_unix_port("/dev/disk0").is_err());
    assert!(validate_unix_port("relative/cu.x").is_err());
    // A link whose own name looks like a port but that points elsewhere is refused by its target.
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("cu.fake");
    std::os::unix::fs::symlink("/dev/null", &link).unwrap();
    assert!(validate_unix_port(link.to_str().unwrap()).is_err());
}

fn settings() -> Settings {
    Settings { serial_port: Some("COM3".into()), ..Default::default() }
}

#[test]
fn defaults_and_validation() {
    let s = SerialSettings::from_settings(&settings()).unwrap();
    assert_eq!((s.baud, s.data_bits, s.parity, s.stop_bits, s.flow, s.local_echo, s.enter), (9600, 8, Parity::None, 1, Flow::None, false, LineEnding::Cr));
    assert_eq!(s.status_line(), "COM3 · 9600 8N1");
    let s = SerialSettings::from_settings(&Settings {
        serial_port: Some("/dev/cu.usbserial-A1".into()),
        serial_baud: Some(115200),
        serial_parity: Some("even".into()),
        serial_data_bits: Some(7),
        serial_stop_bits: Some(2),
        ..Default::default()
    })
    .unwrap();
    assert_eq!(s.status_line(), "cu.usbserial-A1 · 115200 7E2");
    assert!(SerialSettings::from_settings(&Settings::default()).is_err(), "no port");
    for bad in [
        Settings { serial_baud: Some(10), ..settings() },
        Settings { serial_data_bits: Some(9), ..settings() },
        Settings { serial_stop_bits: Some(3), ..settings() },
        Settings { serial_parity: Some("mark".into()), ..settings() },
        Settings { serial_flow: Some("dtr".into()), ..settings() },
        Settings { serial_enter: Some("nul".into()), ..settings() },
    ] {
        assert!(SerialSettings::from_settings(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn listing_ports_does_not_fail() {
    // The build machines have no adapters; the list may be empty but must not be an error
    // except where enumeration itself is unsupported.
    if let Ok(ports) = list_serial_ports() {
        assert!(ports.windows(2).all(|w| w[0].name < w[1].name), "sorted, no duplicates");
    }
}

#[test]
fn idle_reads_are_told_from_lost_devices() {
    use std::io::{Error, ErrorKind};
    assert!(is_idle_read(&Error::from(ErrorKind::TimedOut)));
    assert!(!is_idle_read(&Error::from(ErrorKind::BrokenPipe)));
    assert!(!is_idle_read(&Error::from(ErrorKind::PermissionDenied)));
    assert!(!is_idle_read(&Error::other("device gone")));
}

/// The pty tests run one at a time: each makes and closes pty pairs, and the kernel reuses
/// `/dev/pts/<n>` numbers at once.
#[cfg(unix)]
static PTY_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The slave's path. `ttyname_r`, not `ttyname`: the latter returns one shared static buffer, so
/// two tests in parallel read each other's name (a wrong or empty path).
#[cfg(unix)]
fn pty_name(fd: libc::c_int) -> String {
    let mut buf = [0 as libc::c_char; 128];
    assert_eq!(unsafe { libc::ttyname_r(fd, buf.as_mut_ptr(), buf.len()) }, 0);
    unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_str().unwrap().to_string()
}

/// B7-LIVE: a pseudo-terminal opens only in a test-hooks core; a release core refuses it.
#[test]
#[cfg(unix)]
fn pseudo_terminals_open_only_in_test_hooks_builds() {
    let _one = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let (mut master, mut slave) = (0, 0);
    let rc = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    let name = pty_name(slave);
    let result = validate_unix_port(&name);
    unsafe { libc::close(master); libc::close(slave) };
    assert_eq!(result.is_ok(), cfg!(feature = "test-hooks"), "{name}: {result:?}");
    // Neither build accepts other ttys-like names or anything else under /dev/pts.
    assert!(!is_test_pty_path("/dev/ttysX") && !is_test_pty_path("/dev/pts/ptmx") && !is_test_pty_path("/dev/ttys"));
}

/// B7-SERIAL-LINUX: a live round trip through the serial transport on a pseudo-terminal pair. The
/// pty's master end plays the device and echoes what it receives; the slave end is opened by
/// `open_port` at a set baud, data bits, parity and stop bits. Test-hooks builds only: a release
/// core refuses the path (`pseudo_terminals_open_only_in_test_hooks_builds`).
#[test]
#[cfg(all(target_os = "linux", feature = "test-hooks"))]
fn a_pty_device_echoes_through_the_serial_transport() {
    let _one = PTY_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, OwnedFd};
    let (mut master, mut slave) = (0, 0);
    let rc = unsafe { libc::openpty(&mut master, &mut slave, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) };
    assert_eq!(rc, 0);
    let name = pty_name(slave);
    // Both ends are owned, so they close however the test ends.
    let master = unsafe { OwnedFd::from_raw_fd(master) };
    let _slave_hold = unsafe { OwnedFd::from_raw_fd(slave) };

    let settings = SerialSettings { port: name.clone(), baud: 57_600, data_bits: 8, parity: Parity::Even, stop_bits: 2, flow: Flow::None, local_echo: false, enter: LineEnding::Cr };
    let mut port = open_port(&settings).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(port.baud_rate().unwrap(), 57_600, "the baud rate was set on the line");
    // A pty keeps the baud rate but has no parity or stop bits of its own (Linux reports None and
    // One whatever was asked), so those two need a real adapter (USB loopback) to prove.

    // The "device": read what the port sent and write it back, once.
    let mut device = std::fs::File::from(master);
    let message = b"show version\r\x00\xff binary-safe";
    port.write_all(message).unwrap();
    port.flush().unwrap();
    let mut got = vec![0u8; message.len()];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut n = 0;
    while n < got.len() {
        assert!(std::time::Instant::now() < deadline, "the device received only {n} bytes");
        n += device.read(&mut got[n..]).unwrap();
    }
    assert_eq!(&got, message, "the device received the bytes unchanged (raw line, no translation)");
    device.write_all(&got).unwrap();

    let mut echo = vec![0u8; message.len()];
    let mut m = 0;
    while m < echo.len() {
        assert!(std::time::Instant::now() < deadline, "the port read back only {m} bytes");
        match port.read(&mut echo[m..]) {
            Ok(k) => m += k,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => panic!("{e}"),
        }
    }
    assert_eq!(&echo, message, "the echo came back through the transport");
}
