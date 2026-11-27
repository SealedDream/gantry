use std::io::{Read, Write};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::settings::SettingsFile;
use crate::terminal::{SessionManager, SshLogin};
use crate::Library;

struct Fixture {
    _dir: tempfile::TempDir,
    lib: Arc<Library>,
    settings: Arc<SettingsFile>,
    manager: Arc<SessionManager>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let lib = Arc::new(Library::open(dir.path().join("lib.json").to_string_lossy().into()).unwrap());
    let settings = Arc::new(SettingsFile::open(dir.path().join("settings.json").to_string_lossy().into()).unwrap());
    let manager = SessionManager::new(dir.path().join("data").to_string_lossy().into()).unwrap();
    Fixture { _dir: dir, lib, settings, manager }
}

/// A one-shot Telnet server on localhost: shows `login:` and records what the client sends.
fn server() -> (u16, std::thread::JoinHandle<Vec<u8>>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let Ok((mut s, _)) = l.accept() else { return Vec::new() };
        s.write_all(b"login: ").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(800))).unwrap();
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n) = s.read(&mut buf) {
            if n == 0 {
                break;
            }
            got.extend_from_slice(&buf[..n]);
            if got.ends_with(b"\r\0") && got.windows(9).any(|w| w == b"pw-secret") {
                break;
            }
            if got.ends_with(b"admin\r\0") {
                s.write_all(b"\r\nPassword: ").unwrap();
            }
        }
        got
    });
    (port, h)
}

fn telnet_conn(f: &Fixture, port: u16) -> String {
    f.lib.add_connection(None, "router".into(), "telnet".into(), "127.0.0.1".into(), Some(port), Some("admin".into())).unwrap()
}

#[test]
fn telnet_is_refused_until_the_user_allows_it() {
    let f = fixture();
    let id = telnet_conn(&f, 1);
    assert!(!telnet_allowed(f.settings.clone()));
    let e = f.manager.connect_telnet(f.lib.clone(), f.settings.clone(), id, String::new(), None, 80, 24).err().expect("refused").to_string();
    assert!(e.contains("Allow Telnet"), "{e}");
}

#[test]
fn allowed_telnet_connects_and_types_nothing_without_the_opt_in() {
    let f = fixture();
    f.settings.set(ALLOW_TELNET_SETTING.into(), "true".into()).unwrap();
    assert!(telnet_allowed(f.settings.clone()));
    let (port, srv) = server();
    let id = telnet_conn(&f, port);
    let login = SshLogin::Password { password: "pw-secret".into() };
    let t = f.manager.connect_telnet(f.lib.clone(), f.settings.clone(), id, "admin".into(), Some(login), 80, 24).unwrap();
    let got = srv.join().unwrap();
    assert!(got.is_empty(), "typed without the opt-in: {got:?}");
    assert!(t.can_reconnect());
    t.close();
}

#[test]
fn the_opt_in_types_username_then_password() {
    let f = fixture();
    f.settings.set(ALLOW_TELNET_SETTING.into(), "true".into()).unwrap();
    let (port, srv) = server();
    let id = telnet_conn(&f, port);
    f.lib.set_property(id.clone(), "telnet_send_password".into(), Some("true".into())).unwrap();
    let login = SshLogin::Password { password: "pw-secret".into() };
    let t = f.manager.connect_telnet(f.lib.clone(), f.settings.clone(), id, "admin".into(), Some(login), 80, 24).unwrap();
    let got = srv.join().unwrap();
    let text = String::from_utf8_lossy(&got);
    let (u, p) = (text.find("admin").expect("username typed"), text.find("pw-secret").expect("password typed"));
    assert!(u < p, "{text}");
    t.close();
}

#[test]
fn a_folder_cannot_turn_the_password_opt_in_on() {
    let f = fixture();
    let folder = f.lib.add_folder(None, "lab".into()).unwrap();
    // The folder defaults path refuses the key or ignores it; either way the connection is not opted in.
    let _ = f.lib.set_property(folder.clone(), "telnet_send_password".into(), Some("true".into()));
    let id = f.lib.add_connection(Some(folder), "r".into(), "telnet".into(), "h".into(), None, None).unwrap();
    let opted = f.lib.resolve(crate::parse_id(&id).unwrap()).unwrap().settings.telnet_send_password;
    assert_ne!(opted, Some(true));
}

#[test]
fn serial_connection_reports_a_missing_port_in_words() {
    let f = fixture();
    let id = f.lib.add_connection(None, "console".into(), "serial".into(), String::new(), None, None).unwrap();
    let missing = if cfg!(windows) { "COM250" } else { "/dev/cu.bastion-missing" };
    f.lib.set_property(id.clone(), "serial_port".into(), Some(missing.into())).unwrap();
    let e = Terminal::serial_connection(f.lib.clone(), id, 80, 24).err().expect("missing port").to_string();
    assert!(e.to_lowercase().contains("not found"), "{e}");
}

#[test]
fn serial_settings_are_validated_when_set() {
    let f = fixture();
    let id = f.lib.add_connection(None, "console".into(), "serial".into(), String::new(), None, None).unwrap();
    for (k, v) in [("serial_port", "/dev/disk0"), ("serial_port", "/etc/passwd"), ("serial_baud", "10"), ("serial_parity", "mark")] {
        assert!(f.lib.set_property(id.clone(), k.into(), Some(v.into())).is_err(), "{k}={v}");
    }
    f.lib.set_property(id.clone(), "serial_baud".into(), Some("115200".into())).unwrap();
}

#[test]
fn port_list_and_constants() {
    assert_eq!(serial_port_poll_ms(), 2000);
    assert!(serial_common_bauds().contains(&115200));
    let _ = list_serial_ports();
    assert!(telnet_warning().contains("not encrypted"));
}
