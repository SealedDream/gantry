use super::*;
use crate::model::Document;
use crate::sshconfig::SshConfig;

fn hosts(text: &str) -> Vec<ResolvedHost> {
    SshConfig::parse_str(text, "config").hosts()
}

fn doc_with(hs: &[ResolvedHost]) -> Document {
    let mut d = Document::new("t");
    crate::sshworkflow::import_hosts(&mut d, hs).unwrap();
    d
}

#[test]
fn parses_every_listen_form() {
    let l = |v| parse(ForwardKind::Local, v);
    let local = |p, h: &str, dp| TunnelSpec::Local { local_port: p, dest_host: h.into(), dest_port: dp };
    assert_eq!(l("5432 db:5432").unwrap(), ParsedForward { spec: local(5432, "db", 5432), wide_bind: false });
    assert!(!l("127.0.0.1:5432 db:5432").unwrap().wide_bind);
    assert!(!l("localhost:5432 db:5432").unwrap().wide_bind);
    assert!(!l("[::1]:443 web:443").unwrap().wide_bind);
    assert!(l("*:8080 web:80").unwrap().wide_bind);
    assert!(l("0.0.0.0:8080 web:80").unwrap().wide_bind);
    assert!(l(":8080 web:80").unwrap().wide_bind, "empty bind = all interfaces");
    assert!(l("[::]:8080 web:80").unwrap().wide_bind);
    assert!(l("192.168.1.5:8080 web:80").unwrap().wide_bind);
    assert_eq!(l("8443 [fd00::1]:443").unwrap().spec, local(8443, "fd00::1", 443));
    assert_eq!(parse(ForwardKind::Dynamic, "1080").unwrap().spec, TunnelSpec::Dynamic { local_port: 1080 });
    assert_eq!(
        parse(ForwardKind::Remote, "9000 localhost:3000").unwrap().spec,
        TunnelSpec::Remote { remote_port: 9000, local_host: "localhost".into(), local_port: 3000 }
    );
}

#[test]
fn refuses_what_bastion_cannot_do() {
    assert!(parse(ForwardKind::Local, "/tmp/s.sock db:5432").unwrap_err().contains("Unix socket"));
    assert!(parse(ForwardKind::Local, "5432 /run/pg.sock").unwrap_err().contains("Unix socket"));
    assert!(parse(ForwardKind::Remote, "1080").unwrap_err().contains("remote SOCKS"));
    assert!(parse(ForwardKind::Local, "0 db:5432").is_err());
    assert!(parse(ForwardKind::Local, "70000 db:5432").is_err());
    assert!(parse(ForwardKind::Local, "5432").is_err());
    assert!(parse(ForwardKind::Local, "5432 db").is_err());
    assert!(parse(ForwardKind::Local, "5432 -oProxyCommand=x:1").is_err());
}

const CFG: &str = "Host acme-db\n  HostName db.acme\n  ProxyJump acme-jump\n  LocalForward 5432 db:5432\n  LocalForward *:8080 web:80\n  RemoteForward 9000 localhost:3000\n  DynamicForward 1080\n  LocalForward /tmp/a.sock /tmp/b.sock\n  ExitOnForwardFailure yes\nHost acme-jump\n  HostName jump.acme\n";

#[test]
fn preview_rows_are_plain_and_flag_problems() {
    let hs = hosts(CFG);
    let d = doc_with(&hs);
    let rows = preview(&d, &hs, &[]);
    let by = |line: &str| rows.iter().find(|r| r.line == line).unwrap_or_else(|| panic!("{line}: {rows:#?}"));
    assert_eq!(by("LocalForward 5432 db:5432").description, "Local port 5432 → db:5432 through acme-db");
    assert!(by("LocalForward *:8080 web:80").warning.contains("127.0.0.1"));
    assert!(by("LocalForward *:8080 web:80").importable());
    assert_eq!(by("RemoteForward 9000 localhost:3000").description, "Server port 9000 on acme-db → port 3000 on this computer");
    assert_eq!(by("DynamicForward 1080").description, "SOCKS proxy on local port 1080 through acme-db");
    assert!(by("LocalForward /tmp/a.sock /tmp/b.sock").blocked.contains("Unix socket"));
    assert!(by("RemoteForward 9000 localhost:3000").warning.is_empty(), "loopback target, no warning");
    assert!(by("RemoteForward 9000 localhost:3000").explain.contains("opens on the server each time you connect"));
    assert!(by("LocalForward 5432 db:5432").explain.contains("Opens each time you connect to acme-db"));
    assert_eq!(rows.len(), 5);
}

#[test]
fn import_creates_only_ticked_rows_auto_starting_via_the_host() {
    let hs = hosts(CFG);
    let mut d = doc_with(&hs);
    let rows = preview(&d, &hs, &[]);
    let key = rows.iter().find(|r| r.line == "LocalForward 5432 db:5432").unwrap().key.clone();
    assert_eq!(import(&mut d, &hs, &[]).unwrap(), 0, "nothing ticked, nothing created");
    assert_eq!(import(&mut d, &hs, std::slice::from_ref(&key)).unwrap(), 1);
    let t = &d.tunnels[0];
    assert_eq!(t.name, "acme-db L5432");
    assert!(t.start_with_connection);
    assert_eq!(d.resolve(t.via).unwrap().connection.name, "acme-db");
    // Re-import: no duplicate, and the row says why.
    assert_eq!(import(&mut d, &hs, std::slice::from_ref(&key)).unwrap(), 0);
    assert!(preview(&d, &hs, &[]).iter().find(|r| r.key == key).unwrap().blocked.starts_with("Already a tunnel"));
    // Blocked rows are never created even when their key is sent.
    let sock = rows.iter().find(|r| !r.importable()).unwrap().key.clone();
    assert_eq!(import(&mut d, &hs, &[sock]).unwrap(), 0);
}

#[test]
fn port_clashes_with_existing_and_with_ticked_rows() {
    let text = "Host a\n  HostName a\n  LocalForward 5432 db:5432\nHost b\n  HostName b\n  LocalForward 5432 db2:5432\nHost c\n  HostName c\n  DynamicForward 5432\n";
    let hs = hosts(text);
    let mut d = doc_with(&hs);
    let keys: Vec<String> = preview(&d, &hs, &[]).into_iter().map(|r| r.key).collect();
    // Tick b first: b claims 5432, a and c show the clash.
    let rows = preview(&d, &hs, &[keys[1].clone(), keys[0].clone()]);
    assert!(rows[1].importable());
    assert!(rows[0].blocked.contains("Local port 5432"));
    assert!(rows[2].blocked.contains("Local port 5432"));
    assert_eq!(import(&mut d, &hs, &[keys[1].clone(), keys[0].clone()]).unwrap(), 1);
    assert_eq!(d.tunnels[0].name, "b L5432");
    // Now the saved tunnel holds the port.
    assert!(preview(&d, &hs, &[]).iter().filter(|r| r.host_alias != "b").all(|r| r.blocked.contains("the tunnel “b L5432”")));
}

#[test]
fn wildcard_blocks_give_each_matching_host_the_forward() {
    let hs = hosts("Host acme-web acme-api\n  User ops\nHost acme-*\n  DynamicForward 1080\n");
    let d = doc_with(&hs);
    let rows = preview(&d, &hs, &[]);
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.importable()), "unticked rows do not clash with each other");
}

#[test]
fn rows_need_their_host_in_the_library() {
    let hs = hosts(CFG);
    let mut d = Document::new("t");
    let keys: Vec<String> = preview(&d, &hs, &[]).into_iter().map(|r| r.key).collect();
    assert_eq!(import(&mut d, &hs, &keys).unwrap(), 0, "host not imported, no tunnel");
}

#[test]
fn export_writes_auto_start_tunnels_back() {
    let hs = hosts(CFG);
    let mut d = doc_with(&hs);
    let keys: Vec<String> = preview(&d, &hs, &[]).into_iter().filter(|r| r.importable()).map(|r| r.key).collect();
    assert_eq!(import(&mut d, &hs, &keys).unwrap(), 4);
    let via = d.tunnels[0].via;
    let ondemand = TunnelDef { id: Uuid::new_v4(), name: "manual".into(), via, spec: TunnelSpec::Dynamic { local_port: 2080 }, start_with_connection: false };
    tunneldefs::put(&mut d, ondemand).unwrap();
    let (text, skipped) = crate::sshconfig_export::export_document(&d, &crate::export::Selection::All);
    assert!(skipped.is_empty(), "{skipped:?}");
    for l in ["LocalForward 5432 db:5432", "LocalForward 8080 web:80", "RemoteForward 9000 localhost:3000", "DynamicForward 1080"] {
        assert!(text.contains(l), "{l} missing:\n{text}");
    }
    assert!(!text.contains("2080"), "on-demand tunnel is not written");
    // Round trip: the exported file previews the same forwards, all already tunnels.
    let back = hosts(&text);
    let again = preview(&d, &back, &[]);
    assert_eq!(again.len(), 4);
}

#[test]
fn remote_forward_to_another_machine_warns_and_says_so() {
    let hs = hosts("Host s\n  HostName s\n  RemoteForward 9000 10.0.0.5:22\n");
    let rows = preview(&doc_with(&hs), &hs, &[]);
    assert_eq!(rows[0].description, "Server port 9000 on s → 10.0.0.5:22, reached through this computer");
    assert!(rows[0].warning.contains("Lets the server reach 10.0.0.5:22 on your network"), "{}", rows[0].warning);
    assert!(rows[0].importable(), "allowed, but only with the warning shown");
}

#[test]
fn a_ticked_key_never_imports_a_line_changed_after_the_preview() {
    let before = hosts("Host s\n  HostName s\n  RemoteForward 9000 localhost:3000\n");
    let mut d = doc_with(&before);
    let key = preview(&d, &before, &[])[0].key.clone();
    // The file changes between preview and Import: same host, same position, other target.
    let after = hosts("Host s\n  HostName s\n  RemoteForward 9000 10.0.0.5:22\n");
    assert_eq!(import(&mut d, &after, std::slice::from_ref(&key)).unwrap(), 0, "the changed line is not created");
    assert!(d.tunnels.is_empty());
    // Unchanged lines still import, wherever they moved to in the file.
    let moved = hosts("Host s\n  HostName s\n  LocalForward 1 a:1\n  RemoteForward 9000 localhost:3000\n");
    assert_eq!(import(&mut d, &moved, &[key]).unwrap(), 1);
}

#[test]
fn match_blocks_give_no_rows() {
    let hs = hosts("Host s\n  HostName s\nMatch host s\n  LocalForward 5432 db:5432\n  DynamicForward 1080\n");
    assert!(preview(&doc_with(&hs), &hs, &[]).is_empty());
}

#[test]
fn server_ports_clash_per_connection() {
    let hs = hosts("Host s\n  HostName s\n  RemoteForward 9000 localhost:3000\n  RemoteForward 9000 localhost:3001\n  RemoteForward 9000 localhost:3000\nHost t\n  HostName t\n  RemoteForward 9000 localhost:3000\n");
    let mut d = doc_with(&hs);
    let rows = preview(&d, &hs, &[]);
    assert_eq!(rows.len(), 3, "the repeated identical line is one row");
    let keys: Vec<String> = rows.iter().map(|r| r.key.clone()).collect();
    let ticked = preview(&d, &hs, &keys);
    assert!(ticked[0].importable());
    assert!(ticked[1].blocked.contains("Server port 9000 on s"), "{}", ticked[1].blocked);
    assert!(ticked[2].importable(), "another host's server is another port space");
    assert_eq!(import(&mut d, &hs, &keys).unwrap(), 2);
    assert!(preview(&d, &hs, &[])[1].blocked.contains("the tunnel “s R9000”"));
}

#[test]
fn forward_rows_are_capped() {
    let mut text = String::from("Host s\n  HostName s\n");
    for p in 1..=300 {
        text.push_str(&format!("  LocalForward {p} db:{p}\n"));
    }
    let hs = hosts(&text);
    let rows = preview(&doc_with(&hs), &hs, &[]);
    assert_eq!(rows.len(), MAX_FORWARD_ROWS + 1);
    let last = rows.last().unwrap();
    assert_eq!(last.description, "44 more forward lines not shown");
    assert!(!last.importable());
}

#[test]
fn loopback_in_every_spelling() {
    for b in ["localhost", "127.0.0.1", "127.1.2.3", "::1", "[::1]", "0:0:0:0:0:0:0:1", "::ffff:127.0.0.1"] {
        assert!(is_loopback(b), "{b}");
    }
    for b in ["*", "0.0.0.0", "::", "10.0.0.5", "db"] {
        assert!(!is_loopback(b), "{b}");
    }
}

#[test]
fn export_leaves_out_only_a_tunnel_ssh_config_cannot_hold() {
    let hs = hosts("Host s\n  HostName s\n");
    let mut d = doc_with(&hs);
    let via = crate::sshforwards::tests::first_connection(&d);
    let bad = TunnelDef { id: Uuid::new_v4(), name: "bad".into(), via, spec: TunnelSpec::Local { local_port: 7000, dest_host: "db%h".into(), dest_port: 1 }, start_with_connection: true };
    d.tunnels.push(bad);
    let good = TunnelDef { id: Uuid::new_v4(), name: "good".into(), via, spec: TunnelSpec::Dynamic { local_port: 7001 }, start_with_connection: true };
    d.tunnels.push(good);
    let (text, skipped) = crate::sshconfig_export::export_document(&d, &crate::export::Selection::All);
    assert!(!text.contains("db%h"));
    assert!(text.contains("Host s") && text.contains("DynamicForward 7001"), "the host and its safe tunnel stay:\n{text}");
    assert_eq!(skipped.len(), 1);
    assert!(skipped[0].1.contains("tunnel bad left out"), "{skipped:?}");
}

fn first_connection(d: &Document) -> Uuid {
    *connections_by_identity(d).values().next().unwrap()
}
