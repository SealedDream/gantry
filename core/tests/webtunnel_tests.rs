//! Web tabs through a tunnel: the route each tunnel kind gives, per-tunnel data folders, port
//! checks, copyable settings and the external-browser fallback arguments.
use std::net::TcpListener;

use bastion_core::model::{Connection, Document, Node, Protocol};
use bastion_core::tunneldefs::{self, TunnelDef, TunnelSpec};
use bastion_core::webtunnel::{self, BrowserFamily, WebRoute};
use uuid::Uuid;

struct Fixture {
    doc: Document,
    web: Uuid,
    socks: Uuid,
    local: Uuid,
    remote: Uuid,
}

fn fixture() -> Fixture {
    let mut doc = Document::new("t");
    let ssh = Connection::new("jump", Protocol::Ssh, "127.0.0.1");
    let web = Connection::new("intranet", Protocol::Web, "https://intranet.corp");
    let (s, w) = (ssh.id, web.id);
    doc.insert(None, Node::Connection(ssh)).unwrap();
    doc.insert(None, Node::Connection(web)).unwrap();
    let mut put = |name: &str, spec| tunneldefs::put(&mut doc, TunnelDef { id: Uuid::new_v4(), name: name.into(), via: s, spec, start_with_connection: false }).unwrap();
    let socks = put("Corp SOCKS", TunnelSpec::Dynamic { local_port: 18080 });
    let local = put("Intranet", TunnelSpec::Local { local_port: 18443, dest_host: "intranet.corp".into(), dest_port: 443 });
    let remote = put("Back", TunnelSpec::Remote { remote_port: 9000, local_host: "127.0.0.1".into(), local_port: 9000 });
    Fixture { doc, web: w, socks, local, remote }
}

#[test]
fn socks_tunnel_gives_the_web_tab_a_proxy_and_its_own_data_folder() {
    let mut f = fixture();
    let root = tempfile::tempdir().unwrap();
    assert_eq!(webtunnel::plan_for(&f.doc, f.web, root.path()).unwrap(), None, "direct by default");
    webtunnel::set_web_tunnel(&mut f.doc, f.web, Some(f.socks)).unwrap();
    let plan = webtunnel::plan_for(&f.doc, f.web, root.path()).unwrap().unwrap();
    assert_eq!(plan.route, WebRoute::Proxy { proxy_url: "socks5://127.0.0.1:18080".into() });
    assert_eq!(plan.tunnel_name, "Corp SOCKS");
    assert!(plan.data_dir.starts_with(root.path().join("web-tunnels")));

    // Another tunnel gets another folder: cookies never mix.
    webtunnel::set_web_tunnel(&mut f.doc, f.web, Some(f.local)).unwrap();
    let other = webtunnel::plan_for(&f.doc, f.web, root.path()).unwrap().unwrap();
    assert_eq!(other.route, WebRoute::Forward { address: "127.0.0.1:18443".into() });
    assert_ne!(other.data_dir, plan.data_dir);

    webtunnel::set_web_tunnel(&mut f.doc, f.web, None).unwrap();
    assert_eq!(webtunnel::plan_for(&f.doc, f.web, root.path()).unwrap(), None);
}

#[test]
fn wrong_kinds_and_deleted_tunnels_are_refused_never_silently_direct() {
    let mut f = fixture();
    let root = tempfile::tempdir().unwrap();
    assert!(webtunnel::set_web_tunnel(&mut f.doc, f.web, Some(f.remote)).is_err(), "-R can't carry a web tab");
    assert!(webtunnel::set_web_tunnel(&mut f.doc, f.web, Some(Uuid::new_v4())).is_err(), "unknown tunnel");
    let ssh = f.doc.tunnels[0].via;
    assert!(webtunnel::set_web_tunnel(&mut f.doc, ssh, Some(f.socks)).is_err(), "only web connections");

    webtunnel::set_web_tunnel(&mut f.doc, f.web, Some(f.socks)).unwrap();
    tunneldefs::remove(&mut f.doc, f.socks).unwrap();
    let e = webtunnel::plan_for(&f.doc, f.web, root.path()).unwrap_err();
    assert!(e.to_string().contains("deleted"), "{e}");

    f.doc.set_metadata(f.web, webtunnel::WEB_TUNNEL_KEY, Some("../../etc".into())).unwrap();
    assert!(webtunnel::plan_for(&f.doc, f.web, root.path()).is_err());
}

#[test]
fn data_folders_are_owner_only_cleared_and_pruned() {
    let f = fixture();
    let root = tempfile::tempdir().unwrap();
    let dir = webtunnel::ensure_data_dir(root.path(), f.socks).unwrap();
    std::fs::write(dir.join("Cookies"), "x").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    }
    webtunnel::clear_data(root.path(), f.socks).unwrap();
    assert!(!dir.exists());
    webtunnel::clear_data(root.path(), f.socks).unwrap();

    // A deleted tunnel's folder goes; live ones, foreign names and a planted link's target stay.
    let live = webtunnel::ensure_data_dir(root.path(), f.local).unwrap();
    let gone = webtunnel::ensure_data_dir(root.path(), Uuid::new_v4()).unwrap();
    let foreign = root.path().join("web-tunnels/keep-me");
    std::fs::create_dir_all(&foreign).unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("precious"), "x").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), webtunnel::data_dir(root.path(), Uuid::new_v4())).unwrap();
    let removed = webtunnel::prune_data(root.path(), &f.doc).unwrap();
    assert_eq!(removed, if cfg!(unix) { 2 } else { 1 });
    assert!(live.exists() && !gone.exists() && foreign.exists());
    assert!(outside.path().join("precious").exists());
}

#[test]
fn port_checks_find_a_free_port() {
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = taken.local_addr().unwrap().port();
    assert!(!webtunnel::port_free(p));
    let next = webtunnel::next_free_port(p).unwrap();
    assert!(next > p && webtunnel::port_free(next));
    assert!(!webtunnel::port_free(0));
    drop(taken);
}

#[test]
fn copyable_settings_resolve_names_through_the_proxy() {
    let f = fixture();
    let socks = f.doc.tunnels.iter().find(|t| t.id == f.socks).unwrap();
    let s = webtunnel::proxy_settings(socks).unwrap();
    assert_eq!(s.url, "socks5h://127.0.0.1:18080");
    assert!(s.pac.contains("SOCKS5 127.0.0.1:18080"));
    assert!(webtunnel::proxy_settings(f.doc.tunnels.iter().find(|t| t.id == f.local).unwrap()).is_none());
}

#[test]
fn external_browser_uses_a_separate_profile_and_remote_dns() {
    let dir = std::path::Path::new("/tmp/bastion profile");
    let chrome = webtunnel::browser_args(BrowserFamily::Chromium, 18080, dir);
    assert!(chrome.contains(&"--user-data-dir=/tmp/bastion profile".to_string()), "one argument, spaces kept");
    assert!(chrome.contains(&"--proxy-server=socks5://127.0.0.1:18080".to_string()));
    assert!(chrome.iter().any(|a| a.starts_with("--host-resolver-rules=MAP * ~NOTFOUND")));
    let ff = webtunnel::browser_args(BrowserFamily::Firefox, 18080, dir);
    assert_eq!(ff[..2], ["-profile".to_string(), "/tmp/bastion profile".to_string()]);
    let js = webtunnel::firefox_user_js(18080);
    assert!(js.contains("socks_remote_dns\", true") && js.contains("socks_port\", 18080") && js.contains("trr.mode\", 5"));
}

#[test]
fn tunnels_from_the_per_user_registry_work_the_same() {
    use bastion_core::tunnel_registry::{TunnelDef as RegDef, TunnelSpec as RegSpec};
    use bastion_core::webtunnel::Candidate;
    let mut f = fixture();
    let ssh = f.doc.tunnels[0].via;
    let socks = RegDef::new("Reg SOCKS", ssh, RegSpec::Socks { bind_port: 19080 }).unwrap();
    let back = RegDef::new("Reg back", ssh, RegSpec::Remote { remote_port: 9001, local_host: "127.0.0.1".into(), local_port: 9001 }).unwrap();
    let cands: Vec<Candidate> = [&socks, &back].into_iter().map(Candidate::from).collect();
    let root = tempfile::tempdir().unwrap();
    assert!(webtunnel::set_web_tunnel_from(&mut f.doc, f.web, Some(back.id), &cands).is_err());
    webtunnel::set_web_tunnel_from(&mut f.doc, f.web, Some(socks.id), &cands).unwrap();
    let p = webtunnel::plan_from(&f.doc, f.web, root.path(), &cands).unwrap().unwrap();
    assert_eq!(p.route, WebRoute::Proxy { proxy_url: "socks5://127.0.0.1:19080".into() });
    // The library's own store doesn't know that id: an error, not a direct connection.
    assert!(webtunnel::plan_for(&f.doc, f.web, root.path()).is_err());
    assert_eq!(cands[0].socks_port.map(webtunnel::socks_settings).unwrap().url, "socks5h://127.0.0.1:19080");
}
