//! Real components in the test host: the template and the probe, built for `wasm32-wasip2`.
//!
//! Needs the target: `rustup target add wasm32-wasip2`. The components are built once per run.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bastion_plugin_testhost::bindings::bastion::plugin::types::{Entry, Login};
use bastion_plugin_testhost::bindings::bastion::plugin::events::Input;
use bastion_plugin_testhost::bindings::bastion::plugin::ui::ConfirmKind;
use bastion_plugin_testhost::{Config, FakeConnection, FakeHttpRequest, FakeHttpResponse, FakeServer, LineEcho, Permissions, TestHost, WAIT};

fn build(dir: &str, artifact: &str) -> PathBuf {
    build_with(dir, artifact, &[])
}

fn build_with(dir: &str, artifact: &str, extra: &[&str]) -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(dir);
    let status = Command::new(env!("CARGO"))
        .args(["build", "--release", "--target", "wasm32-wasip2", "--quiet"])
        .args(extra)
        .current_dir(&root)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTFLAGS")
        .status()
        .expect("run cargo");
    assert!(status.success(), "building {dir} for wasm32-wasip2 failed");
    root.join("target/wasm32-wasip2/release").join(artifact)
}

fn template() -> &'static PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| build("../template", "bastion_plugin_template.wasm"))
}

fn probe() -> &'static PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| build("tests/probe", "testhost_probe.wasm"))
}

fn entry(port: u16) -> Entry {
    Entry { id: "e1".into(), name: "Lab".into(), host: "127.0.0.1".into(), port, fields: vec![("greeting".into(), "hi there".into())] }
}

fn template_host() -> (TestHost, Permissions) {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../template/plugin.toml");
    TestHost::load_files(template(), &manifest).expect("load the template")
}

fn probe_host() -> TestHost {
    TestHost::load(&std::fs::read(probe()).unwrap(), &Permissions::all()).expect("load the probe")
}

fn logs(session: &bastion_plugin_testhost::Session) -> Vec<String> {
    session.with_outputs(|o| o.logs.iter().map(|(_, l)| l.clone()).collect())
}

fn wait_log(session: &bastion_plugin_testhost::Session, needle: &str) {
    session
        .wait_for(WAIT, |o| o.logs.iter().any(|(_, l)| l.contains(needle)))
        .unwrap_or_else(|e| panic!("waiting for {needle:?}: {e}; logs {:?}", logs(session)));
}

#[test]
fn template_imports_only_what_its_permissions_allow() {
    let (host, _) = template_host();
    let bastion: Vec<&String> = host.import_names().iter().filter(|n| n.starts_with("bastion:")).collect();
    for name in &bastion {
        assert!(
            ["types", "host", "log", "ui", "events", "net"].iter().any(|i| **name == format!("bastion:plugin/{i}@1.6.0")),
            "unexpected import {name}"
        );
    }
    assert!(bastion.iter().any(|n| n.as_str() == "bastion:plugin/net@1.6.0"));
    for unused in ["credentials", "storage", "clipboard", "files", "http"] {
        let name = format!("bastion:plugin/{unused}@1.6.0");
        assert!(!host.import_names().contains(&name), "{name} is imported but not used");
    }
}

#[test]
fn template_draws_its_view_and_talks_to_the_server() {
    let (host, permissions) = template_host();
    let config = Config { permissions, entry: Some(entry(7)), ..Config::default() };
    let mut s = host.start(config, Box::new(LineEcho)).unwrap();
    let view = s.open_view("echo");
    s.wait_for(WAIT, |o| o.views.get(&view).is_some_and(|n| !n.is_empty())).unwrap();
    assert_eq!(
        s.render(view),
        "#0 stack\n  #1 text-field \"Line to send\" = \"hi there\"\n  #2 button \"Send\"\n  #3 label \"Press Send.\"\n"
    );
    s.type_text(view, "Line to send", "ping").unwrap();
    s.press(view, "Send").unwrap();
    s.wait_for(WAIT, |o| {
        o.views.get(&view).is_some_and(|n| bastion_plugin_testhost::view::find_by_label(n, "PING").is_some())
    })
    .unwrap_or_else(|e| panic!("{e}\n{}", s.render(view)));
    assert!(s.render(view).contains("#3 label \"PING\""));
    s.with_outputs(|o| assert_eq!(o.written, vec![(1, b"ping\n".to_vec())]));
    assert_eq!(s.stop(), Ok(()));
}

#[test]
fn template_shows_a_banner_when_the_server_refuses() {
    let (host, permissions) = template_host();
    let config = Config { permissions, entry: Some(entry(7)), ..Config::default() };
    let mut s = host.start(config, Box::new(bastion_plugin_testhost::NoServer)).unwrap();
    let view = s.open_view("echo");
    s.wait_for(WAIT, |o| o.views.get(&view).is_some_and(|n| !n.is_empty())).unwrap();
    s.command("send", Some(view));
    s.wait_for(WAIT, |o| o.views[&view].iter().any(|n| format!("{:?}", n.component).contains("Banner")))
        .unwrap();
    assert!(s.render(view).contains("#3 banner error \"no server listens on port 7\""), "{}", s.render(view));
    assert_eq!(s.stop(), Ok(()));
}

#[test]
fn an_import_the_manifest_does_not_grant_is_refused() {
    let bytes = std::fs::read(template()).unwrap();
    let e = TestHost::load(&bytes, &Permissions::default()).err().expect("refused");
    assert!(e.contains("bastion:plugin/net@1.6.0") && e.contains("does not grant"), "{e}");
}

#[test]
fn imports_outside_wasi_and_bastion_are_refused() {
    let names = vec!["bastion:plugin/log@1.6.0".to_string(), "evil:host/shell".to_string()];
    let e = bastion_plugin_testhost::check_imports(&names, &Permissions::all()).unwrap_err();
    assert!(e.contains("outside wasi:* and bastion:plugin"), "{e}");
    let names = vec!["bastion:plugin/log@2.0.0".to_string()];
    assert!(bastion_plugin_testhost::check_imports(&names, &Permissions::all()).is_err());
}

#[test]
fn an_endless_loop_is_stopped_by_the_compute_limit() {
    let host = probe_host();
    let config = Config {
        permissions: Permissions::all(),
        compute_limit: Duration::from_millis(500),
        ..Config::default()
    };
    let s = host.start(config, Box::new(LineEcho)).unwrap();
    let started = Instant::now();
    s.command("spin", None);
    let end = s.wait_end(WAIT);
    let took = started.elapsed();
    let e = end.unwrap_err();
    assert!(e.contains("compute limit"), "{e}");
    assert!(took >= Duration::from_millis(450) && took < Duration::from_secs(5), "{took:?}");
}

#[test]
fn waiting_does_not_count_as_compute() {
    let host = probe_host();
    let config = Config { permissions: Permissions::all(), compute_limit: Duration::from_millis(300), ..Config::default() };
    let s = host.start(config, Box::new(LineEcho)).unwrap();
    std::thread::sleep(Duration::from_millis(800));
    s.command("time", None);
    wait_log(&s, "time ok true");
    assert_eq!(s.stop(), Ok(()));
}

#[test]
fn memory_over_the_cap_ends_the_plugin() {
    let host = probe_host();
    let config = Config { permissions: Permissions::all(), memory_limit: 32 * 1024 * 1024, ..Config::default() };
    let s = host.start(config, Box::new(LineEcho)).unwrap();
    s.command("grow", None);
    // The allocation fails inside the plugin, which aborts (panic = "abort").
    assert!(s.wait_end(WAIT).is_err());
}

#[test]
fn stubbed_wasi_ends_the_plugin() {
    for command in ["print", "env"] {
        let s = probe_host().start(Config { permissions: Permissions::all(), ..Config::default() }, Box::new(LineEcho)).unwrap();
        s.command(command, None);
        let e = s.wait_end(WAIT).unwrap_err();
        assert!(e.contains("unknown import") || e.contains("wasi:"), "{command}: {e}");
    }
}

#[test]
fn every_permission_round_trips() {
    let config = Config {
        permissions: Permissions::all(),
        entry: Some(entry(5432)),
        login: Some(Login { user: "alice".into(), secret: "not-a-real-password-1".into() }),
        file_to_open: Some(("in.csv".into(), b"a,b".to_vec())),
        confirm: false,
        ..Config::default()
    };
    let s = probe_host().start(config, Box::new(LineEcho)).unwrap();
    s.command("everything", None);
    wait_log(&s, "confirm");
    assert_eq!(
        logs(&s),
        vec!["user alice", "keys [\"k\"]", "open Ok(\"in.csv\")", "confirm Ok(false)"]
    );
    s.with_outputs(|o| {
        assert_eq!(o.logins_released, 1);
        assert_eq!(o.clipboard, vec!["copied"]);
        assert_eq!(o.saved_files, vec![("out.txt".to_string(), b"data".to_vec())]);
        assert!(matches!(o.confirms[0].0, ConfirmKind::Drop));
    });
    assert_eq!(s.stop(), Ok(()));
}

#[test]
fn the_released_password_is_kept_out_of_logs_storage_and_clipboard() {
    let config = Config {
        permissions: Permissions::all(),
        entry: Some(entry(5432)),
        login: Some(Login { user: "alice".into(), secret: "not-a-real-password-2".into() }),
        ..Config::default()
    };
    let s = probe_host().start(config, Box::new(LineEcho)).unwrap();
    s.command("leak-login", None);
    wait_log(&s, "store");
    let all = logs(&s);
    assert!(!all.iter().any(|l| l.contains("not-a-real-password-2")), "{all:?}");
    assert!(all[0].starts_with("store Err(Failure::Denied"), "{all:?}");
    s.with_outputs(|o| {
        assert_eq!(o.secret_refusals, vec!["log", "storage", "clipboard"]);
        assert!(o.storage.is_empty() && o.clipboard.is_empty());
    });
    assert_eq!(s.stop(), Ok(()));
}

#[test]
fn rows_are_answered_for_open_asks_only() {
    let mut s = probe_host()
        .start(Config { permissions: Permissions::all(), ..Config::default() }, Box::new(LineEcho))
        .unwrap();
    let view = s.open_view("main");
    s.wait_for(WAIT, |o| o.views.get(&view).is_some_and(|n| !n.is_empty())).unwrap();
    assert_eq!(s.render(view), "#0 stack\n  #1 table [\"n\", \"square\"]\n");
    let ask = s.ask_rows(view, 1, 10, 3);
    s.wait_for(WAIT, |o| o.rows.contains_key(&ask)).unwrap();
    s.with_outputs(|o| {
        let (rows, total) = &o.rows[&ask];
        assert_eq!(rows.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(), ["10", "11", "12"]);
        assert_eq!(*total, Some(10_000));
    });
    assert_eq!(s.stop(), Ok(()));
}

/// A server that records what reaches it on each connection.
struct Recorder(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);
struct RecorderConnection(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>, usize);

impl FakeServer for Recorder {
    fn connect(&mut self, _port: u16) -> Result<Box<dyn FakeConnection>, String> {
        let mut log = self.0.lock().unwrap();
        log.push(Vec::new());
        Ok(Box::new(RecorderConnection(self.0.clone(), log.len() - 1)))
    }
}

impl FakeConnection for RecorderConnection {
    fn write(&mut self, data: &[u8]) -> Result<(), String> {
        self.0.lock().unwrap()[self.1].extend_from_slice(data);
        Ok(())
    }
    fn read(&mut self, _max: usize) -> Option<Vec<u8>> {
        None
    }
}

#[test]
fn abort_bytes_go_out_on_a_new_stream_when_the_helper_stops() {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let config = Config { permissions: Permissions::all(), entry: Some(entry(5432)), ..Config::default() };
    let s = probe_host().start(config, Box::new(Recorder(seen.clone()))).unwrap();
    s.command("abort", None);
    wait_log(&s, "abort registered");
    assert_eq!(s.stop(), Ok(()));
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 2, "the plugin's stream and the abort stream");
    assert_eq!(seen[1], b"CANCEL 42\n");
}

#[test]
fn a_bad_view_from_the_host_side_is_refused_and_the_old_one_kept() {
    use bastion_plugin_testhost::bindings::bastion::plugin::ui::{Component, Node};
    let nodes = vec![
        Node { id: 0, parent: None, component: Component::Label("leaf".into()) },
        Node { id: 1, parent: Some(0), component: Component::Label("child".into()) },
    ];
    let e = bastion_plugin_testhost::view::check(&nodes).unwrap_err();
    assert!(e.contains("cannot hold children"), "{e}");
    let rendered = bastion_plugin_testhost::view::render(&[
        Node { id: 0, parent: None, component: Component::Label("bell\u{7}".into()) },
    ]);
    assert_eq!(rendered, "#0 label \"bell\\u{7}\"\n");
}

// ---- the Proxmox VE plugin (PLUG-PVE-01) against a mock Proxmox API over `http` ----

struct MockProxmox;

impl FakeServer for MockProxmox {
    fn connect(&mut self, _port: u16) -> Result<Box<dyn FakeConnection>, String> {
        Err("the Proxmox plugin opens no streams".into())
    }

    fn http(&mut self, req: &FakeHttpRequest) -> Result<FakeHttpResponse, String> {
        let ok = |body: &str| Ok(FakeHttpResponse { status: 200, headers: vec![("Content-Type".into(), "application/json".into())], body: body.as_bytes().to_vec() });
        if req.login.is_none() {
            return Ok(FakeHttpResponse { status: 401, headers: vec![], body: b"no ticket".to_vec() });
        }
        match (req.method.as_str(), req.target.as_str()) {
            ("GET", "/api2/json/version") => ok(r#"{"data":{"release":"8.3","version":"8.3.0"}}"#),
            ("GET", "/api2/json/nodes/pve/qemu/301/agent/network-get-interfaces") => ok(r#"{"data":{"result":[{"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1"}]},{"name":"ens18","ip-addresses":[{"ip-address":"192.0.2.31"}]}]}}"#),
            ("GET", "/api2/json/nodes") => ok(r#"{"data":[{"node":"pve","status":"online","cpu":0.2,"maxcpu":4,"mem":1073741824,"maxmem":4294967296}]}"#),
            ("GET", "/api2/json/cluster/resources?type=vm") => ok(r#"{"data":[{"vmid":301,"name":"lab-web","node":"pve","type":"qemu","status":"running","cpu":0.1,"mem":1,"maxmem":2},{"vmid":302,"name":"lab-ct","node":"pve","type":"lxc","status":"stopped"}]}"#),
            _ => Ok(FakeHttpResponse { status: 501, headers: vec![], body: vec![] }),
        }
    }
}

fn proxmox_host() -> (TestHost, Permissions) {
    static P: OnceLock<PathBuf> = OnceLock::new();
    let wasm = P.get_or_init(|| build_with("../official/proxmox", "bastion_plugin_proxmox.wasm", &["--features", "plugin"]));
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../official/proxmox/plugin.toml");
    TestHost::load_files(wasm, &manifest).expect("load the Proxmox plugin")
}

#[test]
fn proxmox_imports_http_and_nothing_that_reaches_the_network_otherwise() {
    let (host, permissions) = proxmox_host();
    assert!(permissions.http && !permissions.network && !permissions.credentials);
    let bastion: Vec<&String> = host.import_names().iter().filter(|n| n.starts_with("bastion:")).collect();
    assert!(bastion.iter().any(|n| n.as_str() == "bastion:plugin/http@1.6.0"));
    assert!(bastion.iter().any(|n| n.as_str() == "bastion:plugin/open@1.6.0"), "asks the app to open a guest");
    for absent in ["net", "credentials", "storage", "clipboard", "files"] {
        assert!(!bastion.iter().any(|n| n.as_str() == format!("bastion:plugin/{absent}@1.6.0")), "{absent}");
    }
}

#[test]
fn proxmox_asks_to_open_ssh_to_the_selected_guest_at_the_agents_address() {
    let (host, permissions) = proxmox_host();
    let config = Config {
        permissions,
        entry: Some(Entry { id: "e1".into(), name: "Lab PVE".into(), host: "127.0.0.1".into(), port: 8006, fields: vec![] }),
        login: Some(Login { user: "bastion-plugin@pve!t".into(), secret: "not-a-real-secret".into() }),
        ..Config::default()
    };
    let mut s = host.start(config, Box::new(MockProxmox)).unwrap();
    let view = s.open_view("pve");
    s.wait_for(WAIT, |o| o.views.get(&view).is_some_and(|n| n.iter().any(|n| format!("{:?}", n.component).contains("of 2 running")))).unwrap_or_else(|e| panic!("{e}: {}", s.render(view)));
    s.input(view, 9, Input::Selected(vec!["pve/301".into()]));
    s.input(view, 3, Input::Pressed);
    s.wait_for(WAIT, |o| !o.opens.is_empty()).unwrap_or_else(|e| panic!("{e}: {}", s.render(view)));
    let opens = s.with_outputs(|o| o.opens.clone());
    assert_eq!(opens.len(), 1);
    assert_eq!(opens[0].host, "192.0.2.31");
    assert_eq!(opens[0].label, "lab-web (pve/301)");
    let agent = s.with_outputs(|o| o.http_requests.iter().find(|r| r.target.contains("/agent/")).cloned()).expect("address read");
    assert!(agent.method == "GET" && agent.login.is_some());
    assert_eq!(s.stop(), Ok(()));
}

#[test]
fn proxmox_lists_guests_from_the_mock_api_with_the_login_added_by_the_host() {
    let (host, permissions) = proxmox_host();
    let config = Config {
        permissions,
        entry: Some(Entry { id: "e1".into(), name: "Lab PVE".into(), host: "127.0.0.1".into(), port: 8006, fields: vec![] }),
        login: Some(Login { user: "bastion-plugin@pve!t".into(), secret: "not-a-real-secret".into() }),
        ..Config::default()
    };
    let mut s = host.start(config, Box::new(MockProxmox)).unwrap();
    let view = s.open_view("pve");
    s.wait_for(WAIT, |o| o.views.get(&view).is_some_and(|n| n.iter().any(|n| format!("{:?}", n.component).contains("of 2 running")))).unwrap_or_else(|e| panic!("{e}: {}", s.render(view)));
    let render = s.render(view);
    assert!(render.contains("Proxmox VE 8.3 · 1 of 2 running"), "{render}");
    assert!(render.contains("stat \"CPU\" \"20%\" \"4 cores\" 20%"), "{render}");
    let sent = s.with_outputs(|o| o.http_requests.clone());
    assert_eq!(sent.len(), 3, "version, nodes, guests");
    for r in &sent {
        assert_eq!((r.method.as_str(), r.port), ("GET", 8006));
        assert!(r.login.is_some(), "the host added the login");
        assert!(r.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("authorization")));
    }
    assert_eq!(s.stop(), Ok(()));
}

struct MockVcenter;

impl FakeServer for MockVcenter {
    fn connect(&mut self, _port: u16) -> Result<Box<dyn FakeConnection>, String> {
        Err("the VMware plugin opens no streams".into())
    }

    fn http(&mut self, req: &FakeHttpRequest) -> Result<FakeHttpResponse, String> {
        let ok = |body: &str| Ok(FakeHttpResponse { status: 200, headers: vec![("Content-Type".into(), "application/json".into())], body: body.as_bytes().to_vec() });
        if req.login.is_none() {
            return Ok(FakeHttpResponse { status: 401, headers: vec![], body: br#"{"error_type":"UNAUTHENTICATED","messages":[]}"#.to_vec() });
        }
        match (req.method.as_str(), req.target.as_str()) {
            ("GET", "/api/vcenter/host") => ok(r#"[{"host":"host-21","name":"esx1","connection_state":"CONNECTED"},{"host":"host-22","name":"esx2","connection_state":"CONNECTED"}]"#),
            ("GET", "/api/vcenter/vm") => ok(r#"[{"vm":"vm-42","name":"lab-web","power_state":"POWERED_ON","cpu_count":2,"memory_size_MiB":2048},{"vm":"vm-43","name":"lab-dns","power_state":"POWERED_OFF"},{"vm":"vm-44","name":"lab-db","power_state":"SUSPENDED"}]"#),
            _ => Ok(FakeHttpResponse { status: 404, headers: vec![], body: vec![] }),
        }
    }
}

fn vmware_host() -> (TestHost, Permissions) {
    static P: OnceLock<PathBuf> = OnceLock::new();
    let wasm = P.get_or_init(|| build_with("../official/vmware", "bastion_plugin_vmware.wasm", &["--features", "plugin"]));
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../official/vmware/plugin.toml");
    TestHost::load_files(wasm, &manifest).expect("load the VMware plugin")
}

#[test]
fn vmware_imports_http_and_nothing_that_reaches_the_network_otherwise() {
    let (host, permissions) = vmware_host();
    assert!(permissions.http && !permissions.network && !permissions.credentials);
    let bastion: Vec<&String> = host.import_names().iter().filter(|n| n.starts_with("bastion:")).collect();
    assert!(bastion.iter().any(|n| n.as_str() == "bastion:plugin/http@1.6.0"));
    for absent in ["net", "credentials", "storage", "clipboard", "files"] {
        assert!(!bastion.iter().any(|n| n.as_str() == format!("bastion:plugin/{absent}@1.6.0")), "{absent}");
    }
}

#[test]
fn vmware_lists_vms_from_the_mock_api_with_the_login_added_by_the_host() {
    let (host, permissions) = vmware_host();
    let config = Config {
        permissions,
        entry: Some(Entry { id: "e1".into(), name: "Lab vCenter".into(), host: "127.0.0.1".into(), port: 443, fields: vec![] }),
        login: Some(Login { user: "readonly@vsphere.local".into(), secret: "not-a-real-secret".into() }),
        ..Config::default()
    };
    let mut s = host.start(config, Box::new(MockVcenter)).unwrap();
    let view = s.open_view("vcenter");
    s.wait_for(WAIT, |o| o.views.get(&view).is_some_and(|n| n.iter().any(|n| format!("{:?}", n.component).contains("of 3 VMs on")))).unwrap_or_else(|e| panic!("{e}: {}", s.render(view)));
    let render = s.render(view);
    assert!(render.contains("vCenter · 1 of 3 VMs on"), "{render}");
    assert!(render.contains("esx2"), "{render}");
    let sent = s.with_outputs(|o| o.http_requests.clone());
    assert_eq!(sent.len(), 2);
    for r in &sent {
        assert_eq!((r.method.as_str(), r.port), ("GET", 443));
        assert!(r.login.is_some(), "the host added the login");
        assert!(r.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("authorization")));
    }
    assert_eq!(s.stop(), Ok(()));
}

#[test]
fn open_needs_a_user_action_once_and_the_answer_comes_back() {
    let entry = Entry { id: "e1".into(), name: "Lab".into(), host: "pve.lab".into(), port: 8006, fields: vec![] };
    let config = Config { permissions: Permissions::all(), entry: Some(entry.clone()), open_answer: false, ..Config::default() };
    let s = probe_host().start(config, Box::new(LineEcho)).unwrap();
    s.command("open", None);
    wait_log(&s, "open Ok(false) then refused");
    let opens = s.with_outputs(|o| o.opens.clone());
    assert_eq!(opens.len(), 1, "one sheet for one user action");
    assert_eq!((opens[0].host.as_str(), opens[0].label.as_str(), opens[0].port, opens[0].via_entry_route), ("10.0.0.5", "lab-web", None, true));
    assert_eq!(s.stop(), Ok(()));

    // Without the protocol in the manifest, nothing reaches the user.
    let only_rdp = Permissions { open_ssh: false, ..Permissions::all() };
    let s = probe_host().start(Config { permissions: only_rdp, entry: Some(entry), ..Config::default() }, Box::new(LineEcho)).unwrap();
    s.command("open", None);
    wait_log(&s, "open Err(");
    assert!(s.with_outputs(|o| o.opens.is_empty()));
    assert_eq!(s.stop(), Ok(()));
}

/// A Docker host that answers the Docker plugin's templates with recorded output.
struct MockDocker;

impl FakeServer for MockDocker {
    fn connect(&mut self, _port: u16) -> Result<Box<dyn bastion_plugin_testhost::FakeConnection>, String> {
        Err("no streams".into())
    }
    fn exec(&mut self, template: &str, _args: &[(String, String)]) -> Result<bastion_plugin_testhost::FakeExecOutput, String> {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../official/docker/tests/fixtures");
        let text = match template {
            "version" => "\"27.3.1\"\n".to_string(),
            "ps" | "stats" | "images" | "volumes" | "networks" => std::fs::read_to_string(dir.join(format!("{template}.jsonl"))).unwrap(),
            _ => String::new(),
        };
        Ok(bastion_plugin_testhost::FakeExecOutput { exit: Some(0), stdout: text.into_bytes(), stderr: vec![] })
    }
}

fn docker_host() -> (TestHost, Permissions) {
    static P: OnceLock<PathBuf> = OnceLock::new();
    let wasm = P.get_or_init(|| build_with("../official/docker", "bastion_plugin_docker.wasm", &["--features", "plugin"]));
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../official/docker/plugin.toml");
    TestHost::load_files(wasm, &manifest).expect("load the Docker plugin")
}

#[test]
fn docker_imports_exec_and_nothing_that_reaches_the_network() {
    let (host, permissions) = docker_host();
    assert!(permissions.exec && !permissions.network && !permissions.http && !permissions.credentials);
    let bastion: Vec<&String> = host.import_names().iter().filter(|n| n.starts_with("bastion:")).collect();
    assert!(bastion.iter().any(|n| n.as_str() == "bastion:plugin/exec@1.5.0"));
    for absent in ["net", "http", "credentials", "storage", "clipboard", "files", "open"] {
        assert!(!bastion.iter().any(|n| n.as_str() == format!("bastion:plugin/{absent}@1.5.0")), "{absent}");
    }
}

#[test]
fn docker_shows_the_hosts_containers_from_declared_commands() {
    let (host, permissions) = docker_host();
    let config = Config {
        permissions,
        entry: Some(Entry { id: "e1".into(), name: "docker1".into(), host: "docker1.lab".into(), port: 22, fields: vec![] }),
        ..Config::default()
    };
    let mut s = host.start(config, Box::new(MockDocker)).unwrap();
    let view = s.open_view("host");
    s.wait_for(WAIT, |o| o.views.get(&view).is_some_and(|n| n.iter().any(|n| format!("{:?}", n.component).contains("1 of 2 containers running")))).unwrap_or_else(|e| panic!("{e}: {}", s.render(view)));
    let execs = s.with_outputs(|o| o.execs.iter().map(|(t, _)| t.clone()).collect::<Vec<_>>());
    assert_eq!(execs, ["version", "ps", "stats", "images", "volumes", "networks"]);
    assert_eq!(s.stop(), Ok(()));
}

/// The Kubernetes plugin's recorded API answers (`plugins/official/kubernetes/tests/fixtures`).
struct MockKubernetes;

impl FakeServer for MockKubernetes {
    fn connect(&mut self, _port: u16) -> Result<Box<dyn FakeConnection>, String> {
        Err("the Kubernetes plugin opens no streams".into())
    }

    fn http(&mut self, req: &FakeHttpRequest) -> Result<FakeHttpResponse, String> {
        let file = |name: &str| std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../official/kubernetes/tests/fixtures").join(name)).unwrap();
        let answer = |status: u16, body: Vec<u8>| Ok(FakeHttpResponse { status, headers: vec![("Content-Type".into(), "application/json".into())], body });
        if req.login.is_none() {
            return answer(401, file("unauthorized.json"));
        }
        match (req.method.as_str(), req.target.as_str()) {
            ("GET", "/api/v1/namespaces") => answer(200, file("namespaces.json")),
            ("GET", "/api/v1/pods") => answer(200, file("pods.json")),
            ("GET", "/apis/apps/v1/deployments") => answer(200, file("deployments.json")),
            ("GET", "/api/v1/services") => answer(200, file("services.json")),
            ("GET", "/api/v1/nodes") => answer(200, file("nodes.json")),
            ("GET", "/apis/metrics.k8s.io/v1beta1/pods") => answer(200, file("metrics.json")),
            _ => answer(404, vec![]),
        }
    }
}

fn kubernetes_host() -> (TestHost, Permissions) {
    static P: OnceLock<PathBuf> = OnceLock::new();
    let wasm = P.get_or_init(|| build_with("../official/kubernetes", "bastion_plugin_kubernetes.wasm", &["--features", "plugin"]));
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../official/kubernetes/plugin.toml");
    TestHost::load_files(wasm, &manifest).expect("load the Kubernetes plugin")
}

#[test]
fn kubernetes_imports_http_only_and_reads_the_cluster_with_the_host_login() {
    let (host, permissions) = kubernetes_host();
    assert!(permissions.http && !permissions.network && !permissions.credentials);
    let bastion: Vec<&String> = host.import_names().iter().filter(|n| n.starts_with("bastion:")).collect();
    for absent in ["net", "credentials", "storage", "clipboard", "files", "open"] {
        assert!(!bastion.iter().any(|n| n.starts_with(&format!("bastion:plugin/{absent}@"))), "{absent}");
    }
    let config = Config {
        permissions,
        entry: Some(Entry { id: "e1".into(), name: "lab-k3s".into(), host: "127.0.0.1".into(), port: 6443, fields: vec![] }),
        login: Some(Login { user: String::new(), secret: "not-a-real-token".into() }),
        ..Config::default()
    };
    let mut s = host.start(config, Box::new(MockKubernetes)).unwrap();
    let view = s.open_view("k8s");
    s.wait_for(WAIT, |o| o.views.get(&view).is_some_and(|n| n.iter().any(|n| format!("{:?}", n.component).contains("pods · 2 nodes")))).unwrap_or_else(|e| panic!("{e}: {}", s.render(view)));
    let render = s.render(view);
    assert!(render.contains("3/5 pods · 2 nodes"), "{render}");
    let sent = s.with_outputs(|o| o.http_requests.clone());
    assert_eq!(sent.len(), 6, "namespaces, pods, deployments, services, nodes, metrics");
    for r in &sent {
        assert_eq!((r.method.as_str(), r.port), ("GET", 6443));
        assert!(r.login.is_some(), "the host added the token");
        assert!(r.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("authorization")));
    }
    assert_eq!(s.stop(), Ok(()));
}
