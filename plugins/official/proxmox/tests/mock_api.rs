//! The client against a mock Proxmox API: canned answers shaped like Proxmox VE 8 and 9.

use bastion_plugin_proxmox::api::*;
use bastion_plugin_proxmox::model::*;
use bastion_plugin_proxmox::{Method, Request, Response, Transport};
use std::collections::HashMap;

#[derive(Default)]
struct Mock {
    routes: HashMap<(Method, String), (u16, String)>,
    sent: Vec<Request>,
}

impl Mock {
    fn on(mut self, m: Method, target: &str, status: u16, body: &str) -> Self {
        self.routes.insert((m, target.to_string()), (status, body.to_string()));
        self
    }
}

impl Transport for Mock {
    fn send(&mut self, req: &Request) -> Result<Response, String> {
        self.sent.push(req.clone());
        match self.routes.get(&(req.method, req.target.clone())) {
            Some((s, b)) => Ok(Response { status: *s, body: b.clone().into_bytes() }),
            None => Ok(Response { status: 501, body: b"Method not implemented".to_vec() }),
        }
    }
}

const RESOURCES: &str = r#"{"data":[
 {"id":"qemu/201","vmid":201,"name":"web","node":"pve1","type":"qemu","status":"running","qmpstatus":"running","cpu":0.0123,"maxcpu":2,"mem":1073741824,"maxmem":2147483648,"disk":0,"maxdisk":34359738368,"uptime":3600,"template":0},
 {"id":"lxc/202","vmid":"202","name":"dns","node":"pve2","type":"lxc","status":"stopped","maxmem":536870912},
 {"id":"qemu/9000","vmid":9000,"name":"tmpl","node":"pve1","type":"qemu","status":"stopped","template":1},
 {"id":"qemu/203","vmid":203,"name":"evil","node":"pve1/../../access","type":"qemu","status":"running"},
 {"id":"storage/pve1/local","node":"pve1","type":"storage","vmid":0}
]}"#;

#[test]
fn guests_parse_and_drop_bad_rows() {
    let mock = Mock::default().on(Method::Get, "/api2/json/cluster/resources?type=vm", 200, RESOURCES);
    let mut c = Client::new(mock, Access::ReadOnly);
    let g = c.guests().unwrap();
    // The storage row has an unknown type and the row with a hostile node name is dropped.
    assert_eq!(g.iter().map(|g| g.vmid).collect::<Vec<_>>(), vec![201, 202, 9000]);
    assert_eq!(g[0].power(), PowerState::Running);
    assert_eq!(g[0].maxmem, 2147483648);
    assert_eq!(g[1].kind, Some(GuestKind::Lxc));
    assert_eq!(g[1].vmid, 202, "vmid given as a string");
    assert_eq!(g[1].power(), PowerState::Stopped);
    assert!(g[2].is_template());
}

#[test]
fn nodes_and_version() {
    let mock = Mock::default()
        .on(Method::Get, "/api2/json/nodes", 200, r#"{"data":[{"node":"pve1","status":"online","cpu":0.05,"maxcpu":16,"mem":"1000","maxmem":64000000000,"uptime":99},{"node":"pve2","status":"offline"}]}"#)
        .on(Method::Get, "/api2/json/version", 200, r#"{"data":{"version":"9.0.3","release":"9.0","repoid":"abc"}}"#);
    let mut c = Client::new(mock, Access::ReadOnly);
    let n = c.nodes().unwrap();
    assert_eq!(n.len(), 2);
    assert_eq!(n[0].mem, 1000);
    assert_eq!(n[1].maxcpu, 0);
    assert_eq!(c.version().unwrap()["release"], "9.0");
}

#[test]
fn paused_vm_status() {
    let mock = Mock::default().on(Method::Get, "/api2/json/nodes/pve1/qemu/201/status/current", 200,
        r#"{"data":{"vmid":201,"name":"web","status":"running","qmpstatus":"paused","cpus":2}}"#);
    let mut c = Client::new(mock, Access::ReadOnly);
    let g = c.guest_status("pve1", GuestKind::Qemu, 201).unwrap();
    assert_eq!(g.power(), PowerState::Paused);
    assert_eq!(g.node, "pve1");
    assert_eq!(g.cpus, 2);
}

#[test]
fn snapshots_hide_current() {
    let mock = Mock::default().on(Method::Get, "/api2/json/nodes/pve1/qemu/201/snapshot", 200,
        r#"{"data":[{"name":"before-upgrade","description":"x","snaptime":1700000000,"vmstate":0},{"name":"current","parent":"before-upgrade","running":1}]}"#);
    let mut c = Client::new(mock, Access::ReadOnly);
    let s = c.snapshots("pve1", GuestKind::Qemu, 201).unwrap();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].name, "before-upgrade");
    assert_eq!(s[0].snaptime, 1700000000);
}

#[test]
fn agent_address_prefers_ipv4_and_skips_local() {
    let body = r#"{"data":{"result":[
      {"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1","ip-address-type":"ipv4"}]},
      {"name":"docker0","ip-addresses":[{"ip-address":"172.17.0.1"}]},
      {"name":"eth0","ip-addresses":[{"ip-address":"fe80::1"},{"ip-address":"2001:db8::5"},{"ip-address":"169.254.3.3"},{"ip-address":"192.0.2.10"}]}
    ]}}"#;
    let mock = Mock::default().on(Method::Get, "/api2/json/nodes/pve1/qemu/201/agent/network-get-interfaces", 200, body);
    let mut c = Client::new(mock, Access::ReadOnly);
    assert_eq!(c.address("pve1", GuestKind::Qemu, 201).unwrap(), Some("192.0.2.10".parse().unwrap()));
}

#[test]
fn agent_address_falls_back_to_ipv6_and_none() {
    let six = [AgentInterface { name: "eth0".into(), ip_addresses: vec![AgentAddress { ip_address: "fe80::2".into() }, AgentAddress { ip_address: "2001:db8::7".into() }] }];
    assert_eq!(pick_address(&six), Some("2001:db8::7".parse().unwrap()));
    let none = [AgentInterface { name: "eth0".into(), ip_addresses: vec![AgentAddress { ip_address: "not an ip".into() }, AgentAddress { ip_address: "0.0.0.0".into() }] }];
    assert_eq!(pick_address(&none), None);
}

#[test]
fn lxc_address_from_cidr() {
    let mock = Mock::default().on(Method::Get, "/api2/json/nodes/pve2/lxc/202/interfaces", 200,
        r#"{"data":[{"name":"lo","inet":"127.0.0.1/8"},{"name":"eth0","inet":"198.51.100.4/24","inet6":"fe80::3/64","hwaddr":"x"}]}"#);
    let mut c = Client::new(mock, Access::ReadOnly);
    assert_eq!(c.address("pve2", GuestKind::Lxc, 202).unwrap(), Some("198.51.100.4".parse().unwrap()));
}

#[test]
fn agent_not_running_is_a_status_error() {
    let mock = Mock::default().on(Method::Get, "/api2/json/nodes/pve1/qemu/201/agent/network-get-interfaces", 500, "QEMU guest agent is not running\u{1b}[0m");
    let mut c = Client::new(mock, Access::ReadOnly);
    match c.address("pve1", GuestKind::Qemu, 201) {
        Err(Error::Status(500, t)) => { assert!(t.contains("not running")); assert!(!t.contains('\u{1b}')); }
        other => panic!("{other:?}"),
    }
}

#[test]
fn read_only_client_refuses_every_change_and_sends_nothing() {
    let mut c = Client::new(Mock::default(), Access::ReadOnly);
    for a in [Power::Start, Power::Shutdown, Power::Reboot, Power::Stop, Power::Suspend, Power::Resume] {
        assert!(matches!(c.power("pve1", GuestKind::Qemu, 201, a), Err(Error::Refused(_))));
    }
    assert!(matches!(c.take_snapshot("pve1", GuestKind::Qemu, 201, "s1", ""), Err(Error::Refused(_))));
    assert!(matches!(c.rollback("pve1", GuestKind::Qemu, 201, "s1"), Err(Error::Refused(_))));
    assert!(matches!(c.delete_snapshot("pve1", GuestKind::Qemu, 201, "s1"), Err(Error::Refused(_))));
    assert!(c.transport().sent.is_empty());
}

#[test]
fn changes_build_the_right_requests() {
    let upid = r#"{"data":"UPID:pve1:00001234:00ABCDEF:65000000:qmstart:201:bastion-plugin@pve!t:"}"#;
    let mock = Mock::default()
        .on(Method::Post, "/api2/json/nodes/pve1/qemu/201/status/start", 200, upid)
        .on(Method::Post, "/api2/json/nodes/pve1/qemu/201/status/stop", 200, upid)
        .on(Method::Post, "/api2/json/nodes/pve1/qemu/201/snapshot", 200, upid)
        .on(Method::Post, "/api2/json/nodes/pve1/qemu/201/snapshot/s1/rollback", 200, upid)
        .on(Method::Delete, "/api2/json/nodes/pve1/qemu/201/snapshot/s1", 200, upid);
    let mut c = Client::new(mock, Access::MayChange);
    assert!(c.power("pve1", GuestKind::Qemu, 201, Power::Start).unwrap().starts_with("UPID:"));
    assert!(Power::Stop.forced() && !Power::Shutdown.forced());
    c.power("pve1", GuestKind::Qemu, 201, Power::Stop).unwrap();
    c.take_snapshot("pve1", GuestKind::Qemu, 201, "s1", "before connect & test").unwrap();
    c.rollback("pve1", GuestKind::Qemu, 201, "s1").unwrap();
    c.delete_snapshot("pve1", GuestKind::Qemu, 201, "s1").unwrap();
    let snap = &c.transport().sent[2];
    assert_eq!(snap.body(), "snapname=s1&description=before%20connect%20%26%20test");
    assert!(matches!(c.power("pve2", GuestKind::Lxc, 202, Power::Suspend), Err(Error::Refused(_))));
}

#[test]
fn hostile_names_never_reach_the_path() {
    let mut c = Client::new(Mock::default(), Access::MayChange);
    for node in ["", "pve1/..", "../access", "pve 1", "pve1?x=1", "pve1#", "-pve", "pve%2f", &"a".repeat(64)] {
        assert!(matches!(c.snapshots(node, GuestKind::Qemu, 201), Err(Error::Refused(_))), "{node:?}");
    }
    for id in [0, 99, 1_000_000_000] {
        assert!(matches!(c.snapshots("pve1", GuestKind::Qemu, id), Err(Error::Refused(_))), "{id}");
    }
    for s in ["", "1abc", "a/b", "a..b", "current", "a b", &"a".repeat(41)] {
        assert!(matches!(c.rollback("pve1", GuestKind::Qemu, 201, s), Err(Error::Refused(_))), "{s:?}");
    }
    assert!(c.transport().sent.is_empty());
}

#[test]
fn every_request_stays_under_the_prefix() {
    let mut c = Client::new(Mock::default(), Access::MayChange);
    let _ = c.version();
    let _ = c.nodes();
    let _ = c.guests();
    let _ = c.guest_status("pve1", GuestKind::Lxc, 100);
    let _ = c.address("pve1", GuestKind::Qemu, 100);
    let _ = c.power("pve1", GuestKind::Qemu, 100, Power::Reboot);
    for r in &c.transport().sent {
        assert!(r.target.starts_with(PREFIX), "{}", r.target);
        assert!(!r.target.contains(".."));
        assert!(r.target.bytes().all(|b| (0x21..0x7f).contains(&b)));
    }
}

#[test]
fn bad_answers_are_errors_not_panics() {
    let mock = Mock::default()
        .on(Method::Get, "/api2/json/nodes", 200, "<html>")
        .on(Method::Get, "/api2/json/version", 200, r#"{"data":null}"#)
        .on(Method::Get, "/api2/json/cluster/resources?type=vm", 401, "");
    let mut c = Client::new(mock, Access::ReadOnly);
    assert!(matches!(c.nodes(), Err(Error::Parse(_))));
    assert!(matches!(c.version(), Err(Error::Parse(_))));
    assert!(matches!(c.guests(), Err(Error::Status(401, _))));
}

#[test]
fn form_encoding() {
    assert_eq!(encode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    let r = Request { method: Method::Post, target: "/api2/json/x".into(), form: vec![("k".into(), "v~-._".into())] };
    assert_eq!(r.body(), "k=v~-._");
}
