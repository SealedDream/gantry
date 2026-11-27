//! The client against a mock vCenter REST API: canned answers shaped like vCenter 7 and 8.

use bastion_plugin_vmware::api::*;
use bastion_plugin_vmware::model::*;
use bastion_plugin_vmware::{Method, Request, Response, Transport};
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
            None => Ok(Response { status: 404, body: br#"{"error_type":"NOT_FOUND","messages":[]}"#.to_vec() }),
        }
    }
}

const VMS: &str = r#"[
 {"memory_size_MiB":4096,"vm":"vm-42","name":"web","power_state":"POWERED_ON","cpu_count":2},
 {"memory_size_MiB":1024,"vm":"vm-43","name":"dns","power_state":"POWERED_OFF","cpu_count":1},
 {"vm":"vm-44","name":"paused","power_state":"SUSPENDED"},
 {"vm":"vm-../../session","name":"evil","power_state":"POWERED_ON"},
 {"vm":"host-1","name":"wrong kind","power_state":"POWERED_ON"},
 {"name":"no id"}
]"#;

#[test]
fn vms_parse_and_drop_bad_rows() {
    let mut c = Client::new(Mock::default().on(Method::Get, "/api/vcenter/vm", 200, VMS), Access::ReadOnly);
    let v = c.vms().unwrap();
    assert_eq!(v.iter().map(|v| v.vm.as_str()).collect::<Vec<_>>(), vec!["vm-42", "vm-43", "vm-44"]);
    assert_eq!(v[0].power(), PowerState::Running);
    assert_eq!((v[0].cpu_count, v[0].memory_mib), (Some(2), Some(4096)));
    assert_eq!(v[1].power(), PowerState::Stopped);
    assert_eq!(v[2].power(), PowerState::Suspended);
    assert_eq!(v[2].cpu_count, None);
}

#[test]
fn hosts_parse() {
    let body = r#"[{"host":"host-21","name":"esx1.lab","connection_state":"CONNECTED","power_state":"POWERED_ON"},{"host":"host-22","name":"esx2.lab","connection_state":"DISCONNECTED"},{"host":"x/y"}]"#;
    let mut c = Client::new(Mock::default().on(Method::Get, "/api/vcenter/host", 200, body), Access::ReadOnly);
    let h = c.hosts().unwrap();
    assert_eq!(h.len(), 2);
    assert_eq!(h[1].connection_state, "DISCONNECTED");
    assert_eq!(h[1].power_state, None);
}

#[test]
fn address_prefers_preferred_ipv4_and_skips_local() {
    let body = r#"[
      {"mac_address":"00:50:56:aa","ip":{"ip_addresses":[{"ip_address":"fe80::1","prefix_length":64,"state":"PREFERRED"},{"ip_address":"192.0.2.9","prefix_length":24,"state":"DEPRECATED"},{"ip_address":"2001:db8::5","prefix_length":64,"state":"PREFERRED"},{"ip_address":"169.254.3.3","state":"PREFERRED"},{"ip_address":"192.0.2.10","prefix_length":24,"state":"PREFERRED"}]}},
      {"mac_address":"00:50:56:bb"}
    ]"#;
    let mut c = Client::new(Mock::default().on(Method::Get, "/api/vcenter/vm/vm-42/guest/networking/interfaces", 200, body), Access::ReadOnly);
    assert_eq!(c.address("vm-42").unwrap(), Some("192.0.2.10".parse().unwrap()));
}

#[test]
fn address_falls_back_to_ipv6_identity_and_none() {
    let six: Vec<GuestInterface> = serde_json::from_str(r#"[{"ip":{"ip_addresses":[{"ip_address":"fe80::2"},{"ip_address":"2001:db8::7"}]}}]"#).unwrap();
    assert_eq!(pick_address(&six, None), Some("2001:db8::7".parse().unwrap()));
    let id = Identity { ip_address: Some("198.51.100.4".into()), host_name: None, family: None };
    assert_eq!(pick_address(&[], Some(&id)), Some("198.51.100.4".parse().unwrap()));
    let none: Vec<GuestInterface> = serde_json::from_str(r#"[{"ip":{"ip_addresses":[{"ip_address":"not an ip"},{"ip_address":"0.0.0.0"},{"ip_address":"127.0.0.1"}]}}]"#).unwrap();
    assert_eq!(pick_address(&none, None), None);
}

#[test]
fn tools_not_running_is_a_status_error_in_plain_text() {
    let body = "{\"error_type\":\"SERVICE_UNAVAILABLE\",\"messages\":[{\"default_message\":\"VMware Tools is not running\\u001b[0m\",\"id\":\"x\"}]}";
    let mut c = Client::new(Mock::default().on(Method::Get, "/api/vcenter/vm/vm-42/guest/identity", 503, body), Access::ReadOnly);
    match c.identity("vm-42") {
        Err(Error::Status(503, t)) => {
            assert_eq!(t, "VMware Tools is not running[0m");
            assert!(!t.contains('\u{1b}'));
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn read_only_client_refuses_every_change_and_sends_nothing() {
    let mut c = Client::new(Mock::default(), Access::ReadOnly);
    for a in [Power::Start, Power::Shutdown, Power::Reboot, Power::Stop, Power::Reset, Power::Suspend] {
        assert!(matches!(c.power("vm-42", a), Err(Error::Refused(_))));
    }
    assert!(c.transport().sent.is_empty());
}

#[test]
fn changes_build_the_right_requests() {
    let mock = Mock::default()
        .on(Method::Post, "/api/vcenter/vm/vm-42/power?action=start", 204, "")
        .on(Method::Post, "/api/vcenter/vm/vm-42/power?action=stop", 204, "")
        .on(Method::Post, "/api/vcenter/vm/vm-42/guest/power?action=shutdown", 204, "");
    let mut c = Client::new(mock, Access::MayChange);
    c.power("vm-42", Power::Start).unwrap();
    c.power("vm-42", Power::Stop).unwrap();
    c.power("vm-42", Power::Shutdown).unwrap();
    assert!(Power::Stop.forced() && Power::Reset.forced() && !Power::Shutdown.forced() && !Power::Reboot.forced());
    assert!(matches!(c.power("vm-42", Power::Suspend), Err(Error::Status(404, _))));
}

#[test]
fn hostile_ids_never_reach_the_path() {
    let mut c = Client::new(Mock::default(), Access::MayChange);
    for id in ["", "vm", "vm-", "vm-1/..", "vm-../x", "vm-1?x=1", "vm-1#", "vm-1 2", "host-1", "VM-1", "vm-%2f", &format!("vm-{}", "a".repeat(62))] {
        assert!(matches!(c.address(id), Err(Error::Refused(_))), "{id:?}");
        assert!(matches!(c.power(id, Power::Start), Err(Error::Refused(_))), "{id:?}");
    }
    assert!(c.transport().sent.is_empty());
    assert!(check_id("vm-1001", "vm").is_ok() && check_id("host-21", "host").is_ok());
}

#[test]
fn every_request_stays_under_the_prefix() {
    let mut c = Client::new(Mock::default(), Access::MayChange);
    let _ = c.hosts();
    let _ = c.vms();
    let _ = c.address("vm-1");
    let _ = c.identity("vm-1");
    for a in [Power::Start, Power::Shutdown, Power::Reboot, Power::Stop, Power::Reset, Power::Suspend] {
        let _ = c.power("vm-1", a);
    }
    assert_eq!(c.transport().sent.len(), 10);
    for r in &c.transport().sent {
        assert!(r.target.starts_with(PREFIX), "{}", r.target);
        assert!(!r.target.contains(".."));
        assert!(r.target.bytes().all(|b| (0x21..0x7f).contains(&b)));
    }
}

#[test]
fn bad_answers_are_errors_not_panics() {
    let mock = Mock::default()
        .on(Method::Get, "/api/vcenter/host", 200, "<html>")
        .on(Method::Get, "/api/vcenter/vm", 401, r#"{"error_type":"UNAUTHENTICATED","messages":[{"default_message":"Authentication required.","id":"x"}]}"#);
    let mut c = Client::new(mock, Access::ReadOnly);
    assert!(matches!(c.hosts(), Err(Error::Parse(_))));
    assert_eq!(c.vms(), Err(Error::Status(401, "Authentication required.".into())));
}

#[test]
fn vms_on_one_host_for_the_tree() {
    let mut c = Client::new(Mock::default().on(Method::Get, "/api/vcenter/vm?hosts=host-21", 200, VMS), Access::ReadOnly);
    assert_eq!(c.vms_on("host-21").unwrap().len(), 3);
    assert!(matches!(c.vms_on("host-21&hosts=host-22"), Err(Error::Refused(_))));
    assert!(matches!(c.vms_on("vm-42"), Err(Error::Refused(_))));
}

#[test]
fn snapshots_list_take_revert_delete() {
    let list = r#"[{"snapshot":"snapshot-7","name":"before patch","description":""},{"snapshot":"../x","name":"evil"}]"#;
    let mock = Mock::default()
        .on(Method::Get, "/api/vcenter/vm/vm-42/snapshots", 200, list)
        .on(Method::Post, "/api/vcenter/vm/vm-42/snapshots", 201, "")
        .on(Method::Post, "/api/vcenter/vm/vm-42/snapshots/snapshot-7?action=revert", 204, "")
        .on(Method::Delete, "/api/vcenter/vm/vm-42/snapshots/snapshot-7", 204, "");
    let mut c = Client::new(mock, Access::MayChange);
    let s = c.snapshots("vm-42").unwrap();
    assert_eq!(s.iter().map(|s| s.snapshot.as_str()).collect::<Vec<_>>(), vec!["snapshot-7"]);
    c.take_snapshot("vm-42", "before\npatch").unwrap();
    c.revert_snapshot("vm-42", "snapshot-7").unwrap();
    c.delete_snapshot("vm-42", "snapshot-7").unwrap();
    let body: serde_json::Value = serde_json::from_slice(&c.transport().sent[1].body).unwrap();
    assert_eq!(body["name"], "beforepatch");
    assert_eq!(body["memory"], false);
    assert!(matches!(c.take_snapshot("vm-42", " \n"), Err(Error::Refused(_))));
    assert!(matches!(c.delete_snapshot("vm-42", "snapshot-7/../../x"), Err(Error::Refused(_))));
}

#[test]
fn snapshot_changes_are_refused_read_only() {
    let mut c = Client::new(Mock::default(), Access::ReadOnly);
    assert!(matches!(c.take_snapshot("vm-42", "a"), Err(Error::Refused(_))));
    assert!(matches!(c.revert_snapshot("vm-42", "snapshot-7"), Err(Error::Refused(_))));
    assert!(matches!(c.delete_snapshot("vm-42", "snapshot-7"), Err(Error::Refused(_))));
    assert!(c.transport().sent.is_empty());
    // Listing is a read.
    assert!(matches!(c.snapshots("vm-42"), Err(Error::Status(404, _))));
}

/// The manifest's field keys and labels pass the core's checks (core/src/plugin/manifest.rs):
/// ids are lower-case letters, digits and `-`; a label must not contain a secret word once
/// folded (the first label tried, "…and snapshot…", folded to "…dsn…").
#[test]
fn manifest_fields_pass_the_cores_checks() {
    const SECRET_WORDS: [&str; 11] = ["password", "passwd", "pwd", "passphrase", "secret", "token", "apikey", "privatekey", "credential", "dsn", "connectionstring"];
    let text = include_str!("../plugin.toml");
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("key = \"") {
            let key = v.trim_end_matches('"');
            assert!(key.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'), "{key}");
        }
        if let Some(v) = line.strip_prefix("label = \"") {
            let folded: String = v.trim_end_matches('"').chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_ascii_lowercase();
            assert!(!SECRET_WORDS.iter().any(|w| folded.contains(w)), "{v}");
        }
        if let Some(v) = line.strip_prefix("description = \"") {
            assert!(v.trim_end_matches('"').chars().count() <= 120);
        }
    }
}
