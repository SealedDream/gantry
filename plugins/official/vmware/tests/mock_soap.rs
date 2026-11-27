//! The client against a mock standalone ESXi host (SOAP). The transport plays the core: it logs
//! in with the session template and adds the cookie, as `[http.session]` does. There is no real
//! ESXi host in the lab; this mock is the proof.

#[path = "support/esxi.rs"]
mod esxi;

use bastion_plugin_vmware::api::*;
use bastion_plugin_vmware::model::PowerState;
use bastion_plugin_vmware::{Request, Response, Transport};
use esxi::Esxi;

struct Core {
    host: Esxi,
    cookie: Option<String>,
    sent: Vec<Request>,
}

impl Core {
    fn new() -> Core {
        set_backend(Backend::Soap);
        Core { host: Esxi::default(), cookie: None, sent: Vec::new() }
    }
}

impl Transport for Core {
    fn send(&mut self, req: &Request) -> Result<Response, String> {
        self.sent.push(req.clone());
        assert_eq!(req.target, "/sdk/");
        let body = String::from_utf8(req.body.clone()).unwrap();
        assert!(!body.contains("<Login"), "the plugin never logs in itself");
        if self.cookie.is_none() {
            let login = format!("<Envelope><Body><Login><_this>ha-sessionmgr</_this><userName>{}</userName><password>{}</password></Login></Body></Envelope>", esxi::USER, esxi::PASSWORD);
            self.cookie = self.host.answer(&login, None).2;
        }
        let (status, body, _) = self.host.answer(&body, self.cookie.as_deref());
        Ok(Response { status, body: body.into_bytes() })
    }
}

fn client(access: Access) -> Client<Core> {
    Client::new(Core::new(), access)
}

#[test]
fn the_host_and_its_vms_with_rest_shaped_ids() {
    let mut c = client(Access::ReadOnly);
    let hosts = c.hosts().unwrap();
    assert_eq!(hosts.len(), 1);
    assert_eq!((hosts[0].host.as_str(), hosts[0].name.as_str(), hosts[0].connection_state.as_str(), hosts[0].power_state.as_deref()), ("host-ha-host", "esxi-mock.lab.example", "CONNECTED", Some("POWERED_ON")));
    let vms = c.vms_on("host-ha-host").unwrap();
    assert_eq!(vms.iter().map(|v| v.vm.as_str()).collect::<Vec<_>>(), vec!["vm-1", "vm-2", "vm-3"]);
    assert_eq!((vms[0].name.as_str(), vms[0].power(), vms[0].cpu_count, vms[0].memory_mib), ("web01", PowerState::Running, Some(2), Some(4096)));
    assert_eq!(vms[2].power(), PowerState::Stopped);
    assert!(c.vms_on("host-other").is_err(), "a standalone host has one host");
    assert_eq!(c.transport().host.logins, 1, "one login for every call");
}

#[test]
fn reads_never_count_as_changes_on_a_read_only_entry() {
    let mut c = client(Access::ReadOnly);
    assert!(c.vms().is_ok() && c.snapshots("vm-1").is_ok() && c.address("vm-1").is_ok() && c.identity("vm-2").is_ok());
    assert!(matches!(c.power("vm-1", Power::Stop), Err(Error::Refused(_))));
    assert!(matches!(c.take_snapshot("vm-1", "x"), Err(Error::Refused(_))));
    assert!(c.transport().host.calls.iter().all(|m| m.starts_with("RetrievePropertiesEx")), "{:?}", c.transport().host.calls);
}

#[test]
fn address_and_family_from_vmware_tools() {
    let mut c = client(Access::ReadOnly);
    assert_eq!(c.address("vm-1").unwrap(), Some("192.0.2.11".parse().unwrap()), "IPv4 first, link-local skipped");
    assert_eq!(c.address("vm-3").unwrap(), None, "no Tools address");
    assert_eq!(c.identity("vm-2").unwrap().family.as_deref(), Some("WINDOWS"));
    assert_eq!(c.identity("vm-1").unwrap().family.as_deref(), Some("LINUX"));
}

#[test]
fn power_and_snapshots_send_the_right_methods() {
    let mut c = client(Access::MayChange);
    c.power("vm-3", Power::Start).unwrap();
    c.power("vm-1", Power::Shutdown).unwrap();
    c.power("vm-2", Power::Reset).unwrap();
    assert_eq!(c.transport().host.vms["3"].power, "poweredOn");
    let snaps = c.snapshots("vm-1").unwrap();
    assert_eq!((snaps[0].snapshot.as_str(), snaps[0].name.as_str()), ("snapshot-1-snapshot-1", "before upgrade"));
    c.take_snapshot("vm-1", "a <b> & \"c\"").unwrap();
    c.revert_snapshot("vm-1", "snapshot-1-snapshot-1").unwrap();
    c.delete_snapshot("vm-1", "snapshot-1-snapshot-1").unwrap();
    let calls = &c.transport().host.calls;
    for want in ["PowerOnVM_Task 3", "ShutdownGuest 1", "ResetVM_Task 2", "CreateSnapshot_Task 1 a &lt;b&gt; &amp; &quot;c&quot;", "RevertToSnapshot_Task 1-snapshot-1", "RemoveSnapshot_Task 1-snapshot-1"] {
        assert!(calls.iter().any(|m| m == want), "{want} in {calls:?}");
    }
    assert_eq!(c.snapshots("vm-1").unwrap().len(), 1, "the removed one is gone, the new one is there");
}

#[test]
fn hostile_ids_never_reach_the_body() {
    let mut c = client(Access::MayChange);
    for bad in ["vm-1</_this><Login>", "vm-../x", "vm-", "host-1", "vm-1 2"] {
        assert!(matches!(c.power(bad, Power::Start), Err(Error::Refused(_))), "{bad}");
    }
    assert!(c.revert_snapshot("vm-1", "snapshot-1<x>").is_err());
    assert!(c.transport().sent.is_empty());
}

#[test]
fn faults_become_the_statuses_the_plugin_explains() {
    let mut c = client(Access::MayChange);
    match c.power("vm-99", Power::Start) {
        Err(Error::Status(404, _)) => {}
        other => panic!("{other:?}"),
    }
    // The host ended the session and the core could not log in again: a 401 for the plugin.
    c.transport_mut().cookie = Some("stale".into());
    match c.vms() {
        Err(Error::Status(401, t)) => assert!(t.is_empty(), "never the fault text"),
        other => panic!("{other:?}"),
    }
}
