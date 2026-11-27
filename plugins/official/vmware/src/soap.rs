//! The same calls as [`crate::api::calls`], for a standalone ESXi host over the vSphere Web
//! Services (SOAP) API (`POST /sdk/`). The core logs in (manifest `[http.session]`) and adds the
//! session cookie; the plugin never sees the password or the cookie.
//!
//! ESXi's managed-object ids (`12`, `ha-host`, `12-snapshot-3`) are given the REST prefixes
//! (`vm-12`, `host-ha-host`, `snapshot-12-snapshot-3`), so the tree, menus and checks are the
//! vCenter ones. An id with any other character is dropped.

use crate::api::{check_id, Call, Error, Power, MAX_SNAPSHOT_NAME};
use crate::model::*;
use crate::xml::{self, Element};
use crate::{Method, Request, Response};

/// The path the plugin's SOAP calls go to (the manifest lists `/sdk/`).
pub const SDK: &str = "/sdk/";
/// ESXi's fixed managed objects.
const COLLECTOR: &str = "ha-property-collector";
const HOST: &str = "ha-host";
pub const MAX_MOID: usize = 48;

fn envelope(inner: &str) -> Vec<u8> {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="urn:vim25"><soapenv:Body>{inner}</soapenv:Body></soapenv:Envelope>"#).into_bytes()
}

/// The ESXi id inside a plugin key, checked.
fn moid<'a>(key: &'a str, prefix: &str) -> Result<&'a str, Error> {
    let id = check_id(key, prefix)?;
    Ok(&id[prefix.len() + 1..])
}

/// The plugin key for an ESXi id; `None` for an id with characters the key cannot hold.
fn key(prefix: &str, id: &str) -> Option<String> {
    let id = id.trim();
    let ok = !id.is_empty() && id.len() <= MAX_MOID && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
    ok.then(|| format!("{prefix}-{id}"))
}

fn soap<R: 'static>(body: String, changes: bool, finish: impl FnOnce(Element) -> Result<R, Error> + 'static) -> Call<R> {
    Call::new(Request { method: Method::Post, target: SDK.into(), body: envelope(&body), changes }, move |resp| finish(answer(resp)?))
}

/// The first element of a successful answer's body, or the fault as an error.
fn answer(resp: Response) -> Result<Element, Error> {
    let doc = xml::parse(&resp.body);
    if !(200..300).contains(&resp.status) {
        return Err(fault(resp.status, doc.ok()));
    }
    let doc = doc.map_err(Error::Parse)?;
    doc.child("Body").and_then(|b| b.children.first()).cloned().ok_or_else(|| Error::Parse("no SOAP body".into()))
}

/// A SOAP fault in the REST statuses the plugin already explains.
fn fault(status: u16, doc: Option<Element>) -> Error {
    let f = doc.as_ref().and_then(|d| d.child("Body")).and_then(|b| b.child("Fault"));
    let detail = f.and_then(|f| f.child("detail")).and_then(|d| d.children.first()).map(|e| e.name.as_str()).unwrap_or("");
    let text: String = f.and_then(|f| f.text_of("faultstring")).unwrap_or("").chars().filter(|c| !c.is_control()).take(200).collect();
    match detail {
        "NotAuthenticatedFault" | "InvalidLoginFault" => Error::Status(401, String::new()),
        "NoPermissionFault" => Error::Status(403, String::new()),
        "ManagedObjectNotFoundFault" => Error::Status(404, "not found on the host".into()),
        _ => Error::Status(status, text),
    }
}

/// One object of a `RetrievePropertiesEx` answer: type, id and its properties.
struct Object<'a> {
    kind: &'a str,
    id: &'a str,
    props: Vec<(&'a str, &'a Element)>,
}

impl Object<'_> {
    fn text(&self, name: &str) -> &str {
        self.props.iter().find(|(n, _)| *n == name).map(|(_, v)| v.text.trim()).unwrap_or("")
    }
    fn val(&self, name: &str) -> Option<&Element> {
        self.props.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
    }
}

fn objects(resp: &Element) -> Vec<Object<'_>> {
    let Some(ret) = resp.child("returnval") else { return Vec::new() };
    ret.all("objects")
        .filter_map(|o| {
            let obj = o.child("obj")?;
            let props = o.all("propSet").filter_map(|p| Some((p.text_of("name")?, p.child("val")?))).collect();
            Some(Object { kind: obj.kind.as_deref().unwrap_or(""), id: obj.text.trim(), props })
        })
        .collect()
}

fn retrieve(prop_sets: &str, object_set: &str) -> String {
    format!(r#"<RetrievePropertiesEx><_this type="PropertyCollector">{COLLECTOR}</_this><specSet>{prop_sets}{object_set}</specSet><options><maxObjects>4000</maxObjects></options></RetrievePropertiesEx>"#)
}

fn prop_set(kind: &str, paths: &[&str]) -> String {
    let paths: String = paths.iter().map(|p| format!("<pathSet>{p}</pathSet>")).collect();
    format!("<propSet><type>{kind}</type>{paths}</propSet>")
}

const VM_PATHS: [&str; 4] = ["name", "runtime.powerState", "config.hardware.numCPU", "config.hardware.memoryMB"];

/// The host and, through its `vm` list, every VM on it.
fn inventory() -> String {
    let props = prop_set("HostSystem", &["name", "runtime.connectionState", "runtime.powerState"]) + &prop_set("VirtualMachine", &VM_PATHS);
    let objects = format!(r#"<objectSet><obj type="HostSystem">{HOST}</obj><skip>false</skip><selectSet xsi:type="TraversalSpec"><name>vms</name><type>HostSystem</type><path>vm</path><skip>false</skip></selectSet></objectSet>"#);
    retrieve(&props, &objects)
}

fn one_vm(vm: &str, paths: &[&str]) -> String {
    retrieve(&prop_set("VirtualMachine", paths), &format!(r#"<objectSet><obj type="VirtualMachine">{vm}</obj><skip>false</skip></objectSet>"#))
}

fn power_word(s: &str) -> &'static str {
    match s {
        "poweredOn" => "POWERED_ON",
        "poweredOff" => "POWERED_OFF",
        "suspended" => "SUSPENDED",
        "standBy" => "STANDBY",
        _ => "",
    }
}

fn host_of(o: &Object<'_>) -> Option<Host> {
    let power = power_word(o.text("runtime.powerState"));
    Some(Host { host: key("host", o.id)?, name: o.text("name").to_string(), connection_state: o.text("runtime.connectionState").to_ascii_uppercase(), power_state: (!power.is_empty()).then(|| power.to_string()) })
}

fn vm_of(o: &Object<'_>) -> Option<Vm> {
    Some(Vm {
        vm: key("vm", o.id)?,
        name: o.text("name").to_string(),
        power_state: power_word(o.text("runtime.powerState")).to_string(),
        cpu_count: o.text("config.hardware.numCPU").parse().ok(),
        memory_mib: o.text("config.hardware.memoryMB").parse().ok(),
    })
}

fn vms_in(resp: &Element) -> Vec<Vm> {
    objects(resp).iter().filter(|o| o.kind == "VirtualMachine").filter_map(vm_of).collect()
}

fn task(name: &str, kind: &str, id: &str, extra: &str) -> String {
    format!(r#"<{name}><_this type="{kind}">{id}</_this>{extra}</{name}>"#)
}

pub fn hosts() -> Call<Vec<Host>> {
    soap(inventory(), false, |resp| Ok(objects(&resp).iter().filter(|o| o.kind == "HostSystem").filter_map(host_of).collect()))
}

pub fn vms() -> Call<Vec<Vm>> {
    soap(inventory(), false, |resp| Ok(vms_in(&resp)))
}

/// A standalone host has one host: its VMs are all VMs.
pub fn vms_on(host: &str) -> Result<Call<Vec<Vm>>, Error> {
    if moid(host, "host")? != HOST {
        return Err(Error::Refused("not this host".into()));
    }
    Ok(vms())
}

pub fn name(vm: &str) -> Result<Call<String>, Error> {
    let vm = moid(vm, "vm")?;
    Ok(soap(one_vm(vm, &["name"]), false, |resp| Ok(objects(&resp).first().map(|o| o.text("name").to_string()).unwrap_or_default())))
}

/// The address VMware Tools reports: every IP in `guest.net` and `guest.ipAddress`.
pub fn address(vm: &str) -> Result<Call<Option<std::net::IpAddr>>, Error> {
    let vm = moid(vm, "vm")?;
    Ok(soap(one_vm(vm, &["guest.ipAddress", "guest.net"]), false, |resp| {
        let objs = objects(&resp);
        let Some(o) = objs.first() else { return Ok(None) };
        let mut found = Vec::new();
        if let Some(net) = o.val("guest.net") {
            net.descendants("ipAddress", &mut found);
        }
        let addresses = found.iter().filter(|e| e.children.is_empty()).map(|e| GuestAddress { ip_address: e.text.trim().to_string(), state: None }).collect();
        let ifaces = vec![GuestInterface { ip: Some(GuestIp { ip_addresses: addresses }) }];
        let primary = Identity { ip_address: Some(o.text("guest.ipAddress").to_string()).filter(|s| !s.is_empty()), host_name: None, family: None };
        Ok(pick_address(&ifaces, Some(&primary)))
    }))
}

/// `guest.guestFamily` (`windowsGuest`, `linuxGuest`) as the REST family words.
pub fn identity(vm: &str) -> Result<Call<Identity>, Error> {
    let vm = moid(vm, "vm")?;
    Ok(soap(one_vm(vm, &["guest.guestFamily", "guest.hostName", "guest.ipAddress"]), false, |resp| {
        let objs = objects(&resp);
        let o = objs.first();
        let text = |p: &str| o.map(|o| o.text(p).to_string()).filter(|s| !s.is_empty());
        let family = text("guest.guestFamily").map(|f| if f == "windowsGuest" { "WINDOWS".into() } else { f.trim_end_matches("Guest").to_ascii_uppercase() });
        Ok(Identity { ip_address: text("guest.ipAddress"), host_name: text("guest.hostName"), family })
    }))
}

fn done(_: Element) -> Result<(), Error> {
    Ok(())
}

/// A power action: starts a host task (or asks VMware Tools); the answer is the task, not its end.
pub fn power(vm: &str, action: Power) -> Result<Call<()>, Error> {
    let vm = moid(vm, "vm")?;
    let name = match action {
        Power::Start => "PowerOnVM_Task",
        Power::Stop => "PowerOffVM_Task",
        Power::Reset => "ResetVM_Task",
        Power::Suspend => "SuspendVM_Task",
        Power::Shutdown => "ShutdownGuest",
        Power::Reboot => "RebootGuest",
    };
    Ok(soap(task(name, "VirtualMachine", vm, ""), true, done))
}

pub fn snapshots(vm: &str) -> Result<Call<Vec<Snapshot>>, Error> {
    let id = moid(vm, "vm")?;
    Ok(soap(one_vm(id, &["snapshot"]), false, |resp| {
        let objs = objects(&resp);
        let Some(info) = objs.first().and_then(|o| o.val("snapshot")) else { return Ok(Vec::new()) };
        let mut trees = Vec::new();
        info.descendants("rootSnapshotList", &mut trees);
        info.descendants("childSnapshotList", &mut trees);
        Ok(trees
            .into_iter()
            .filter_map(|t| Some(Snapshot { snapshot: key("snapshot", t.text_of("snapshot")?)?, name: t.text_of("name").unwrap_or("").to_string(), description: t.text_of("description").unwrap_or("").to_string() }))
            .collect())
    }))
}

/// Disks only: no memory, no quiescing.
pub fn take_snapshot(vm: &str, name: &str) -> Result<Call<()>, Error> {
    let vm = moid(vm, "vm")?;
    let name: String = name.chars().filter(|c| !c.is_control()).take(MAX_SNAPSHOT_NAME).collect();
    if name.trim().is_empty() {
        return Err(Error::Refused("a snapshot needs a name".into()));
    }
    let extra = format!("<name>{}</name><memory>false</memory><quiesce>false</quiesce>", xml::escape(&name));
    Ok(soap(task("CreateSnapshot_Task", "VirtualMachine", vm, &extra), true, done))
}

pub fn revert_snapshot(vm: &str, snapshot: &str) -> Result<Call<()>, Error> {
    moid(vm, "vm")?;
    let snap = moid(snapshot, "snapshot")?;
    Ok(soap(task("RevertToSnapshot_Task", "VirtualMachineSnapshot", snap, ""), true, done))
}

pub fn delete_snapshot(vm: &str, snapshot: &str) -> Result<Call<()>, Error> {
    moid(vm, "vm")?;
    let snap = moid(snapshot, "snapshot")?;
    Ok(soap(task("RemoveSnapshot_Task", "VirtualMachineSnapshot", snap, "<removeChildren>false</removeChildren>"), true, done))
}
