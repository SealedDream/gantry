//! A mock standalone ESXi host's SOAP API (`/sdk`), pure: one request body in, one answer out.
//! Shared by the plugin's tests and the `mock_esxi` example server the app suites use. There is
//! no real ESXi host in the lab; the answers follow the vSphere Web Services API reference
//! (vim25, ESXi 7 and 8), trimmed to what the plugin reads.

#![allow(dead_code)]

use std::collections::BTreeMap;

pub const USER: &str = "root";
/// The mock's own test password (no real host has it).
pub const PASSWORD: &str = "esxi-mock-pw";
pub const COOKIE: &str = "vmware_soap_session";

#[derive(Clone, Debug)]
pub struct Vm {
    pub id: &'static str,
    pub name: &'static str,
    pub power: &'static str,
    pub cpus: u32,
    pub memory: u32,
    pub family: &'static str,
    pub ip: &'static str,
    pub snapshots: Vec<(String, String)>,
}

pub struct Esxi {
    pub vms: BTreeMap<&'static str, Vm>,
    /// The session the host accepts now.
    pub session: Option<String>,
    pub logins: usize,
    /// Every method called, in order (`PowerOnVM_Task 1`).
    pub calls: Vec<String>,
    next_snapshot: u32,
}

impl Default for Esxi {
    fn default() -> Self {
        let vms = [
            Vm { id: "1", name: "web01", power: "poweredOn", cpus: 2, memory: 4096, family: "linuxGuest", ip: "192.0.2.11", snapshots: vec![("1-snapshot-1".into(), "before upgrade".into())] },
            Vm { id: "2", name: "dc01", power: "poweredOn", cpus: 4, memory: 8192, family: "windowsGuest", ip: "192.0.2.12", snapshots: vec![] },
            Vm { id: "3", name: "build", power: "poweredOff", cpus: 1, memory: 2048, family: "linuxGuest", ip: "", snapshots: vec![] },
        ];
        Esxi { vms: vms.into_iter().map(|v| (v.id, v)).collect(), session: None, logins: 0, calls: Vec::new(), next_snapshot: 2 }
    }
}

fn envelope(inner: &str) -> String {
    format!(r#"<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body>{inner}</soapenv:Body></soapenv:Envelope>"#)
}

pub fn fault(detail: &str, text: &str) -> (u16, String) {
    (500, envelope(&format!(r#"<soapenv:Fault><faultcode>ServerFaultCode</faultcode><faultstring>{text}</faultstring><detail><{detail} xmlns="urn:vim25" xsi:type="{detail}"/></detail></soapenv:Fault>"#)))
}

/// The text between `<tag>` (any attributes) and `</tag>`.
fn between<'a>(body: &'a str, tag: &str) -> Option<&'a str> {
    let at = |i: usize| body[i + 1 + tag.len()..].starts_with([' ', '>']);
    let open = body.match_indices(&format!("<{tag}")).map(|(i, _)| i).find(|i| at(*i))?;
    let start = open + body[open..].find('>')? + 1;
    let end = start + body[start..].find(&format!("</{tag}>"))?;
    Some(&body[start..end])
}

fn prop(name: &str, kind: &str, val: &str) -> String {
    format!(r#"<propSet><name>{name}</name><val xsi:type="{kind}">{val}</val></propSet>"#)
}

impl Esxi {
    /// One request: `cookie` is the `vmware_soap_session` the client sent, if any. Returns the
    /// status, the body and a `Set-Cookie` value for a login.
    pub fn answer(&mut self, body: &str, cookie: Option<&str>) -> (u16, String, Option<String>) {
        if let Some(login) = between(body, "Login") {
            self.logins += 1;
            let (user, pw) = (between(login, "userName").unwrap_or(""), between(login, "password").unwrap_or(""));
            if user != USER || pw != PASSWORD {
                let (s, b) = fault("InvalidLoginFault", "Cannot complete login due to an incorrect user name or password.");
                return (s, b, None);
            }
            let session = format!("52{:04x}-mock-session", self.logins);
            self.session = Some(session.clone());
            return (200, envelope(&format!("<LoginResponse xmlns=\"urn:vim25\"><returnval><key>{session}</key><userName>{USER}</userName></returnval></LoginResponse>")), Some(session));
        }
        if body.contains("<Logout") {
            self.session = None;
            return (200, envelope("<LogoutResponse xmlns=\"urn:vim25\"></LogoutResponse>"), None);
        }
        if cookie.is_none() || cookie != self.session.as_deref() {
            let (s, b) = fault("NotAuthenticatedFault", "The session is not authenticated.");
            return (s, b, None);
        }
        let (s, b) = self.call(body);
        (s, b, None)
    }

    fn call(&mut self, body: &str) -> (u16, String) {
        for (method, kind) in [("PowerOnVM_Task", "poweredOn"), ("PowerOffVM_Task", "poweredOff"), ("ResetVM_Task", ""), ("SuspendVM_Task", "suspended"), ("ShutdownGuest", "poweredOff"), ("RebootGuest", "")] {
            if let Some(inner) = between(body, method) {
                let id = between(inner, "_this").unwrap_or("").to_string();
                self.calls.push(format!("{method} {id}"));
                let Some(vm) = self.vms.get_mut(id.as_str()) else { return fault("ManagedObjectNotFoundFault", "The object has already been deleted or has not been completely created") };
                if !kind.is_empty() {
                    vm.power = kind;
                }
                return (200, envelope(&format!(r#"<{method}Response xmlns="urn:vim25"><returnval type="Task">haTask-{id}-vim.VirtualMachine.powerOn-1</returnval></{method}Response>"#)));
            }
        }
        if let Some(inner) = between(body, "CreateSnapshot_Task") {
            let id = between(inner, "_this").unwrap_or("").to_string();
            let name = between(inner, "name").unwrap_or("").to_string();
            self.calls.push(format!("CreateSnapshot_Task {id} {name}"));
            let n = self.next_snapshot;
            self.next_snapshot += 1;
            let Some(vm) = self.vms.get_mut(id.as_str()) else { return fault("ManagedObjectNotFoundFault", "not found") };
            vm.snapshots.push((format!("{id}-snapshot-{n}"), name));
            return (200, envelope(r#"<CreateSnapshot_TaskResponse xmlns="urn:vim25"><returnval type="Task">haTask-1</returnval></CreateSnapshot_TaskResponse>"#));
        }
        for method in ["RevertToSnapshot_Task", "RemoveSnapshot_Task"] {
            if let Some(inner) = between(body, method) {
                let snap = between(inner, "_this").unwrap_or("").to_string();
                self.calls.push(format!("{method} {snap}"));
                if method == "RemoveSnapshot_Task" {
                    for vm in self.vms.values_mut() {
                        vm.snapshots.retain(|(s, _)| *s != snap);
                    }
                }
                return (200, envelope(&format!(r#"<{method}Response xmlns="urn:vim25"><returnval type="Task">haTask-2</returnval></{method}Response>"#)));
            }
        }
        if let Some(spec) = between(body, "RetrievePropertiesEx") {
            return (200, envelope(&format!(r#"<RetrievePropertiesExResponse xmlns="urn:vim25"><returnval>{}</returnval></RetrievePropertiesExResponse>"#, self.retrieve(spec))));
        }
        fault("MethodNotFoundFault", "Unknown method")
    }

    fn retrieve(&mut self, spec: &str) -> String {
        if spec.contains(r#"<obj type="HostSystem">ha-host</obj>"#) {
            self.calls.push("RetrievePropertiesEx inventory".into());
            let mut out = format!(
                r#"<objects><obj type="HostSystem">ha-host</obj>{}{}{}</objects>"#,
                prop("name", "xsd:string", "esxi-mock.lab.example"),
                prop("runtime.connectionState", "HostSystemConnectionState", "connected"),
                prop("runtime.powerState", "HostSystemPowerState", "poweredOn")
            );
            for vm in self.vms.values() {
                out += &format!(
                    r#"<objects><obj type="VirtualMachine">{}</obj>{}{}{}{}</objects>"#,
                    vm.id,
                    prop("name", "xsd:string", vm.name),
                    prop("runtime.powerState", "VirtualMachinePowerState", vm.power),
                    prop("config.hardware.numCPU", "xsd:int", &vm.cpus.to_string()),
                    prop("config.hardware.memoryMB", "xsd:int", &vm.memory.to_string())
                );
            }
            return out;
        }
        let id = between(spec, "obj").unwrap_or("").to_string();
        self.calls.push(format!("RetrievePropertiesEx {id}"));
        let Some(vm) = self.vms.get(id.as_str()) else { return String::new() };
        let mut props = String::new();
        let paths: Vec<&str> = spec.split("<pathSet>").skip(1).filter_map(|p| p.split("</pathSet>").next()).collect();
        for p in paths {
            props += &match p {
                "name" => prop("name", "xsd:string", vm.name),
                "guest.guestFamily" => prop("guest.guestFamily", "xsd:string", vm.family),
                "guest.hostName" => prop("guest.hostName", "xsd:string", vm.name),
                "guest.ipAddress" if !vm.ip.is_empty() => prop("guest.ipAddress", "xsd:string", vm.ip),
                "guest.net" if !vm.ip.is_empty() => prop(
                    "guest.net",
                    "ArrayOfGuestNicInfo",
                    &format!(r#"<GuestNicInfo xsi:type="GuestNicInfo"><network>VM Network</network><ipAddress>fe80::1</ipAddress><ipAddress>{}</ipAddress><ipConfig><ipAddress><ipAddress>{}</ipAddress><prefixLength>24</prefixLength><state>preferred</state></ipAddress></ipConfig><connected>true</connected></GuestNicInfo>"#, vm.ip, vm.ip),
                ),
                "snapshot" if !vm.snapshots.is_empty() => {
                    let list: String = vm.snapshots.iter().map(|(s, n)| format!(r#"<rootSnapshotList><snapshot type="VirtualMachineSnapshot">{s}</snapshot><vm type="VirtualMachine">{}</vm><name>{n}</name><description></description><createTime>2026-11-01T10:00:00Z</createTime><state>poweredOff</state><quiesced>false</quiesced></rootSnapshotList>"#, vm.id)).collect();
                    prop("snapshot", "VirtualMachineSnapshotInfo", &format!(r#"<currentSnapshot type="VirtualMachineSnapshot">{}</currentSnapshot>{list}"#, vm.snapshots.last().map(|s| s.0.as_str()).unwrap_or("")))
                }
                _ => String::new(),
            };
        }
        format!(r#"<objects><obj type="VirtualMachine">{}</obj>{props}</objects>"#, vm.id)
    }
}
