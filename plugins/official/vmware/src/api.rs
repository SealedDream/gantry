//! Requests to the vSphere Automation REST API and their answers.

use crate::model::*;
use crate::{Method, Request, Response, Transport};
use serde::de::DeserializeOwned;

/// Which API the entry's server speaks: vCenter REST, or a standalone ESXi host's SOAP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Backend {
    #[default]
    Rest,
    Soap,
}

thread_local! {
    static BACKEND: std::cell::Cell<Backend> = const { std::cell::Cell::new(Backend::Rest) };
}

/// Set once when the view opens, from the entry's connection type.
pub fn set_backend(b: Backend) {
    BACKEND.with(|c| c.set(b));
}

pub fn backend() -> Backend {
    BACKEND.with(|c| c.get())
}

/// The connection type's backend: `esxi` is SOAP, everything else REST.
pub fn backend_for(connection_type: &str) -> Backend {
    if connection_type == "esxi" {
        Backend::Soap
    } else {
        Backend::Rest
    }
}

/// The path prefix the manifest's `http.paths` lists.
pub const PREFIX: &str = "/api/vcenter/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Refused before anything was sent: a bad id, or a change on a read-only client.
    Refused(String),
    /// The server answered with an error status.
    Status(u16, String),
    /// The answer was not the JSON expected.
    Parse(String),
    /// The transport failed.
    Transport(String),
}

/// Whether the client may change the server (spec section 17: read-only by default).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
    MayChange,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Power {
    Start,
    /// Guest OS shutdown through VMware Tools, the guest decides.
    Shutdown,
    /// Guest OS reboot through VMware Tools.
    Reboot,
    /// Forced: like pulling the plug.
    Stop,
    /// Forced: like pressing reset.
    Reset,
    Suspend,
}

impl Power {
    /// The path after `vm/{vm}/` and the action.
    fn target(self) -> (&'static str, &'static str) {
        match self {
            Power::Start => ("power", "start"),
            Power::Stop => ("power", "stop"),
            Power::Reset => ("power", "reset"),
            Power::Suspend => ("power", "suspend"),
            Power::Shutdown => ("guest/power", "shutdown"),
            Power::Reboot => ("guest/power", "reboot"),
        }
    }

    /// Forced actions say so in their confirm (spec section 17).
    pub fn forced(self) -> bool {
        matches!(self, Power::Stop | Power::Reset)
    }
}

/// A vCenter managed-object id (`vm-42`, `host-21`): a lowercase prefix, `-`, then letters,
/// digits and `-`, at most 64. Anything else is refused, so it cannot add path segments.
pub fn check_id<'a>(id: &'a str, prefix: &str) -> Result<&'a str, Error> {
    let rest = id.strip_prefix(prefix).and_then(|r| r.strip_prefix('-'));
    let ok = id.len() <= 64 && rest.is_some_and(|r| !r.is_empty() && r.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if ok {
        Ok(id)
    } else {
        Err(Error::Refused(format!("not a valid {prefix} id")))
    }
}

/// One API call: the request, and how to read its answer. Pure: the synchronous [`Client`]
/// runs it over a [`Transport`], and the plugin runs it over the core's `http.send`.
pub struct Call<R> {
    pub request: Request,
    finish: Box<dyn FnOnce(Response) -> Result<R, Error>>,
}

impl<R> Call<R> {
    pub(crate) fn new(request: Request, finish: impl FnOnce(Response) -> Result<R, Error> + 'static) -> Call<R> {
        Call { request, finish: Box::new(finish) }
    }

    /// Refuses a call that changes the server on a read-only connection, before anything is
    /// sent (spec section 17: read-only by default).
    pub fn check(&self, access: Access) -> Result<(), Error> {
        if self.request.changes && access == Access::ReadOnly {
            return Err(Error::Refused("this connection is read-only".into()));
        }
        Ok(())
    }

    pub fn finish(self, resp: Response) -> Result<R, Error> {
        (self.finish)(resp)
    }
}

/// A short, plain excerpt of an error answer: vCenter sends `{"error_type":…,"messages":[…]}`.
fn excerpt(body: &[u8]) -> String {
    let text = serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            let m = v.get("messages")?.get(0)?.get("default_message")?.as_str()?.to_string();
            Some(m)
        })
        .unwrap_or_else(|| String::from_utf8_lossy(body).into_owned());
    text.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// The body of a successful answer.
fn json<R: DeserializeOwned>(resp: Response) -> Result<R, Error> {
    if !(200..300).contains(&resp.status) {
        return Err(Error::Status(resp.status, excerpt(&resp.body)));
    }
    serde_json::from_slice(&resp.body).map_err(|e| Error::Parse(e.to_string()))
}

/// No body expected (204).
fn empty(resp: Response) -> Result<(), Error> {
    if !(200..300).contains(&resp.status) {
        return Err(Error::Status(resp.status, excerpt(&resp.body)));
    }
    Ok(())
}

fn call<R: 'static>(method: Method, path: String, finish: impl FnOnce(Response) -> Result<R, Error> + 'static) -> Call<R> {
    Call { request: Request { method, target: format!("{PREFIX}{path}"), body: Vec::new(), changes: method.changes() }, finish: Box::new(finish) }
}

/// The longest snapshot name the plugin sends.
pub const MAX_SNAPSHOT_NAME: usize = 80;

/// Rows parsed one by one, so a row with a hostile id or an unknown shape is dropped.
fn rows<R: DeserializeOwned>(resp: Response, keep: impl Fn(&R) -> bool) -> Result<Vec<R>, Error> {
    let rows: Vec<serde_json::Value> = json(resp)?;
    Ok(rows.into_iter().filter_map(|r| serde_json::from_value::<R>(r).ok()).filter(keep).collect())
}

/// Every call the plugin makes. Ids are checked before they go into a path.
pub mod calls {
    use super::*;

    pub fn hosts() -> Call<Vec<Host>> {
        if backend() == Backend::Soap {
            return crate::soap::hosts();
        }
        call(Method::Get, "host".into(), |resp| rows(resp, |h: &Host| check_id(&h.host, "host").is_ok()))
    }

    /// The VMs vCenter lists (it caps the answer at 4000 rows).
    pub fn vms() -> Call<Vec<Vm>> {
        if backend() == Backend::Soap {
            return crate::soap::vms();
        }
        call(Method::Get, "vm".into(), |resp| rows(resp, |v: &Vm| check_id(&v.vm, "vm").is_ok()))
    }

    /// The VMs on one host (`?hosts=`), for the tree.
    pub fn vms_on(host: &str) -> Result<Call<Vec<Vm>>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::vms_on(host);
        }
        let host = check_id(host, "host")?;
        Ok(call(Method::Get, format!("vm?hosts={host}"), |resp| rows(resp, |v: &Vm| check_id(&v.vm, "vm").is_ok())))
    }

    /// One VM's name, for a prompt about a VM the plugin has not listed yet.
    pub fn name(vm: &str) -> Result<Call<String>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::name(vm);
        }
        let vm = check_id(vm, "vm")?;
        Ok(call(Method::Get, format!("vm/{vm}"), |resp| Ok(json::<VmInfo>(resp)?.name)))
    }

    /// The address to suggest for SSH, RDP or VNC, from VMware Tools. `None` when the guest
    /// reports none; Tools not running is an error status (503).
    pub fn address(vm: &str) -> Result<Call<Option<std::net::IpAddr>>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::address(vm);
        }
        let vm = check_id(vm, "vm")?;
        Ok(call(Method::Get, format!("vm/{vm}/guest/networking/interfaces"), |resp| {
            let ifaces: Vec<GuestInterface> = json(resp)?;
            Ok(pick_address(&ifaces, None))
        }))
    }

    pub fn identity(vm: &str) -> Result<Call<Identity>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::identity(vm);
        }
        let vm = check_id(vm, "vm")?;
        Ok(call(Method::Get, format!("vm/{vm}/guest/identity"), json::<Identity>))
    }

    /// A power action (answers 204).
    pub fn power(vm: &str, action: Power) -> Result<Call<()>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::power(vm, action);
        }
        let vm = check_id(vm, "vm")?;
        let (path, verb) = action.target();
        Ok(call(Method::Post, format!("vm/{vm}/{path}?action={verb}"), empty))
    }

    /// A VM's snapshots (vSphere 9.0 REST; 404 before it).
    pub fn snapshots(vm: &str) -> Result<Call<Vec<Snapshot>>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::snapshots(vm);
        }
        let vm = check_id(vm, "vm")?;
        Ok(call(Method::Get, format!("vm/{vm}/snapshots"), |resp| rows(resp, |s: &Snapshot| check_id(&s.snapshot, "snapshot").is_ok())))
    }

    /// Takes a snapshot of the disks only (no memory, no quiescing). The name is cut to
    /// [`MAX_SNAPSHOT_NAME`] characters with control characters removed.
    pub fn take_snapshot(vm: &str, name: &str) -> Result<Call<()>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::take_snapshot(vm, name);
        }
        let vm = check_id(vm, "vm")?;
        let name: String = name.chars().filter(|c| !c.is_control()).take(MAX_SNAPSHOT_NAME).collect();
        if name.trim().is_empty() {
            return Err(Error::Refused("a snapshot needs a name".into()));
        }
        let body = serde_json::json!({ "name": name, "memory": false, "quiesce": false });
        let mut c = call(Method::Post, format!("vm/{vm}/snapshots"), empty);
        c.request.body = serde_json::to_vec(&body).map_err(|e| Error::Parse(e.to_string()))?;
        Ok(c)
    }

    pub fn revert_snapshot(vm: &str, snapshot: &str) -> Result<Call<()>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::revert_snapshot(vm, snapshot);
        }
        let vm = check_id(vm, "vm")?;
        let snapshot = check_id(snapshot, "snapshot")?;
        Ok(call(Method::Post, format!("vm/{vm}/snapshots/{snapshot}?action=revert"), empty))
    }

    pub fn delete_snapshot(vm: &str, snapshot: &str) -> Result<Call<()>, Error> {
        if backend() == Backend::Soap {
            return crate::soap::delete_snapshot(vm, snapshot);
        }
        let vm = check_id(vm, "vm")?;
        let snapshot = check_id(snapshot, "snapshot")?;
        Ok(call(Method::Delete, format!("vm/{vm}/snapshots/{snapshot}"), empty))
    }
}

/// The calls over a synchronous [`Transport`] (tests, tools).
pub struct Client<T: Transport> {
    transport: T,
    access: Access,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T, access: Access) -> Self {
        Self { transport, access }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    pub fn run<R>(&mut self, c: Call<R>) -> Result<R, Error> {
        c.check(self.access)?;
        debug_assert!(c.request.target.starts_with(PREFIX) || c.request.target == crate::soap::SDK);
        let resp = self.transport.send(&c.request).map_err(Error::Transport)?;
        c.finish(resp)
    }

    pub fn hosts(&mut self) -> Result<Vec<Host>, Error> {
        self.run(calls::hosts())
    }
    pub fn vms(&mut self) -> Result<Vec<Vm>, Error> {
        self.run(calls::vms())
    }
    pub fn address(&mut self, vm: &str) -> Result<Option<std::net::IpAddr>, Error> {
        self.run(calls::address(vm)?)
    }
    pub fn identity(&mut self, vm: &str) -> Result<Identity, Error> {
        self.run(calls::identity(vm)?)
    }
    pub fn power(&mut self, vm: &str, action: Power) -> Result<(), Error> {
        self.run(calls::power(vm, action)?)
    }
    pub fn vms_on(&mut self, host: &str) -> Result<Vec<Vm>, Error> {
        self.run(calls::vms_on(host)?)
    }
    pub fn snapshots(&mut self, vm: &str) -> Result<Vec<Snapshot>, Error> {
        self.run(calls::snapshots(vm)?)
    }
    pub fn take_snapshot(&mut self, vm: &str, name: &str) -> Result<(), Error> {
        self.run(calls::take_snapshot(vm, name)?)
    }
    pub fn revert_snapshot(&mut self, vm: &str, snapshot: &str) -> Result<(), Error> {
        self.run(calls::revert_snapshot(vm, snapshot)?)
    }
    pub fn delete_snapshot(&mut self, vm: &str, snapshot: &str) -> Result<(), Error> {
        self.run(calls::delete_snapshot(vm, snapshot)?)
    }
}
