//! Requests to the Proxmox VE API and their answers.

use crate::model::*;
use crate::{Method, Request, Response, Transport};
use serde::de::DeserializeOwned;

/// The path prefix the manifest's `http.paths` will list.
pub const PREFIX: &str = "/api2/json/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Refused before anything was sent: a bad name, or a change on a read-only client.
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
    /// ACPI shutdown, the guest decides.
    Shutdown,
    Reboot,
    /// Forced: like pulling the plug.
    Stop,
    Suspend,
    Resume,
}

impl Power {
    fn verb(self) -> &'static str {
        match self {
            Power::Start => "start",
            Power::Shutdown => "shutdown",
            Power::Reboot => "reboot",
            Power::Stop => "stop",
            Power::Suspend => "suspend",
            Power::Resume => "resume",
        }
    }

    /// Forced actions say so in their confirm (spec section 17).
    pub fn forced(self) -> bool {
        matches!(self, Power::Stop)
    }
}

/// Percent-encode everything outside the unreserved set (RFC 3986).
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// A node name as Proxmox allows it (a DNS label): letters, digits and `-`, 1 to 63, not
/// starting or ending with `-`. Anything else is refused, so it cannot add path segments.
pub fn check_node(n: &str) -> Result<&str, Error> {
    let ok = !n.is_empty()
        && n.len() <= 63
        && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !n.starts_with('-')
        && !n.ends_with('-');
    if ok {
        Ok(n)
    } else {
        Err(Error::Refused("not a valid node name".into()))
    }
}

/// Proxmox VMIDs are 100 to 999,999,999.
pub fn check_vmid(id: u64) -> Result<u64, Error> {
    if (100..=999_999_999).contains(&id) {
        Ok(id)
    } else {
        Err(Error::Refused("not a valid VM id".into()))
    }
}

/// Snapshot names: a letter, then letters, digits, `-` and `_`, at most 40 (Proxmox's rule).
pub fn check_snapshot(n: &str) -> Result<&str, Error> {
    let mut b = n.bytes();
    let ok = n.len() <= 40
        && b.next().is_some_and(|c| c.is_ascii_alphabetic())
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    if ok && n != "current" {
        Ok(n)
    } else {
        Err(Error::Refused("not a valid snapshot name".into()))
    }
}

/// Maps a Proxmox `ostype` to a library OS hint. QEMU: `win*` is Windows, `l24`/`l26` Linux,
/// `solaris` and `other` other. LXC: every template but `unmanaged` is a Linux distribution.
pub fn os_family_of(kind: GuestKind, ostype: &str) -> Option<&'static str> {
    match kind {
        GuestKind::Qemu if ostype.starts_with("win") => Some("windows"),
        GuestKind::Qemu if ostype == "l24" || ostype == "l26" => Some("linux"),
        GuestKind::Qemu if ostype == "solaris" || ostype == "other" => Some("other"),
        GuestKind::Qemu => None,
        GuestKind::Lxc if ostype == "unmanaged" => Some("other"),
        GuestKind::Lxc if !ostype.is_empty() => Some("linux"),
        GuestKind::Lxc => None,
    }
}

/// One API call: the request, and how to read its answer. Pure: the synchronous [`Client`]
/// runs it over a [`Transport`], and the plugin runs it over the core's `http.send`.
pub struct Call<R> {
    pub request: Request,
    finish: Box<dyn FnOnce(Response) -> Result<R, Error>>,
}

impl<R> Call<R> {
    /// Refuses a call that changes the server on a read-only connection, before anything is
    /// sent (spec section 17: read-only by default).
    pub fn check(&self, access: Access) -> Result<(), Error> {
        if self.request.method.changes() && access == Access::ReadOnly {
            return Err(Error::Refused("this connection is read-only".into()));
        }
        Ok(())
    }

    /// Reads the answer.
    pub fn finish(self, resp: Response) -> Result<R, Error> {
        (self.finish)(resp)
    }
}

/// The `data` of a successful answer.
fn data<R: DeserializeOwned>(resp: Response) -> Result<R, Error> {
    if !(200..300).contains(&resp.status) {
        // Proxmox puts the reason in the status line; the body is often empty or JSON with
        // `errors`. Keep a short, plain excerpt for the message.
        let text: String = String::from_utf8_lossy(&resp.body).chars().filter(|c| !c.is_control()).take(200).collect();
        return Err(Error::Status(resp.status, text));
    }
    let env: Envelope<R> = serde_json::from_slice(&resp.body).map_err(|e| Error::Parse(e.to_string()))?;
    env.data.ok_or_else(|| Error::Parse("no data".into()))
}

fn call<R: 'static>(method: Method, path: String, form: Vec<(String, String)>, finish: impl FnOnce(Response) -> Result<R, Error> + 'static) -> Call<R> {
    Call { request: Request { method, target: format!("{PREFIX}{path}"), form }, finish: Box::new(finish) }
}

fn get<R: DeserializeOwned + 'static>(path: String) -> Call<R> {
    call(Method::Get, path, vec![], data::<R>)
}

/// Every call the plugin makes. Names and ids are checked before they go into a path.
pub mod calls {
    use super::*;

    /// Server version, a cheap check that the token works.
    pub fn version() -> Call<serde_json::Value> {
        get("version".into())
    }

    pub fn nodes() -> Call<Vec<Node>> {
        get("nodes".into())
    }

    /// Every VM and container in the cluster, with its node. Rows are parsed one by one, so a
    /// row of a type this version does not know, or with a hostile node name, is dropped.
    pub fn guests() -> Call<Vec<Guest>> {
        call(Method::Get, "cluster/resources?type=vm".into(), vec![], |resp| {
            let rows: Vec<serde_json::Value> = data(resp)?;
            Ok(rows
                .into_iter()
                .filter_map(|r| serde_json::from_value::<Guest>(r).ok())
                .filter(|g| g.kind.is_some() && check_node(&g.node).is_ok() && check_vmid(g.vmid).is_ok())
                .collect())
        })
    }

    pub fn guest_status(node: &str, kind: GuestKind, vmid: u64) -> Result<Call<Guest>, Error> {
        let (node, vmid) = (check_node(node)?.to_string(), check_vmid(vmid)?);
        let path = format!("nodes/{node}/{}/{vmid}/status/current", kind.path());
        Ok(call(Method::Get, path, vec![], move |resp| {
            let mut g: Guest = data(resp)?;
            g.node = node;
            g.kind = Some(kind);
            g.vmid = vmid;
            Ok(g)
        }))
    }

    pub fn snapshots(node: &str, kind: GuestKind, vmid: u64) -> Result<Call<Vec<Snapshot>>, Error> {
        let (node, vmid) = (check_node(node)?, check_vmid(vmid)?);
        Ok(call(Method::Get, format!("nodes/{node}/{}/{vmid}/snapshot", kind.path()), vec![], |resp| {
            let rows: Vec<serde_json::Value> = data(resp)?;
            Ok(rows.into_iter().filter_map(|r| serde_json::from_value::<Snapshot>(r).ok()).filter(|s| !s.is_current()).collect())
        }))
    }

    /// The address to suggest for SSH, RDP or VNC: QEMU guest agent, or LXC interfaces.
    /// `None` when the guest reports none (agent not running is an error status).
    pub fn address(node: &str, kind: GuestKind, vmid: u64) -> Result<Call<Option<std::net::IpAddr>>, Error> {
        let (node, vmid) = (check_node(node)?, check_vmid(vmid)?);
        Ok(match kind {
            GuestKind::Qemu => call(Method::Get, format!("nodes/{node}/qemu/{vmid}/agent/network-get-interfaces"), vec![], |resp| {
                let r: AgentResult = data(resp)?;
                Ok(pick_address(&r.result))
            }),
            GuestKind::Lxc => call(Method::Get, format!("nodes/{node}/lxc/{vmid}/interfaces"), vec![], |resp| {
                let l: Vec<LxcInterface> = data(resp)?;
                Ok(pick_address(&lxc_to_agent(&l)))
            }),
        })
    }

    /// The guest's operating system family for a library proposal (`windows`, `linux` or
    /// `other`), from the config's `ostype`; `None` when the config does not say.
    pub fn os_family(node: &str, kind: GuestKind, vmid: u64) -> Result<Call<Option<&'static str>>, Error> {
        let (node, vmid) = (check_node(node)?, check_vmid(vmid)?);
        Ok(call(Method::Get, format!("nodes/{node}/{}/{vmid}/config", kind.path()), vec![], move |resp| {
            let config: serde_json::Value = data(resp)?;
            Ok(config.get("ostype").and_then(serde_json::Value::as_str).and_then(|t| os_family_of(kind, t)))
        }))
    }

    /// A power action. Answers the task id (UPID).
    pub fn power(node: &str, kind: GuestKind, vmid: u64, action: Power) -> Result<Call<String>, Error> {
        let (node, vmid) = (check_node(node)?, check_vmid(vmid)?);
        if kind == GuestKind::Lxc && action == Power::Suspend {
            return Err(Error::Refused("containers cannot be suspended here".into()));
        }
        Ok(call(Method::Post, format!("nodes/{node}/{}/{vmid}/status/{}", kind.path(), action.verb()), vec![], data::<String>))
    }

    pub fn take_snapshot(node: &str, kind: GuestKind, vmid: u64, name: &str, description: &str) -> Result<Call<String>, Error> {
        let (node, vmid, name) = (check_node(node)?, check_vmid(vmid)?, check_snapshot(name)?);
        let mut form = vec![("snapname".to_string(), name.to_string())];
        if !description.is_empty() {
            form.push(("description".into(), description.chars().take(1024).collect()));
        }
        Ok(call(Method::Post, format!("nodes/{node}/{}/{vmid}/snapshot", kind.path()), form, data::<String>))
    }

    pub fn rollback(node: &str, kind: GuestKind, vmid: u64, name: &str) -> Result<Call<String>, Error> {
        let (node, vmid, name) = (check_node(node)?, check_vmid(vmid)?, check_snapshot(name)?);
        Ok(call(Method::Post, format!("nodes/{node}/{}/{vmid}/snapshot/{name}/rollback", kind.path()), vec![], data::<String>))
    }

    pub fn delete_snapshot(node: &str, kind: GuestKind, vmid: u64, name: &str) -> Result<Call<String>, Error> {
        let (node, vmid, name) = (check_node(node)?, check_vmid(vmid)?, check_snapshot(name)?);
        Ok(call(Method::Delete, format!("nodes/{node}/{}/{vmid}/snapshot/{name}", kind.path()), vec![], data::<String>))
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

    pub fn run<R>(&mut self, c: Call<R>) -> Result<R, Error> {
        c.check(self.access)?;
        debug_assert!(c.request.target.starts_with(PREFIX));
        let resp = self.transport.send(&c.request).map_err(Error::Transport)?;
        c.finish(resp)
    }

    pub fn version(&mut self) -> Result<serde_json::Value, Error> {
        self.run(calls::version())
    }
    pub fn nodes(&mut self) -> Result<Vec<Node>, Error> {
        self.run(calls::nodes())
    }
    pub fn guests(&mut self) -> Result<Vec<Guest>, Error> {
        self.run(calls::guests())
    }
    pub fn guest_status(&mut self, node: &str, kind: GuestKind, vmid: u64) -> Result<Guest, Error> {
        self.run(calls::guest_status(node, kind, vmid)?)
    }
    pub fn snapshots(&mut self, node: &str, kind: GuestKind, vmid: u64) -> Result<Vec<Snapshot>, Error> {
        self.run(calls::snapshots(node, kind, vmid)?)
    }
    pub fn address(&mut self, node: &str, kind: GuestKind, vmid: u64) -> Result<Option<std::net::IpAddr>, Error> {
        self.run(calls::address(node, kind, vmid)?)
    }
    pub fn power(&mut self, node: &str, kind: GuestKind, vmid: u64, action: Power) -> Result<String, Error> {
        self.run(calls::power(node, kind, vmid, action)?)
    }
    pub fn take_snapshot(&mut self, node: &str, kind: GuestKind, vmid: u64, name: &str, description: &str) -> Result<String, Error> {
        self.run(calls::take_snapshot(node, kind, vmid, name, description)?)
    }
    pub fn rollback(&mut self, node: &str, kind: GuestKind, vmid: u64, name: &str) -> Result<String, Error> {
        self.run(calls::rollback(node, kind, vmid, name)?)
    }
    pub fn delete_snapshot(&mut self, node: &str, kind: GuestKind, vmid: u64, name: &str) -> Result<String, Error> {
        self.run(calls::delete_snapshot(node, kind, vmid, name)?)
    }
}
