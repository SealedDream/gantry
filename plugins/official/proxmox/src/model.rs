//! Records from the Proxmox VE API. Fields the plugin does not use are ignored; fields Proxmox
//! leaves out (a stopped VM has no `cpu`) default, so a newer or older server still parses.

use serde::{Deserialize, Deserializer};
use std::net::IpAddr;

/// Proxmox sends some numbers as strings or as numbers depending on version; take both.
fn num<'de, D: Deserializer<'de>>(d: D) -> Result<f64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum N {
        F(f64),
        S(String),
    }
    Ok(match Option::<N>::deserialize(d)? {
        Some(N::F(f)) => f,
        Some(N::S(s)) => s.trim().parse().unwrap_or(0.0),
        None => 0.0,
    })
}

fn int<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let f = num(d)?;
    Ok(if f.is_finite() && f > 0.0 { f as u64 } else { 0 })
}

/// The `{"data": …}` envelope every Proxmox JSON answer has.
#[derive(Debug, Deserialize)]
pub struct Envelope<T> {
    pub data: Option<T>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Node {
    pub node: String,
    #[serde(default)]
    pub status: String,
    #[serde(default, deserialize_with = "num")]
    pub cpu: f64,
    #[serde(default, deserialize_with = "int")]
    pub maxcpu: u64,
    #[serde(default, deserialize_with = "int")]
    pub mem: u64,
    #[serde(default, deserialize_with = "int")]
    pub maxmem: u64,
    #[serde(default, deserialize_with = "int")]
    pub uptime: u64,
}

/// QEMU VM or LXC container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestKind {
    Qemu,
    Lxc,
}

impl GuestKind {
    pub fn path(self) -> &'static str {
        match self {
            GuestKind::Qemu => "qemu",
            GuestKind::Lxc => "lxc",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    Running,
    Stopped,
    Paused,
    Unknown,
}

/// A guest as `/cluster/resources?type=vm` or `/nodes/{node}/qemu` lists it.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Guest {
    #[serde(deserialize_with = "int")]
    pub vmid: u64,
    #[serde(default)]
    pub name: String,
    /// Present in `/cluster/resources`; filled in by the caller for per-node lists.
    #[serde(default)]
    pub node: String,
    /// `type` in `/cluster/resources`; per-node lists leave it out.
    #[serde(rename = "type", default)]
    pub kind: Option<GuestKind>,
    #[serde(default)]
    pub status: String,
    /// `qmpstatus` is more precise than `status` for paused VMs.
    #[serde(default)]
    pub qmpstatus: Option<String>,
    #[serde(default, deserialize_with = "num")]
    pub cpu: f64,
    #[serde(default, deserialize_with = "int")]
    pub maxcpu: u64,
    #[serde(default, deserialize_with = "int")]
    pub cpus: u64,
    #[serde(default, deserialize_with = "int")]
    pub mem: u64,
    #[serde(default, deserialize_with = "int")]
    pub maxmem: u64,
    #[serde(default, deserialize_with = "int")]
    pub disk: u64,
    #[serde(default, deserialize_with = "int")]
    pub maxdisk: u64,
    #[serde(default, deserialize_with = "int")]
    pub uptime: u64,
    #[serde(default, deserialize_with = "int")]
    pub template: u64,
}

impl Guest {
    pub fn power(&self) -> PowerState {
        match (self.qmpstatus.as_deref(), self.status.as_str()) {
            (Some("paused") | Some("suspended") | Some("prelaunch"), _) => PowerState::Paused,
            (_, "running") => PowerState::Running,
            (_, "stopped") => PowerState::Stopped,
            _ => PowerState::Unknown,
        }
    }

    pub fn is_template(&self) -> bool {
        self.template != 0
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Snapshot {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub parent: Option<String>,
    #[serde(default, deserialize_with = "int")]
    pub snaptime: u64,
    #[serde(default, deserialize_with = "int")]
    pub vmstate: u64,
}

impl Snapshot {
    /// Proxmox lists the live state as a pseudo-snapshot named `current`.
    pub fn is_current(&self) -> bool {
        self.name == "current"
    }
}

/// `/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces` answers `{"data":{"result":[…]}}`.
#[derive(Debug, Deserialize)]
pub struct AgentResult {
    #[serde(default)]
    pub result: Vec<AgentInterface>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentInterface {
    #[serde(default)]
    pub name: String,
    #[serde(rename = "ip-addresses", default)]
    pub ip_addresses: Vec<AgentAddress>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AgentAddress {
    #[serde(rename = "ip-address", default)]
    pub ip_address: String,
}

/// The address to connect to: the first usable IPv4 address, else the first usable IPv6.
/// Loopback, link-local, unspecified, multicast and Docker-style bridge interfaces are skipped.
/// The result is only a suggestion for the core's connect sheet; the plugin never connects.
pub fn pick_address(ifaces: &[AgentInterface]) -> Option<IpAddr> {
    let mut v6 = None;
    for i in ifaces {
        let n = i.name.as_str();
        if n == "lo" || n.starts_with("docker") || n.starts_with("br-") || n.starts_with("veth") {
            continue;
        }
        for a in &i.ip_addresses {
            let Ok(ip) = a.ip_address.trim().parse::<IpAddr>() else { continue };
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
                continue;
            }
            match ip {
                IpAddr::V4(v4) if v4.is_link_local() || v4.is_broadcast() => continue,
                IpAddr::V4(_) => return Some(ip),
                IpAddr::V6(v) if (v.segments()[0] & 0xffc0) == 0xfe80 => continue,
                IpAddr::V6(_) => {
                    if v6.is_none() {
                        v6 = Some(ip)
                    }
                }
            }
        }
    }
    v6
}

/// LXC: `/nodes/{node}/lxc/{vmid}/interfaces` answers a flat list with `inet` and `inet6`
/// in CIDR form.
#[derive(Debug, Clone, Deserialize)]
pub struct LxcInterface {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub inet: Option<String>,
    #[serde(default)]
    pub inet6: Option<String>,
}

pub fn lxc_to_agent(list: &[LxcInterface]) -> Vec<AgentInterface> {
    list.iter()
        .map(|l| AgentInterface {
            name: l.name.clone(),
            ip_addresses: [&l.inet, &l.inet6]
                .into_iter()
                .flatten()
                .map(|c| AgentAddress { ip_address: c.split('/').next().unwrap_or("").to_string() })
                .collect(),
        })
        .collect()
}
