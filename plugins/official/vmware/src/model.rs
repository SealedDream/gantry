//! Records from the vSphere Automation REST API (`/api/vcenter/...`, vCenter 7.0 and later).
//! Fields the plugin does not use are ignored; fields left out default, so a newer or older
//! server still parses.

use serde::Deserialize;
use std::net::IpAddr;

/// `GET /api/vcenter/host` row.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Host {
    pub host: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub connection_state: String,
    #[serde(default)]
    pub power_state: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    Running,
    Stopped,
    Suspended,
    Unknown,
}

/// `GET /api/vcenter/vm` row.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Vm {
    pub vm: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub power_state: String,
    #[serde(default)]
    pub cpu_count: Option<u64>,
    #[serde(rename = "memory_size_MiB", default)]
    pub memory_mib: Option<u64>,
}

impl Vm {
    pub fn power(&self) -> PowerState {
        match self.power_state.as_str() {
            "POWERED_ON" => PowerState::Running,
            "POWERED_OFF" => PowerState::Stopped,
            "SUSPENDED" => PowerState::Suspended,
            _ => PowerState::Unknown,
        }
    }
}

/// `GET /api/vcenter/vm/{vm}/guest/identity`, reported by VMware Tools.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Identity {
    #[serde(default)]
    pub ip_address: Option<String>,
    #[serde(default)]
    pub host_name: Option<String>,
    #[serde(default)]
    pub family: Option<String>,
}

/// `GET /api/vcenter/vm/{vm}/guest/networking/interfaces` row.
#[derive(Debug, Clone, Deserialize)]
pub struct GuestInterface {
    #[serde(default)]
    pub ip: Option<GuestIp>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GuestIp {
    #[serde(default)]
    pub ip_addresses: Vec<GuestAddress>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GuestAddress {
    #[serde(default)]
    pub ip_address: String,
    /// `PREFERRED`, `DEPRECATED`, `INVALID`, … Only preferred (or unstated) addresses are used.
    #[serde(default)]
    pub state: Option<String>,
}

fn usable(ip: IpAddr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
    }
}

/// The address to connect to: the first usable IPv4 address, else the first usable IPv6.
/// The result is only a suggestion for the core's connect sheet; the plugin never connects.
pub fn pick_address(ifaces: &[GuestInterface], identity: Option<&Identity>) -> Option<IpAddr> {
    let from_ifaces = ifaces
        .iter()
        .filter_map(|i| i.ip.as_ref())
        .flat_map(|ip| ip.ip_addresses.iter())
        .filter(|a| a.state.as_deref().is_none_or(|s| s == "PREFERRED"))
        .filter_map(|a| a.ip_address.trim().parse::<IpAddr>().ok());
    let from_identity = identity.and_then(|i| i.ip_address.as_deref()).and_then(|a| a.trim().parse::<IpAddr>().ok());
    let all: Vec<IpAddr> = from_ifaces.chain(from_identity).filter(|ip| usable(*ip)).collect();
    all.iter().find(|ip| ip.is_ipv4()).or_else(|| all.first()).copied()
}

/// A snapshot from `GET /api/vcenter/vm/{vm}/snapshots` (vSphere 9.0 REST). Older vCenters have
/// no snapshot calls and answer 404; the plugin says so.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Snapshot {
    pub snapshot: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

/// `GET /api/vcenter/vm/{vm}`: only the name is used.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct VmInfo {
    #[serde(default)]
    pub name: String,
}
