//! Read-only check against a real Proxmox VE host. Ignored by default; run by hand:
//!
//!   set -a; . ~/.config/bastion/pve-test.env; set +a
//!   BASTION_PVE_PIN='sha256//…' cargo test --offline --test live -- --ignored
//!
//! - TLS: the self-signed certificate is trusted by its key pin only (curl `-k` plus
//!   `--pinnedpubkey`, which curl still enforces), as the entry's "pinned" TLS mode would.
//! - Needs `BASTION_PVE_URL`, `BASTION_PVE_TOKEN_ID`, `BASTION_PVE_TOKEN_SECRET` (a read-only
//!   PVEAuditor token kept outside the repository) and `BASTION_PVE_PIN`, the server key pin
//!   for curl's `--pinnedpubkey`.
//! - Sends GET only, to `version` and `nodes`: it reads no guest, so it never reads the owner's
//!   VMs. The transport refuses any other method or path. `live_snapshot_list` (PVE-SNAP) also
//!   reads one guest's snapshot list, `BASTION_PVE_SNAP_GUEST=node/vmid`, and refuses VMs 100-123.
//! - The token goes to curl on stdin, never in argv, and nothing here prints it or a host name.

use bastion_plugin_proxmox::{Access, Client, Method, Request, Response, Transport};
use std::io::Write;
use std::process::{Command, Stdio};

struct Curl {
    base: String,
    pin: String,
    auth: String,
}

impl Transport for Curl {
    fn send(&mut self, req: &Request) -> Result<Response, String> {
        assert_eq!(req.method, Method::Get, "the live check sends GET only");
        let snap_list = req.target.starts_with("/api2/json/nodes/") && req.target.ends_with("/snapshot") && !owner_vm(&req.target);
        assert!(
            matches!(req.target.as_str(), "/api2/json/version" | "/api2/json/nodes") || snap_list,
            "the live check reads only version, nodes and one non-owner guest's snapshots"
        );
        // Trust by pin only, like the entry's "pinned" TLS mode: the self-signed Proxmox
        // certificate has no public issuer, so CA checking is replaced by the key pin, which
        // curl still enforces with -k. Never -k without a pin.
        assert!(self.pin.starts_with("sha256//") && self.pin.len() == 52, "BASTION_PVE_PIN must be one sha256// pin");
        let mut child = Command::new("curl")
            .args(["-sS", "--max-time", "15", "--proto", "=https", "-k", "--pinnedpubkey", &self.pin])
            .args(["-K", "-", "-w", "\n%{http_code}"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "curl did not start".to_string())?;
        let cfg = format!("url = \"{}{}\"\nheader = \"Authorization: {}\"\n", self.base, req.target, self.auth);
        child.stdin.take().unwrap().write_all(cfg.as_bytes()).map_err(|_| "stdin".to_string())?;
        let out = child.wait_with_output().map_err(|_| "curl failed".to_string())?;
        if !out.status.success() {
            return Err(format!("curl exit {:?}", out.status.code()));
        }
        let text = out.stdout;
        let cut = text.iter().rposition(|&b| b == b'\n').ok_or("no status")?;
        let status = std::str::from_utf8(&text[cut + 1..]).ok().and_then(|s| s.trim().parse().ok()).ok_or("bad status")?;
        Ok(Response { status, body: text[..cut].to_vec() })
    }
}

#[test]
#[ignore = "needs a real Proxmox host and a read-only token"]
fn live_read_only() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
    let id = env("BASTION_PVE_TOKEN_ID");
    let secret = env("BASTION_PVE_TOKEN_SECRET");
    let mut c = Client::new(
        Curl { base: env("BASTION_PVE_URL"), pin: env("BASTION_PVE_PIN"), auth: format!("PVEAPIToken={id}={secret}") },
        Access::ReadOnly,
    );
    let v = c.version().unwrap_or_else(|e| panic!("version: {}", match e { bastion_plugin_proxmox::Error::Status(s, _) => format!("status {s}"), bastion_plugin_proxmox::Error::Transport(t) => t, bastion_plugin_proxmox::Error::Parse(_) => "parse".into(), bastion_plugin_proxmox::Error::Refused(_) => "refused".into() }));
    let nodes = c.nodes().expect("nodes");
    assert!(!nodes.is_empty());
    assert!(nodes.iter().all(|n| bastion_plugin_proxmox::api::check_node(&n.node).is_ok()));
    println!(
        "live: release {}, {} node(s), {} online",
        v["release"].as_str().unwrap_or("?"),
        nodes.len(),
        nodes.iter().filter(|n| n.status == "online").count()
    );
}

/// The owner's VMs 100-123 are off limits, even for reads.
fn owner_vm(target: &str) -> bool {
    target.split('/').filter_map(|s| s.parse::<u64>().ok()).any(|id| (100..=123).contains(&id))
}

#[test]
#[ignore = "needs a real Proxmox host, a read-only token and BASTION_PVE_SNAP_GUEST"]
fn live_snapshot_list() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k} not set"));
    let guest = env("BASTION_PVE_SNAP_GUEST");
    let (node, vmid) = guest.split_once('/').expect("node/vmid");
    let vmid: u64 = vmid.parse().expect("vmid");
    assert!(!(100..=123).contains(&vmid), "owner VMs 100-123 are off limits");
    let (id, secret) = (env("BASTION_PVE_TOKEN_ID"), env("BASTION_PVE_TOKEN_SECRET"));
    let mut c = Client::new(
        Curl { base: env("BASTION_PVE_URL"), pin: env("BASTION_PVE_PIN"), auth: format!("PVEAPIToken={id}={secret}") },
        Access::ReadOnly,
    );
    let snaps = c.snapshots(node, bastion_plugin_proxmox::model::GuestKind::Qemu, vmid).expect("snapshot list");
    assert!(snaps.iter().all(|s| !s.is_current()));
    println!("live: guest {vmid} has {} snapshot(s)", snaps.len());
    // A change is refused before anything is sent on a read-only client.
    assert!(matches!(c.take_snapshot(node, bastion_plugin_proxmox::model::GuestKind::Qemu, vmid, "bastion-1", ""), Err(bastion_plugin_proxmox::Error::Refused(_))));
}
