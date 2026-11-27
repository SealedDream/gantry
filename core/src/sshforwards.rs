//! OpenSSH `LocalForward` / `RemoteForward` / `DynamicForward` lines → saved tunnels
//! (`tunneldefs`). Nothing is created unless the user ticks the row in the import preview; see
//! `docs/plans/SSH-IMPORT-FORWARDS.md`. Bastion tunnels bind loopback only, so a config that asks
//! for a wider bind is imported on 127.0.0.1 with a warning, never widened.
use std::collections::{BTreeSet, HashMap};

use serde::Serialize;
use uuid::Uuid;

use crate::error::Result;
use crate::model::{Document, Folder, Node};
use crate::sshconfig::ResolvedHost;
use crate::tunneldefs::{self, TunnelDef, TunnelSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ForwardKind {
    Local,
    Remote,
    Dynamic,
}

impl ForwardKind {
    fn letter(self) -> char {
        match self {
            ForwardKind::Local => 'L',
            ForwardKind::Remote => 'R',
            ForwardKind::Dynamic => 'D',
        }
    }
}

/// One config line, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedForward {
    pub spec: TunnelSpec,
    /// The listening side asked for more than loopback (`*`, `0.0.0.0`, a LAN address).
    pub wide_bind: bool,
}

/// Parse one forward value (the text after the keyword). `Err` is the reason in plain words.
pub fn parse(kind: ForwardKind, value: &str) -> std::result::Result<ParsedForward, String> {
    let args: Vec<&str> = value.split_whitespace().collect();
    if args.iter().any(|a| a.starts_with('/') || a.starts_with("[/")) {
        return Err("Unix socket forwards are not supported.".into());
    }
    let (bind, port) = split_listen(args.first().ok_or("The line is empty.")?)?;
    let wide_bind = bind.is_some_and(|b| !is_loopback(b));
    let spec = match (kind, args.len()) {
        (ForwardKind::Dynamic, 1) => TunnelSpec::Dynamic { local_port: port },
        (ForwardKind::Remote, 1) => return Err("A remote SOCKS proxy (RemoteForward with one port) is not supported.".into()),
        (ForwardKind::Local, 2) => {
            let (dest_host, dest_port) = split_target(args[1])?;
            TunnelSpec::Local { local_port: port, dest_host, dest_port }
        }
        (ForwardKind::Remote, 2) => {
            let (local_host, local_port) = split_target(args[1])?;
            TunnelSpec::Remote { remote_port: port, local_host, local_port }
        }
        _ => return Err(format!("Unexpected form: {value}")),
    };
    Ok(ParsedForward { spec, wide_bind })
}

fn port_of(s: &str) -> std::result::Result<u16, String> {
    match s.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(format!("{s} is not a port from 1 to 65535.")),
    }
}

/// `[bind:]port`, bind may be `[v6]`, `*` or empty (`:8080` = all interfaces).
fn split_listen(s: &str) -> std::result::Result<(Option<&str>, u16), String> {
    if let Some(rest) = s.strip_prefix('[') {
        let (b, p) = rest.split_once("]:").ok_or_else(|| format!("{s} is not [address]:port."))?;
        return Ok((Some(b), port_of(p)?));
    }
    match s.rsplit_once(':') {
        Some((b, p)) => Ok((Some(if b.is_empty() { "*" } else { b }), port_of(p)?)),
        None => Ok((None, port_of(s)?)),
    }
}

/// `host:port` or `[v6]:port`.
fn split_target(s: &str) -> std::result::Result<(String, u16), String> {
    let (h, p) = if let Some(rest) = s.strip_prefix('[') {
        rest.split_once("]:").ok_or_else(|| format!("{s} is not [address]:port."))?
    } else {
        s.rsplit_once(':').ok_or_else(|| format!("{s} is not host:port."))?
    };
    if h.is_empty() || h.starts_with('-') {
        return Err(format!("{s} has no host."));
    }
    Ok((h.to_owned(), port_of(p)?))
}

/// Loopback in any spelling (`localhost`, `127.x`, `::1`, `0:0:…:1`, `::ffff:127.0.0.1`). Anything
/// else counts as wide, which only adds a warning.
fn is_loopback(b: &str) -> bool {
    let b = b.trim_start_matches('[').trim_end_matches(']');
    b.eq_ignore_ascii_case("localhost")
        || b.parse::<std::net::Ipv4Addr>().is_ok_and(|a| a.is_loopback())
        || b.parse::<std::net::Ipv6Addr>().is_ok_and(|a| a.is_loopback() || a.to_ipv4_mapped().is_some_and(|v| v.is_loopback()))
}

/// At most this many forward rows are offered (a large config cannot flood the preview).
pub const MAX_FORWARD_ROWS: usize = 256;

/// One preview row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardRow {
    /// `identity#L#<normalized line>`: names the line itself, so a key ticked in the preview can
    /// only ever import that same line (a file changed after the preview gives other keys).
    pub key: String,
    pub host_identity: String,
    pub host_alias: String,
    pub kind: ForwardKind,
    /// The config line as written, e.g. `LocalForward 5432 db:5432`.
    pub line: String,
    /// Plain words, e.g. `Local port 5432 → db:5432 through acme-db`. The row's main text.
    pub description: String,
    /// What it does for someone who never used -L/-R/-D, and that it starts on connect.
    pub explain: String,
    /// Something to know before ticking (wide bind). Empty when none.
    pub warning: String,
    /// Why it cannot be imported. Empty when it can.
    pub blocked: String,
    #[serde(skip)]
    spec: Option<TunnelSpec>,
}

impl ForwardRow {
    pub fn importable(&self) -> bool {
        self.blocked.is_empty()
    }
}

fn describe(spec: &TunnelSpec, alias: &str) -> String {
    match spec {
        TunnelSpec::Local { local_port, dest_host, dest_port } => format!("Local port {local_port} → {dest_host}:{dest_port} through {alias}"),
        TunnelSpec::Remote { remote_port, local_host, local_port } if is_loopback(local_host) => {
            format!("Server port {remote_port} on {alias} → port {local_port} on this computer")
        }
        TunnelSpec::Remote { remote_port, local_host, local_port } => format!("Server port {remote_port} on {alias} → {local_host}:{local_port}, reached through this computer"),
        TunnelSpec::Dynamic { local_port } => format!("SOCKS proxy on local port {local_port} through {alias}"),
    }
}

fn explain(spec: &TunnelSpec, alias: &str) -> String {
    match spec {
        TunnelSpec::Local { local_port, .. } => format!("Apps on this computer use 127.0.0.1:{local_port} to reach that service. Opens each time you connect to {alias}."),
        TunnelSpec::Dynamic { .. } => format!("Apps set to use this proxy reach the network as {alias} does. Opens each time you connect to {alias}."),
        TunnelSpec::Remote { .. } => format!("Lets {alias} reach a service on your side. It opens on the server each time you connect, until you turn it off in the Tunnel Manager."),
    }
}

fn keyword(k: ForwardKind) -> &'static str {
    match k {
        ForwardKind::Local => "LocalForward",
        ForwardKind::Remote => "RemoteForward",
        ForwardKind::Dynamic => "DynamicForward",
    }
}

fn connections_by_identity(doc: &Document) -> HashMap<String, Uuid> {
    fn walk(f: &Folder, out: &mut HashMap<String, Uuid>) {
        for n in &f.children {
            match n {
                Node::Folder(f) => walk(f, out),
                Node::Connection(c) => {
                    if let Some(i) = c.metadata.get("SshConfigIdentity") {
                        out.entry(i.clone()).or_insert(c.id);
                    }
                }
            }
        }
    }
    let mut m = HashMap::new();
    walk(&doc.root, &mut m);
    m
}

/// Rows for every forward of `hosts`. `chosen` are keys the user has ticked so far, in order:
/// a ticked row claims its local port, so a later row on the same port shows the clash.
pub fn preview(doc: &Document, hosts: &[ResolvedHost], chosen: &[String]) -> Vec<ForwardRow> {
    let by_identity = connections_by_identity(doc);
    let mut rows: Vec<ForwardRow> = Vec::new();
    let mut keys = BTreeSet::new();
    let mut more = 0usize;
    for h in hosts {
        let lists = [(ForwardKind::Local, &h.local_forwards), (ForwardKind::Remote, &h.remote_forwards), (ForwardKind::Dynamic, &h.dynamic_forwards)];
        for (kind, list) in lists {
            for v in list {
                if rows.len() >= MAX_FORWARD_ROWS {
                    more += 1;
                    continue;
                }
                let line = format!("{} {}", keyword(kind), v.split_whitespace().collect::<Vec<_>>().join(" "));
                let key = format!("{}#{}#{}", h.identity, kind.letter(), &line[keyword(kind).len() + 1..]);
                if !keys.insert(key.clone()) {
                    continue; // the same line twice under one host is one forward
                }
                let (description, explain_text, warning, blocked, spec) = match parse(kind, v) {
                    Ok(p) => {
                        let mut warning = Vec::new();
                        if let TunnelSpec::Remote { local_host, local_port, .. } = &p.spec {
                            if !is_loopback(local_host) {
                                warning.push(format!("Lets the server reach {local_host}:{local_port} on your network through this computer."));
                            }
                        }
                        if p.wide_bind {
                            warning.push(match kind {
                                ForwardKind::Remote => "The config opens this port to the server's network; Gantry keeps it on the server's 127.0.0.1 only.".to_owned(),
                                _ => "The config opens this port to the network; Gantry keeps it on this computer only (127.0.0.1).".to_owned(),
                            });
                        }
                        let warning = warning.join(" ");
                        let blocked = by_identity
                            .get(&h.identity)
                            .and_then(|via| doc.tunnels.iter().find(|t| t.via == *via && t.spec == p.spec))
                            .map(|t| format!("Already a tunnel: “{}”.", t.name))
                            .unwrap_or_default();
                        (describe(&p.spec, &h.alias), explain(&p.spec, &h.alias), warning, blocked, Some(p.spec))
                    }
                    Err(e) => (line.clone(), String::new(), String::new(), e, None),
                };
                rows.push(ForwardRow {
                    key,
                    host_identity: h.identity.clone(),
                    host_alias: h.alias.clone(),
                    kind,
                    line,
                    description,
                    explain: explain_text,
                    warning,
                    blocked,
                    spec,
                });
            }
        }
    }
    // Port clashes: existing tunnels first, then ticked rows in the order ticked, then the rest.
    // Local ports are per computer; remote (server) ports are per connection.
    let mut taken: HashMap<u16, String> = doc.tunnels.iter().filter_map(|t| t.local_port().map(|p| (p, format!("the tunnel “{}”", t.name)))).collect();
    let mut remote_taken: HashMap<(String, u16), String> = HashMap::new();
    for (identity, via) in &by_identity {
        for t in doc.tunnels.iter().filter(|t| t.via == *via) {
            if let TunnelSpec::Remote { remote_port, .. } = t.spec {
                remote_taken.insert((identity.clone(), remote_port), format!("the tunnel “{}”", t.name));
            }
        }
    }
    let index: HashMap<&str, usize> = rows.iter().enumerate().map(|(i, r)| (r.key.as_str(), i)).collect();
    let ticked: BTreeSet<usize> = chosen.iter().filter_map(|k| index.get(k.as_str()).copied()).collect();
    let order: Vec<usize> = chosen.iter().filter_map(|k| index.get(k.as_str()).copied()).chain(0..rows.len()).collect();
    drop(index);
    let mut seen = BTreeSet::new();
    for i in order {
        if !seen.insert(i) {
            continue;
        }
        let claim = ticked.contains(&i);
        let r = &mut rows[i];
        if !r.blocked.is_empty() {
            continue;
        }
        match &r.spec {
            Some(TunnelSpec::Remote { remote_port, .. }) => {
                let k = (r.host_identity.clone(), *remote_port);
                match remote_taken.get(&k) {
                    Some(by) => r.blocked = format!("Server port {remote_port} on {} is already used by {by}.", r.host_alias),
                    None if claim => {
                        remote_taken.insert(k, format!("{} ({})", r.line, r.host_alias));
                    }
                    None => {}
                }
            }
            Some(spec) => {
                let Some(port) = local_port(spec) else { continue };
                match taken.get(&port) {
                    Some(by) => r.blocked = format!("Local port {port} is already used by {by}."),
                    None if claim => {
                        taken.insert(port, format!("{} ({})", r.line, r.host_alias));
                    }
                    None => {}
                }
            }
            None => {}
        }
    }
    if more > 0 {
        rows.push(ForwardRow {
            key: String::new(),
            host_identity: String::new(),
            host_alias: String::new(),
            kind: ForwardKind::Local,
            line: String::new(),
            description: format!("{more} more forward lines not shown"),
            explain: String::new(),
            warning: String::new(),
            blocked: format!("Only the first {MAX_FORWARD_ROWS} forward lines are offered. Add the others in the Tunnel Manager."),
            spec: None,
        });
    }
    rows
}

fn local_port(s: &TunnelSpec) -> Option<u16> {
    match s {
        TunnelSpec::Local { local_port, .. } | TunnelSpec::Dynamic { local_port } => Some(*local_port),
        TunnelSpec::Remote { .. } => None,
    }
}

/// Create a tunnel for each ticked, importable row. The rows are recomputed here, so a clash
/// that appeared after the preview is refused, not created, and a key names its exact line, so a
/// line that changed on disk after the preview is not imported at all. Hosts must be imported
/// first. Fewer created than ticked means the user should look at the preview again.
/// Returns the number of tunnels created.
pub fn import(doc: &mut Document, hosts: &[ResolvedHost], keys: &[String]) -> Result<u32> {
    let rows = preview(doc, hosts, keys);
    let by_identity = connections_by_identity(doc);
    let mut created = 0;
    let wanted: BTreeSet<&String> = keys.iter().collect();
    for r in rows.into_iter().filter(|r| wanted.contains(&r.key) && r.importable()) {
        let (Some(spec), Some(via)) = (r.spec, by_identity.get(&r.host_identity).copied()) else { continue };
        let base = format!("{} {}{}", r.host_alias, r.kind.letter(), match &spec {
            TunnelSpec::Local { local_port, .. } | TunnelSpec::Dynamic { local_port } => *local_port,
            TunnelSpec::Remote { remote_port, .. } => *remote_port,
        });
        let name = (1..).map(|n| if n == 1 { base.clone() } else { format!("{base} {n}") }).find(|n| !doc.tunnels.iter().any(|t| t.name.eq_ignore_ascii_case(n))).unwrap_or(base);
        tunneldefs::put(doc, TunnelDef { id: Uuid::new_v4(), name, via, spec, start_with_connection: true })?;
        created += 1;
    }
    Ok(created)
}

/// Config lines for the auto-start tunnels on `via` (export round trip). On-demand tunnels are
/// left out: OpenSSH would open them on every connect.
/// Forward lines for export, and the reasons for any left out.
#[derive(Debug, Default)]
pub struct ExportLines {
    pub local: Vec<String>,
    pub remote: Vec<String>,
    pub dynamic: Vec<String>,
    /// A tunnel whose host ssh_config could misread (whitespace, `%` tokens, quotes, a leading `-`)
    /// is left out, with this reason; the host block itself is still written.
    pub skipped: Vec<String>,
}

pub fn export_lines(doc: &Document, via: Uuid) -> ExportLines {
    let mut out = ExportLines::default();
    let safe = |h: &str| !(h.is_empty() || h.starts_with('-') || h.chars().any(|c| c.is_whitespace() || c.is_control() || matches!(c, '%' | '"' | '#' | '\'')));
    for t in tunneldefs::starting_with(doc, via) {
        let host = match &t.spec {
            TunnelSpec::Local { dest_host, .. } => Some(dest_host),
            TunnelSpec::Remote { local_host, .. } => Some(local_host),
            TunnelSpec::Dynamic { .. } => None,
        };
        if let Some(h) = host.filter(|h| !safe(h)) {
            out.skipped.push(format!("tunnel {} left out: ssh_config cannot hold the host {h:?}", t.name));
            continue;
        }
        match &t.spec {
            TunnelSpec::Local { local_port, dest_host, dest_port } => out.local.push(format!("{local_port} {}:{dest_port}", bracket(dest_host))),
            TunnelSpec::Remote { remote_port, local_host, local_port } => out.remote.push(format!("{remote_port} {}:{local_port}", bracket(local_host))),
            TunnelSpec::Dynamic { local_port } => out.dynamic.push(local_port.to_string()),
        }
    }
    out
}

fn bracket(h: &str) -> String {
    if h.contains(':') { format!("[{h}]") } else { h.to_owned() }
}

#[cfg(test)]
#[path = "sshforwards_tests.rs"]
mod tests;
