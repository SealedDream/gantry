//! The plugin component (feature `plugin`): a read-only dashboard of the server's guests, and
//! connect to the selected guest by SSH, RDP or VNC through the app (`open.connection`), and
//! save selected guests as library connections (`library.propose`).
//!
//! Every request goes through the core's `http.send` with `with-login`: the core adds the
//! entry's API token as `Authorization: PVEAPIToken=…` (manifest `[http] auth`), so this code
//! never sees it. The entry is read-only unless its "Allow changes (snapshots)" field is on;
//! then Take, Rollback and Delete Snapshot are offered in the tree, each confirmed first
//! (`ui.confirm`). Power actions come later.

use std::cell::RefCell;
use std::rc::Rc;

use bastion_plugin_sdk::bindings::bastion::plugin::events::{ChildrenAsk, RowsAsk};
use bastion_plugin_sdk::bindings::bastion::plugin::ui::{Cell, Row};
use bastion_plugin_sdk::http::{self as http, Method};
use bastion_plugin_sdk::library;
use bastion_plugin_sdk::open::{self, Protocol};
use bastion_plugin_sdk::bindings::bastion::plugin::ui::TreeItem;
use bastion_plugin_sdk::ui::{self, BannerLevel, Component, ConfirmKind, Tone, ViewBuilder};
use bastion_plugin_sdk::{host, log, task, Failure, Input, NodeId, Plugin, Task, View};

use crate::api::{calls, Access, Call, Error};
use crate::model::{Guest, Node, PowerState};
use crate::snapshots::{self as snaps, Key};
use crate::Response;

/// Node ids of the dashboard, in the order [`dashboard`] adds them.
pub const TOOLBAR: NodeId = 1;
pub const REFRESH: NodeId = 2;
/// Connect to the selected guest (PLUG-PVE-02).
pub const SSH: NodeId = 3;
pub const RDP: NodeId = 4;
pub const VNC: NodeId = 5;
pub const SUMMARY: NodeId = 6;
/// One line for connect outcomes (a warning, an error, or empty); never touches the node cards.
pub const MESSAGE: NodeId = 7;
/// A banner, a busy mark, or the row of node cards.
pub const STATUS: NodeId = 8;
pub const TABLE: NodeId = 9;
/// The node → guest → snapshot tree (PVE-SNAP).
pub const TREE: NodeId = 10;
/// Save the selected guests as library connections (`library.propose`, API 1.6). Added after
/// the table and the tree so the ids above stay as they were; it sits at the toolbar's end.
pub const SAVE: NodeId = 11;
/// Guests one Save as Connection proposes at most (the core's cap).
pub const MAX_SAVE: usize = 100;

pub const COLUMNS: [&str; 7] = ["Name", "ID", "Node", "Type", "CPU", "Memory", "Uptime"];

/// The read-only dashboard: a toolbar with the server summary, a row of four tiles (guests,
/// CPU, memory, nodes; API 1.6 `stat`), and the guest table.
/// `status` is a banner or a busy mark; with `nodes` it is replaced by the tiles.
pub fn dashboard(summary: &str, status: Component, nodes: &[Node], rows: usize) -> Vec<ui::Node> {
    dashboard_with(summary, status, nodes, &[], rows, false)
}

/// The connect buttons; enabled only while a guest is selected.
pub fn connect_buttons(enabled: bool) -> [(NodeId, Component); 3] {
    [(SSH, ui::icon_button("SSH", "ssh", enabled)), (RDP, ui::icon_button("RDP", "rdp", enabled)), (VNC, ui::icon_button("VNC", "vnc", enabled))]
}

/// Save as Connection; enabled while at least one guest is selected.
pub fn save_button(enabled: bool) -> Component {
    ui::icon_button("Save as Connection…", "folder-add", enabled)
}

/// What a guest is proposed as: its name, the address when known, and SSH unless the OS hint
/// says Windows (RDP). The user can change each in the app's sheet.
pub fn proposal(g: &Guest, host: Option<std::net::IpAddr>, os: Option<&str>) -> library::Proposal {
    let protocol = if os == Some("windows") { library::Protocol::Rdp } else { library::Protocol::Ssh };
    let label: String = display_name(g).chars().take(128).collect();
    let label = label.trim().to_string();
    library::Proposal { label: if label.is_empty() { format!("Guest {}", g.vmid) } else { label }, host: host.map(|ip| ip.to_string()), protocol, os_hint: os.map(str::to_string) }
}

/// [`dashboard`] with the guests for the tiles and the connect buttons enabled when `connectable`.
pub fn dashboard_with(summary: &str, status: Component, nodes: &[Node], guests: &[Guest], rows: usize, connectable: bool) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, Component::Toolbar), TOOLBAR);
    assert_eq!(b.add(TOOLBAR, ui::icon_button("Refresh", "refresh", true)), REFRESH);
    for (id, button) in connect_buttons(connectable) {
        assert_eq!(b.add(TOOLBAR, button), id);
    }
    assert_eq!(b.add(TOOLBAR, ui::label(summary)), SUMMARY);
    assert_eq!(b.add(root, ui::label("")), MESSAGE);
    let status = if nodes.is_empty() { status } else { ui::row() };
    assert_eq!(b.add(root, status), STATUS);
    let mut table = ui::table(&COLUMNS);
    if let Component::Table(t) = &mut table {
        t.total_rows = Some(rows as u64);
    }
    assert_eq!(b.add(root, table), TABLE);
    assert_eq!(b.add(root, snaps::tree()), TREE);
    assert_eq!(b.add(TOOLBAR, save_button(connectable)), SAVE);
    if !nodes.is_empty() {
        for tile in tiles(nodes, guests) {
            b.add(STATUS, tile);
        }
    }
    b.finish()
}

/// The four tiles: guests running, cluster CPU, cluster memory, nodes online. Only usage tiles
/// have a bar (a bar turns red near full, which is wrong for "all online"). Values stay under
/// 32 characters.
pub fn tiles(nodes: &[Node], guests: &[Guest]) -> [Component; 4] {
    let online: Vec<&Node> = nodes.iter().filter(|n| n.status == "online").collect();
    let listed: Vec<&Guest> = guests.iter().filter(|g| !g.is_template()).collect();
    let running = listed.iter().filter(|g| g.power() == PowerState::Running).count();
    let cores: u64 = online.iter().map(|n| n.maxcpu).sum();
    let cpu = if cores == 0 { 0.0 } else { online.iter().map(|n| n.cpu * n.maxcpu as f64).sum::<f64>() / cores as f64 };
    let (mem, maxmem) = online.iter().fold((0u64, 0u64), |(u, t), n| (u.saturating_add(n.mem), t.saturating_add(n.maxmem)));
    let stopped = listed.len() - running;
    [
        ui::stat("Guests", &format!("{running} / {}", listed.len()), &format!("{stopped} stopped"), None),
        ui::stat("CPU", &format!("{:.0}%", cpu * 100.0), &format!("{cores} cores"), Some(cpu.clamp(0.0, 1.0) as f32)),
        ui::stat("Memory", &format!("{:.1} / {}", gib_f(mem), gib(maxmem)), &format!("{:.0}% used", ratio(mem, maxmem) * 100.0), Some(ratio(mem, maxmem))),
        ui::stat("Nodes", &format!("{} / {} online", online.len(), nodes.len()), &node_names(nodes), None),
    ]
}

/// The node names for the Nodes tile, cut to fit one line.
fn node_names(nodes: &[Node]) -> String {
    let all = nodes.iter().map(|n| n.node.as_str()).collect::<Vec<_>>().join(", ");
    if all.chars().count() <= 40 { all } else { format!("{}…", all.chars().take(39).collect::<String>()) }
}

fn ratio(used: u64, total: u64) -> f32 {
    if total == 0 { 0.0 } else { (used as f64 / total as f64).clamp(0.0, 1.0) as f32 }
}

fn gib_f(bytes: u64) -> f64 {
    bytes as f64 / (1u64 << 30) as f64
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", gib_f(bytes))
}

/// Uptime as the console shows it: days and hours, or hours and minutes.
pub fn uptime(secs: u64) -> String {
    let (d, h, m) = (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60);
    match (secs, d) {
        (0, _) => "—".into(),
        (_, 0) => format!("{h} h {m} m"),
        _ => format!("{d} d {h} h"),
    }
}

/// The guests the table shows: templates are left out.
pub fn listed(guests: Vec<Guest>) -> Vec<Guest> {
    guests.into_iter().filter(|g| !g.is_template()).collect()
}

/// A row's key: `node/vmid`.
pub fn key(g: &Guest) -> String {
    format!("{}/{}", g.node, g.vmid)
}

/// One table row per guest, by node then ID; templates are left out.
pub fn rows(guests: &[Guest]) -> Vec<Row> {
    let mut list: Vec<&Guest> = guests.iter().filter(|g| !g.is_template()).collect();
    list.sort_by(|a, b| (a.node.as_str(), a.vmid).cmp(&(b.node.as_str(), b.vmid)));
    list.into_iter()
        .map(|g| {
            let running = g.power() == PowerState::Running;
            let tone = match g.power() {
                PowerState::Running => Tone::Good,
                PowerState::Paused => Tone::Warning,
                PowerState::Stopped => Tone::Off,
                PowerState::Unknown => Tone::Neutral,
            };
            let kind = match g.kind {
                Some(crate::model::GuestKind::Qemu) => "VM",
                Some(crate::model::GuestKind::Lxc) => "CT",
                None => "",
            };
            let memory = if running { format!("{:.1} / {}", gib_f(g.mem), gib(g.maxmem)) } else { format!("— / {}", gib(g.maxmem)) };
            Row {
                key: key(g),
                cells: vec![
                    ui::status_cell(tone, &display_name(g)),
                    Cell::Number(g.vmid as f64),
                    Cell::Text(g.node.clone()),
                    Cell::Text(kind.into()),
                    Cell::Text(if running { format!("{:.0}%", g.cpu * 100.0) } else { "—".into() }),
                    ui::meter_cell(if running { ratio(g.mem, g.maxmem) } else { 0.0 }, &memory),
                    Cell::Text(uptime(if running { g.uptime } else { 0 })),
                ],
            }
        })
        .collect()
}

/// Runs one read through the core's `http.send`, with the entry's login.
pub async fn run<R>(c: Call<R>) -> Result<R, Error> {
    run_as(c, Access::ReadOnly).await
}

/// Whether the entry allows snapshot changes. Off unless the field says `true`.
pub fn may_change() -> bool {
    host::entry().is_some_and(|e| e.fields.iter().any(|(k, v)| k == snaps::ALLOW_CHANGES && v == "true"))
}

fn access() -> Access {
    if may_change() { Access::MayChange } else { Access::ReadOnly }
}

/// Runs one call; a change is refused before anything is sent unless `access` allows it.
pub async fn run_as<R>(c: Call<R>, access: Access) -> Result<R, Error> {
    c.check(access)?;
    let method = match c.request.method {
        crate::Method::Get => Method::Get,
        crate::Method::Post => Method::Post,
        crate::Method::Delete => Method::Delete,
    };
    let mut req = http::request(method, &c.request.target);
    req.headers.push(("Accept".into(), "application/json".into()));
    if !c.request.form.is_empty() {
        req.headers.push(("Content-Type".into(), "application/x-www-form-urlencoded".into()));
        req.body = c.request.body().into_bytes();
    }
    req.with_login = true;
    req.timeout_ms = Some(20_000);
    let resp = http::send(&req).await.map_err(|f| Error::Transport(describe(&f)))?;
    c.finish(Response { status: resp.status, body: resp.body })
}

pub fn describe(failure: &Failure) -> String {
    match failure {
        Failure::Denied(why) | Failure::Invalid(why) | Failure::Io(why) => why.clone(),
        Failure::TimedOut => "The server did not answer in time.".into(),
        Failure::Cancelled => "Cancelled.".into(),
    }
}

/// The login works but sees no node: it lacks Sys.Audit (PVEAuditor) on `/`.
pub const NO_NODES: &str = "Login sees no nodes: it lacks Sys.Audit. Give the user (and a privilege-separated token) PVEAuditor on /.";

/// What the user sees when a call fails, in plain words.
pub fn message(e: &Error) -> String {
    match e {
        // A token login is `user@realm!token-id` with the token's secret as the password; a
        // user name without `!` is a password, which this type does not send.
        Error::Status(401, _) => "Login refused. API token: user is user@realm!token-id, password is the secret. For a user password, use Proxmox VE (password).".into(),
        Error::Status(403, _) => "Login lacks a privilege. Give the user (and a privilege-separated token) PVEAuditor on /.".into(),
        Error::Status(code, text) if text.is_empty() => format!("The server answered {code}."),
        Error::Status(code, text) => format!("The server answered {code}: {text}"),
        Error::Parse(_) => "The server's answer was not what Proxmox VE sends.".into(),
        Error::Transport(why) | Error::Refused(why) => why.clone(),
    }
}

fn protocol_name(p: Protocol) -> &'static str {
    match p {
        Protocol::Ssh => "SSH",
        Protocol::Rdp => "RDP",
        Protocol::Vnc => "VNC",
    }
}

/// Why a guest cannot be connected to yet, in plain words; `None` when it can.
pub fn not_connectable(g: Option<&Guest>) -> Option<String> {
    match g {
        None => Some("Select a guest first.".into()),
        Some(g) if g.power() != PowerState::Running => Some(format!("{} is not running.", display_name(g))),
        Some(g) if g.kind.is_none() => Some(format!("{} is not a VM or container.", display_name(g))),
        Some(_) => None,
    }
}

fn display_name(g: &Guest) -> String {
    if g.name.is_empty() { format!("Guest {}", g.vmid) } else { g.name.clone() }
}

/// What the user sees when the address cannot be read.
pub fn address_message(e: &Error) -> String {
    match e {
        // Proxmox answers 500 "QEMU guest agent is not running" when the agent is off.
        Error::Status(500, text) if text.to_ascii_lowercase().contains("agent") => {
            "The QEMU guest agent is not running in this guest, so its address is unknown.".into()
        }
        // The guest-agent call needs a privilege PVEAuditor does not have (owner's lab, 2026-11-21).
        Error::Status(403, _) => "Login lacks VM.GuestAgent.Audit (PVE 9) or VM.Monitor (PVE 8) for guest-agent addresses.".into(),
        other => message(other),
    }
}

#[derive(Default)]
pub struct Proxmox {
    rows: RefCell<Vec<Row>>,
    guests: RefCell<Vec<Guest>>,
    selected: RefCell<Vec<String>>,
}

impl Proxmox {
    fn show_message(&self, view: &View, message: Component) {
        let _ = view.patch(vec![ui::Node { id: MESSAGE, parent: Some(0), component: message }], vec![]);
    }

    fn selected_guest(&self) -> Option<Guest> {
        let sel = self.selected.borrow();
        let sel = sel.first()?;
        self.guests.borrow().iter().find(|g| key(g) == *sel).cloned()
    }

    fn selected_guests(&self) -> Vec<Guest> {
        let sel = self.selected.borrow();
        let guests = self.guests.borrow();
        sel.iter().filter_map(|k| guests.iter().find(|g| key(g) == *k).cloned()).take(MAX_SAVE).collect()
    }

    /// Proposes the selected guests to the app's Save as Connection sheet. Addresses come from
    /// the guest agent or the container's interfaces when the guest runs; the OS hint from its
    /// config. Either may be missing: the user fills it in the sheet. Nothing is written to the
    /// server; the plugin learns only how many connections the user saved.
    async fn save_connections(self: Rc<Self>, view: View) {
        let guests = self.selected_guests();
        if guests.is_empty() {
            return self.show_message(&view, ui::banner(BannerLevel::Warning, "Select a guest first."));
        }
        let mut proposals = Vec::with_capacity(guests.len());
        for g in &guests {
            let Some(kind) = g.kind else { continue };
            let host = if g.power() == PowerState::Running {
                match calls::address(&g.node, kind, g.vmid) {
                    Ok(c) => run(c).await.ok().flatten(),
                    Err(_) => None,
                }
            } else {
                None
            };
            let os = match calls::os_family(&g.node, kind, g.vmid) {
                Ok(c) => run(c).await.ok().flatten(),
                Err(_) => None,
            };
            proposals.push(proposal(g, host, os));
        }
        match library::propose(&proposals).await {
            Ok(0) => self.show_message(&view, ui::label("")),
            Ok(n) => self.show_message(&view, ui::label(&format!("Saved {n} connection{}.", if n == 1 { "" } else { "s" }))),
            Err(Failure::Cancelled) => self.show_message(&view, ui::label("")),
            Err(f) => self.show_message(&view, ui::banner(BannerLevel::Error, &format!("Save as Connection: {}", describe(&f)))),
        }
    }

    /// Reads the selected guest's address from the server, then asks the app to open it.
    /// The address comes from the guest agent (QEMU) or the container's interfaces (LXC);
    /// the core checks it and the user confirms it in the app's sheet.
    async fn connect(self: Rc<Self>, view: View, protocol: Protocol) {
        let guest = self.selected_guest();
        if let Some(why) = not_connectable(guest.as_ref()) {
            return self.show_message(&view, ui::banner(BannerLevel::Warning, &why));
        }
        let Some(g) = guest else { return };
        let Some(kind) = g.kind else { return };
        let address = match calls::address(&g.node, kind, g.vmid) {
            Ok(c) => run(c).await,
            Err(e) => Err(e),
        };
        let ip = match address {
            Ok(Some(ip)) => ip,
            Ok(None) => {
                let why = format!("{} reports no usable address.", display_name(&g));
                return self.show_message(&view, ui::banner(BannerLevel::Warning, &why));
            }
            Err(e) => return self.show_message(&view, ui::banner(BannerLevel::Error, &address_message(&e))),
        };
        let label = format!("{} ({}/{})", display_name(&g), g.node, g.vmid);
        let label: String = label.chars().take(128).collect();
        match open::connection(&open::request(protocol, &ip.to_string(), &label)).await {
            Ok(_) => self.show_message(&view, ui::label("")),
            Err(f) => {
                let why = format!("{} to {}: {}", protocol_name(protocol), display_name(&g), describe(&f));
                self.show_message(&view, ui::banner(BannerLevel::Error, &why));
            }
        }
    }

    /// A guest from the last listing, else from a fresh one (the tree can be used before the table loads).
    async fn guest(&self, node: &str, vmid: u64) -> Result<Guest, Error> {
        let find = |list: &[Guest]| list.iter().find(|g| g.node == node && g.vmid == vmid && g.kind.is_some()).cloned();
        if let Some(g) = find(&self.guests.borrow()) {
            return Ok(g);
        }
        let list = listed(run(calls::guests()).await?);
        let found = find(&list);
        *self.guests.borrow_mut() = list;
        found.ok_or_else(|| Error::Refused(format!("Guest {vmid} is not on {node}.")))
    }

    /// The tree's children: nodes at the root, then guests, then their snapshots.
    async fn children_of(self: Rc<Self>, parent: Option<String>) -> Result<Vec<TreeItem>, Error> {
        let Some(parent) = parent else {
            let guests = listed(run(calls::guests()).await?);
            *self.guests.borrow_mut() = guests.clone();
            return Ok(snaps::node_items(&guests));
        };
        match snaps::parse(&parent) {
            Some(Key::Node(node)) => Ok(snaps::guest_items(&self.guests.borrow(), &node, may_change())),
            Some(Key::Guest(node, vmid)) => {
                let kind = self.guest(&node, vmid).await?.kind.unwrap_or(crate::model::GuestKind::Qemu);
                let list = run(calls::snapshots(&node, kind, vmid)?).await?;
                Ok(snaps::snapshot_items(&node, vmid, &list, may_change()))
            }
            _ => Err(Error::Refused("not a tree item".into())),
        }
    }

    /// A change: refused at once on a read-only entry, else confirmed, then sent.
    async fn change(&self, prompt: String, c: Call<String>, done: String) -> Result<Option<String>, Error> {
        c.check(access())?;
        if !ui::confirm(ConfirmKind::Other, &prompt).await.map_err(|f| Error::Transport(describe(&f)))? {
            return Ok(None);
        }
        run_as(c, access()).await?;
        Ok(Some(done))
    }

    async fn snapshot_action(&self, key: &str, id: &str) -> Result<Option<String>, Error> {
        match (snaps::parse(key), id) {
            (Some(Key::Guest(node, vmid)), snaps::TAKE) => {
                let g = self.guest(&node, vmid).await?;
                let kind = g.kind.unwrap_or(crate::model::GuestKind::Qemu);
                // A read-only entry is refused before the list is read for a free name.
                calls::take_snapshot(&node, kind, vmid, "gantry-1", "")?.check(access())?;
                let existing = run(calls::snapshots(&node, kind, vmid)?).await?;
                let snap = snaps::next_name(&existing);
                let name = snaps::guest_name(&g);
                let c = calls::take_snapshot(&node, kind, vmid, &snap, "Taken in Gantry")?;
                self.change(snaps::take_prompt(&name, &snap, kind), c, format!("Snapshot {snap} of {name} started.")).await
            }
            (Some(Key::Snapshot(node, vmid, snap)), snaps::ROLLBACK | snaps::DELETE) => {
                let g = self.guest(&node, vmid).await?;
                let kind = g.kind.unwrap_or(crate::model::GuestKind::Qemu);
                let name = snaps::guest_name(&g);
                if id == snaps::ROLLBACK {
                    self.change(snaps::rollback_prompt(&name, &snap), calls::rollback(&node, kind, vmid, &snap)?, format!("Rollback of {name} started.")).await
                } else {
                    self.change(snaps::delete_prompt(&name, &snap), calls::delete_snapshot(&node, kind, vmid, &snap)?, format!("Deleting snapshot {snap} of {name}.")).await
                }
            }
            _ => Err(Error::Refused("Not available for this item.".into())),
        }
    }

    async fn menu(self: Rc<Self>, view: View, key: String, id: String) {
        match self.snapshot_action(&key, &id).await {
            Ok(Some(text)) => {
                self.clone().refresh(view).await;
                self.show_message(&view, ui::label(&text));
            }
            Ok(None) => {}
            Err(e) => self.show_message(&view, ui::banner(BannerLevel::Error, &message(&e))),
        }
    }

    async fn refresh(self: Rc<Self>, view: View) {
        // The tiles hang under STATUS, so the busy mark goes in the toolbar text.
        let _ = view.patch(vec![ui::Node { id: SUMMARY, parent: Some(TOOLBAR), component: ui::label("Refreshing") }], vec![]);
        let result = async {
            let version = run(calls::version()).await?;
            let nodes = run(calls::nodes()).await?;
            let guests = run(calls::guests()).await?;
            Ok::<_, Error>((version, nodes, guests))
        }
        .await;
        let nodes_view;
        let (summary, status, rows) = match result {
            Ok((v, mut nodes, guests)) => {
                let guests = listed(guests);
                let rows = rows(&guests);
                *self.guests.borrow_mut() = guests.clone();
                let running = guests.iter().filter(|g| !g.is_template() && g.power() == PowerState::Running).count();
                let release = v.get("release").and_then(|r| r.as_str()).unwrap_or("?");
                let release: String = release.chars().take(8).collect();
                nodes.sort_by(|a, b| a.node.cmp(&b.node));
                let summary = format!("Proxmox VE {release} · {} of {} running", running, rows.len());
                nodes_view = nodes;
                // A privilege-separated token with no ACL of its own, or a user without
                // Sys.Audit/VM.Audit, gets 200 and empty lists, not 403.
                let status = if nodes_view.is_empty() { ui::banner(BannerLevel::Warning, NO_NODES) } else { ui::label("") };
                (summary, status, rows)
            }
            Err(e) => {
                log::warn("refresh failed");
                nodes_view = Vec::new();
                self.guests.borrow_mut().clear();
                (String::new(), ui::banner(BannerLevel::Error, &message(&e)), Vec::new())
            }
        };
        let count = rows.len();
        *self.rows.borrow_mut() = rows;
        let connectable = self.selected_guest().is_some();
        if let Err(e) = view.set(dashboard_with(&summary, status, &nodes_view, &self.guests.borrow(), count, connectable)) {
            log::error(&format!("view refused: {e:?}"));
        }
    }
}

impl Plugin for Proxmox {
    fn start() -> Self {
        Proxmox::default()
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        task(async move {
            let _ = view.set(dashboard("Loading", Component::Progress(None), &[], 0));
            self.refresh(view).await;
        })
    }

    fn command(self: Rc<Self>, id: String, view: Option<View>) -> Task {
        match (id.as_str(), view) {
            ("refresh" | "refresh-password", Some(view)) => task(self.refresh(view)),
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        match (node, input) {
            (REFRESH, Input::Pressed) => task(self.refresh(view)),
            (SSH, Input::Pressed) => task(self.connect(view, Protocol::Ssh)),
            (RDP, Input::Pressed) => task(self.connect(view, Protocol::Rdp)),
            (VNC, Input::Pressed) => task(self.connect(view, Protocol::Vnc)),
            (SAVE, Input::Pressed) => task(self.save_connections(view)),
            (TREE, Input::Menu((key, id))) => task(self.menu(view, key, id)),
            (TABLE, Input::Selected(keys)) => {
                *self.selected.borrow_mut() = keys;
                let enabled = self.selected_guest().is_some();
                let mut upsert: Vec<ui::Node> = connect_buttons(enabled).into_iter().map(|(id, component)| ui::Node { id, parent: Some(TOOLBAR), component }).collect();
                upsert.push(ui::Node { id: SAVE, parent: Some(TOOLBAR), component: save_button(enabled) });
                if let Err(e) = view.patch(upsert, vec![]) {
                    log::error(&format!("view refused: {e:?}"));
                }
                bastion_plugin_sdk::done()
            }
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn children(self: Rc<Self>, ask: ChildrenAsk) -> Task {
        task(async move {
            match self.children_of(ask.parent).await {
                Ok(items) => {
                    let _ = ui::provide_children(ask.ask, &items);
                }
                Err(e) => ui::refuse(ask.ask, &message(&e)),
            }
        })
    }

    fn rows(self: Rc<Self>, ask: RowsAsk) -> Task {
        let all = self.rows.borrow();
        let start = (ask.offset as usize).min(all.len());
        let end = start.saturating_add(ask.count as usize).min(all.len()).min(start + ui::MAX_ROWS);
        let _ = ui::provide_rows(ask.ask, &all[start..end], Some(all.len() as u64));
        bastion_plugin_sdk::done()
    }
}

#[cfg(target_arch = "wasm32")]
bastion_plugin_sdk::export_plugin!(Proxmox);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_403_names_what_the_token_lacks() {
        assert!(message(&Error::Status(403, String::new())).contains("PVEAuditor on /"));
        let agent = address_message(&Error::Status(403, "{\"data\":null}".into()));
        assert!(agent.contains("VM.GuestAgent.Audit") && agent.contains("VM.Monitor") && !agent.contains("PVEAuditor"), "{agent}");
    }
    use bastion_plugin_sdk::bindings::bastion::plugin::events::{Event, OpenView, ReplyValue, UiEvent};
    use bastion_plugin_sdk::bindings::bastion::plugin::types::HttpResponse;
    use bastion_plugin_sdk::testing::{reply, run_plugin, Call as CoreCall, FakeCore};

    const RESOURCES: &str = r#"{"data":[
      {"vmid":201,"name":"web","node":"pve1","type":"qemu","status":"running","cpu":0.25,"mem":1073741824,"maxmem":2147483648},
      {"vmid":202,"name":"dns","node":"pve1","type":"lxc","status":"stopped","maxmem":536870912},
      {"vmid":9000,"name":"tmpl","node":"pve1","type":"qemu","status":"stopped","template":1}
    ]}"#;

    const NODES: &str = r#"{"data":[{"node":"pve1","status":"online","cpu":0.12,"maxcpu":8,"mem":4294967296,"maxmem":17179869184,"uptime":90000}]}"#;

    fn node(name: &str, online: bool) -> Node {
        Node { node: name.into(), status: if online { "online" } else { "offline" }.into(), cpu: 0.5, maxcpu: 4, mem: 1, maxmem: 2, uptime: 1 }
    }

    fn ok(body: &str) -> Result<ReplyValue, Failure> {
        Ok(ReplyValue::Http(HttpResponse { status: 200, headers: vec![], body: body.as_bytes().to_vec() }))
    }

    fn server(id: u32, call: &CoreCall) -> Vec<Event> {
        match call {
            CoreCall::HttpSend(r) if r.target == "/api2/json/version" => vec![reply(id, ok(r#"{"data":{"release":"8.3"}}"#))],
            CoreCall::HttpSend(r) if r.target == "/api2/json/cluster/resources?type=vm" => vec![reply(id, ok(RESOURCES))],
            CoreCall::HttpSend(r) if r.target == "/api2/json/nodes" => vec![reply(id, ok(NODES))],
            CoreCall::HttpSend(_) => vec![reply(id, Ok(ReplyValue::Http(HttpResponse { status: 404, headers: vec![], body: vec![] })))],
            _ => vec![],
        }
    }

    fn last_view(core: &FakeCore) -> Vec<ui::Node> {
        core.plain_calls().into_iter().rev().find_map(|c| match c {
            CoreCall::SetView(_, nodes) => Some(nodes.clone()),
            _ => None,
        }).expect("a view")
    }

    #[test]
    fn the_dashboard_passes_the_checks() {
        assert_eq!(ui::check(&dashboard("Loading", Component::Progress(None), &[], 0)), Ok(()));
        assert_eq!(ui::check(&dashboard("Not loaded", ui::banner(BannerLevel::Error, &"x".repeat(500)), &[], 10_000)), Ok(()));
        let many: Vec<Node> = (0..40).map(|i| node(&format!("{}{i}", "n".repeat(40)), i % 3 != 0)).collect();
        let view = dashboard("Proxmox VE 8.3 · 0 of 0 running", ui::label(""), &many, 0);
        assert_eq!(ui::check(&view), Ok(()));
        assert!(matches!(view[STATUS as usize].component, Component::Stack(_)));
        let tiles = view.iter().filter(|n| n.parent == Some(STATUS)).count();
        assert_eq!(tiles, 4, "guests, CPU, memory, nodes");
    }

    #[test]
    fn a_login_that_sees_no_nodes_gets_a_warning() {
        // A privilege-separated token with no ACL: every call answers 200 with empty lists.
        let empty = |id: u32, call: &CoreCall| match call {
            CoreCall::HttpSend(r) if r.target == "/api2/json/version" => vec![reply(id, ok(r#"{"data":{"release":"8.3"}}"#))],
            CoreCall::HttpSend(_) => vec![reply(id, ok(r#"{"data":[]}"#))],
            _ => vec![],
        };
        let core = run_plugin::<Proxmox>(FakeCore::new().respond(empty).with(Event::OpenView(OpenView { view: 1, name: "pve".into() })));
        let view = last_view(&core);
        assert!(matches!(&view[STATUS as usize].component, Component::Banner(b) if b.level == BannerLevel::Warning && b.text == NO_NODES), "{:?}", view[STATUS as usize]);
    }

    #[test]
    fn opening_reads_the_guests_through_the_core_with_the_login() {
        let core = run_plugin::<Proxmox>(FakeCore::new().respond(server).with(Event::OpenView(OpenView { view: 1, name: "pve".into() })));
        let sent: Vec<_> = core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::HttpSend(r) => Some(r.clone()),
            _ => None,
        }).collect();
        assert_eq!(sent.iter().map(|r| r.target.as_str()).collect::<Vec<_>>(), vec!["/api2/json/version", "/api2/json/nodes", "/api2/json/cluster/resources?type=vm"]);
        for r in &sent {
            assert_eq!(r.method, Method::Get);
            assert!(r.with_login, "the core adds the token");
            assert!(r.body.is_empty());
            assert!(r.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("authorization")), "the plugin never sets the token");
        }
        let view = last_view(&core);
        assert!(matches!(&view[SUMMARY as usize].component, Component::Label(t) if t == "Proxmox VE 8.3 · 1 of 2 running"), "{:?}", view[SUMMARY as usize]);
        assert!(matches!(view[STATUS as usize].component, Component::Stack(_)));
        let tile: Vec<_> = view.iter().filter(|n| n.parent == Some(STATUS)).map(|n| &n.component).collect();
        assert!(matches!(tile[0], Component::Stat(t) if t.title == "Guests" && t.value == "1 / 2" && t.detail == "1 stopped"), "{:?}", tile[0]);
        assert!(matches!(tile[1], Component::Stat(t) if t.value == "12%" && t.detail == "8 cores" && (t.fraction.unwrap() - 0.12).abs() < 1e-6));
        assert!(matches!(tile[2], Component::Stat(t) if t.value == "4.0 / 16.0 GiB" && (t.fraction.unwrap() - 0.25).abs() < 1e-6));
        assert!(matches!(tile[3], Component::Stat(t) if t.value == "1 / 1 online" && t.detail == "pve1"));
        assert!(matches!(&view[TABLE as usize].component, Component::Table(t) if t.total_rows == Some(2)));
    }

    #[test]
    fn rows_leave_out_templates_and_page() {
        let guests: Vec<Guest> = serde_json::from_str::<crate::model::Envelope<Vec<Guest>>>(RESOURCES).unwrap().data.unwrap();
        let r = rows(&guests);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].key, "pve1/201");
        assert!(matches!(&r[0].cells[0], Cell::Status(s) if s.tone == Tone::Good), "name first, with a state dot");
        assert!(matches!(&r[1].cells[0], Cell::Status(s) if s.tone == Tone::Off), "a stopped guest is dimmed");
        assert!(matches!(&r[0].cells[3], Cell::Text(t) if t == "VM"));
        assert!(matches!(&r[1].cells[4], Cell::Text(t) if t == "—"), "a stopped guest shows no CPU");
        assert!(matches!(&r[1].cells[5], Cell::Meter(m) if m.text == "— / 0.5 GiB" && m.fraction == 0.0));
        assert!(matches!(&r[0].cells[4], Cell::Text(t) if t == "25%"));
        assert!(matches!(&r[0].cells[5], Cell::Meter(m) if m.text == "1.0 / 2.0 GiB" && (m.fraction - 0.5).abs() < 1e-6));
    }

    #[test]
    fn uptime_reads_like_the_console() {
        assert_eq!(uptime(0), "—");
        assert_eq!(uptime(3_660), "1 h 1 m");
        assert_eq!(uptime(18 * 86_400 + 4 * 3_600), "18 d 4 h");
    }

    #[test]
    fn a_refused_token_shows_a_banner_in_plain_words() {
        let core = run_plugin::<Proxmox>(
            FakeCore::new()
                .respond(|id, c| match c {
                    CoreCall::HttpSend(_) => vec![reply(id, Ok(ReplyValue::Http(HttpResponse { status: 401, headers: vec![], body: b"authentication failure".to_vec() })))],
                    _ => vec![],
                })
                .with(Event::OpenView(OpenView { view: 1, name: "pve".into() })),
        );
        let view = last_view(&core);
        assert!(matches!(&view[STATUS as usize].component, Component::Banner(b) if b.text.starts_with("Login refused.")));
        // A login the core cannot give is passed on as the core's words.
        let core = run_plugin::<Proxmox>(
            FakeCore::new()
                .respond(|id, c| match c {
                    CoreCall::HttpSend(_) => vec![reply(id, Err(Failure::Denied("the entry's login is not available".into())))],
                    _ => vec![],
                })
                .with(Event::OpenView(OpenView { view: 1, name: "pve".into() }))
                .with(Event::Ui(UiEvent { view: 1, node: REFRESH, input: Input::Pressed })),
        );
        let view = last_view(&core);
        assert!(matches!(&view[STATUS as usize].component, Component::Banner(b) if b.text.contains("not available")));
    }

    const AGENT: &str = r#"{"data":{"result":[
      {"name":"lo","ip-addresses":[{"ip-address":"127.0.0.1"}]},
      {"name":"eth0","ip-addresses":[{"ip-address":"fe80::1"},{"ip-address":"10.0.0.21"}]}
    ]}}"#;

    fn with_agent(id: u32, call: &CoreCall) -> Vec<Event> {
        match call {
            CoreCall::HttpSend(r) if r.target == "/api2/json/nodes/pve1/qemu/201/agent/network-get-interfaces" => vec![reply(id, ok(AGENT))],
            CoreCall::OpenConnection(_) => vec![reply(id, Ok(ReplyValue::Connection(true)))],
            _ => server(id, call),
        }
    }

    /// The user acts after the guest list has arrived: the events follow the list's reply.
    fn after_list(
        mut inner: impl FnMut(u32, &CoreCall) -> Vec<Event> + 'static,
        user: fn() -> Vec<Event>,
    ) -> impl FnMut(u32, &CoreCall) -> Vec<Event> + 'static {
        let mut done = false;
        move |id, c| {
            let mut out = inner(id, c);
            if !done && matches!(c, CoreCall::HttpSend(r) if r.target.contains("cluster/resources")) {
                done = true;
                out.extend(user());
            }
            out
        }
    }

    fn open_with(respond: impl FnMut(u32, &CoreCall) -> Vec<Event> + 'static, user: fn() -> Vec<Event>) -> FakeCore {
        run_plugin::<Proxmox>(FakeCore::new().respond(after_list(respond, user)).with(Event::OpenView(OpenView { view: 1, name: "pve".into() })))
    }

    fn press(node: NodeId) -> Event {
        Event::Ui(UiEvent { view: 1, node, input: Input::Pressed })
    }

    fn select(key: &str) -> Event {
        Event::Ui(UiEvent { view: 1, node: TABLE, input: Input::Selected(vec![key.into()]) })
    }

    fn opens(core: &FakeCore) -> Vec<open::OpenRequest> {
        core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::OpenConnection(r) => Some(r.clone()),
            _ => None,
        }).collect()
    }

    fn status(core: &FakeCore) -> Component {
        core.plain_calls().into_iter().rev().find_map(|c| match c {
            CoreCall::PatchView(_, nodes, _) => nodes.iter().find(|n| n.id == MESSAGE).map(|n| n.component.clone()),
            CoreCall::SetView(_, nodes) => Some(nodes[MESSAGE as usize].component.clone()),
            _ => None,
        }).expect("a message line")
    }

    #[test]
    fn ssh_on_a_selected_guest_asks_the_app_with_the_agents_address() {
        let core = open_with(with_agent, || vec![select("pve1/201"), press(SSH)]);
        let o = opens(&core);
        assert_eq!(o.len(), 1);
        assert_eq!(o[0].protocol, Protocol::Ssh);
        assert_eq!(o[0].host, "10.0.0.21", "first usable IPv4; loopback and link-local skipped");
        assert_eq!(o[0].port, None);
        assert!(o[0].via_entry_route);
        assert_eq!(o[0].label, "web (pve1/201)");
        let agent = core.plain_calls().into_iter().find_map(|c| match c {
            CoreCall::HttpSend(r) if r.target.contains("/agent/") => Some(r.clone()),
            _ => None,
        }).expect("the address is read from the server");
        assert_eq!(agent.method, Method::Get);
        assert!(agent.with_login);
        assert!(matches!(status(&core), Component::Label(t) if t.is_empty()), "the message line is cleared");
    }

    #[test]
    fn rdp_and_vnc_use_their_protocols() {
        let rdp = open_with(with_agent, || vec![select("pve1/201"), press(RDP)]);
        assert_eq!(opens(&rdp).iter().map(|o| o.protocol).collect::<Vec<_>>(), vec![Protocol::Rdp]);
        let vnc = open_with(with_agent, || vec![select("pve1/201"), press(VNC)]);
        assert_eq!(opens(&vnc).iter().map(|o| o.protocol).collect::<Vec<_>>(), vec![Protocol::Vnc]);
    }

    #[test]
    fn no_selection_or_a_stopped_guest_asks_nothing() {
        let cases: [fn() -> Vec<Event>; 3] = [|| vec![press(SSH)], || vec![select("pve1/202"), press(SSH)], || vec![select("gone/1"), press(RDP)]];
        for user in cases {
            let core = open_with(with_agent, user);
            assert!(opens(&core).is_empty());
            assert!(core.plain_calls().iter().all(|c| !matches!(c, CoreCall::HttpSend(r) if r.target.contains("/agent/") || r.target.contains("/interfaces"))));
            assert!(matches!(status(&core), Component::Banner(_)));
        }
    }

    #[test]
    fn an_agent_that_is_not_running_is_said_in_plain_words() {
        let core = open_with(
            |id, c| match c {
                CoreCall::HttpSend(r) if r.target.contains("/agent/") => vec![reply(id, Ok(ReplyValue::Http(HttpResponse { status: 500, headers: vec![], body: br#"{"data":null,"message":"QEMU guest agent is not running"}"#.to_vec() })))],
                _ => server(id, c),
            },
            || vec![select("pve1/201"), press(SSH)],
        );
        assert!(opens(&core).is_empty());
        assert!(matches!(status(&core), Component::Banner(b) if b.text.contains("guest agent is not running")), "{:?}", status(&core));
    }

    #[test]
    fn a_refused_open_shows_the_cores_reason() {
        let core = open_with(
            |id, c| match c {
                CoreCall::OpenConnection(_) => vec![reply(id, Err(Failure::Denied("not reported".into())))],
                _ => with_agent(id, c),
            },
            || vec![select("pve1/201"), press(SSH)],
        );
        assert!(matches!(status(&core), Component::Banner(b) if b.text == "SSH to web: not reported"));
    }

    mod snap_tests;

    fn with_config(id: u32, call: &CoreCall) -> Vec<Event> {
        match call {
            CoreCall::HttpSend(r) if r.target == "/api2/json/nodes/pve1/qemu/201/config" => vec![reply(id, ok(r#"{"data":{"ostype":"win11","name":"web"}}"#))],
            CoreCall::LibraryPropose(p) => vec![reply(id, Ok(ReplyValue::Created(p.len() as u32)))],
            _ => with_agent(id, call),
        }
    }

    fn proposed(core: &FakeCore) -> Vec<Vec<library::Proposal>> {
        core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::LibraryPropose(p) => Some(p.clone()),
            _ => None,
        }).collect()
    }

    #[test]
    fn save_as_connection_proposes_every_selected_guest_with_address_and_os() {
        let core = open_with(with_config, || vec![Event::Ui(UiEvent { view: 1, node: TABLE, input: Input::Selected(vec!["pve1/201".into(), "pve1/202".into()]) }), press(SAVE)]);
        let p = proposed(&core);
        assert_eq!(p.len(), 1, "one sheet for the whole selection");
        let (running, stopped) = (&p[0][0], &p[0][1]);
        assert_eq!(running.host.as_deref(), Some("10.0.0.21"));
        assert_eq!(running.os_hint.as_deref(), Some("windows"));
        assert_eq!(running.protocol, library::Protocol::Rdp, "Windows guests default to RDP");
        assert_eq!(running.label, "web");
        assert_eq!(stopped.host, None, "a stopped guest has no address to read");
        assert_eq!(stopped.protocol, library::Protocol::Ssh);
        assert!(matches!(status(&core), Component::Label(t) if t == "Saved 2 connections."));
        // Only reads went to the server.
        assert!(core.plain_calls().iter().all(|c| !matches!(c, CoreCall::HttpSend(r) if r.method != Method::Get)));
    }

    #[test]
    fn save_as_connection_without_a_selection_asks_nothing_and_cancel_is_quiet() {
        let core = open_with(with_config, || vec![press(SAVE)]);
        assert!(proposed(&core).is_empty());
        assert!(matches!(status(&core), Component::Banner(_)));
        let core = open_with(
            |id, c| match c {
                CoreCall::LibraryPropose(_) => vec![reply(id, Err(Failure::Cancelled))],
                _ => with_config(id, c),
            },
            || vec![select("pve1/201"), press(SAVE)],
        );
        assert_eq!(proposed(&core).len(), 1);
        assert!(matches!(status(&core), Component::Label(t) if t.is_empty()));
    }

    #[test]
    fn os_types_map_to_hints() {
        use crate::api::os_family_of;
        use crate::model::GuestKind::{Lxc, Qemu};
        assert_eq!(os_family_of(Qemu, "win10"), Some("windows"));
        assert_eq!(os_family_of(Qemu, "l26"), Some("linux"));
        assert_eq!(os_family_of(Qemu, "other"), Some("other"));
        assert_eq!(os_family_of(Qemu, "wxp-but-odd"), None);
        assert_eq!(os_family_of(Lxc, "debian"), Some("linux"));
        assert_eq!(os_family_of(Lxc, "unmanaged"), Some("other"));
    }

    #[test]
    fn changes_never_leave_a_read_only_plugin() {
        let c = calls::power("pve1", crate::model::GuestKind::Qemu, 201, crate::api::Power::Start).unwrap();
        // Refused before `http.send`: the future is ready at once, with no core to call.
        assert!(matches!(futures_lite_block(run(c)), Err(Error::Refused(_))));
    }

    /// The refusal happens before any await, so polling once is enough.
    fn futures_lite_block<F: std::future::Future>(f: F) -> F::Output {
        let mut f = Box::pin(f);
        let waker = std::task::Waker::noop();
        match f.as_mut().poll(&mut std::task::Context::from_waker(waker)) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("it waited"),
        }
    }
}
