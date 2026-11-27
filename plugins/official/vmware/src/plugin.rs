//! The plugin component (feature `plugin`): a vCenter dashboard and a host → VM → snapshot tree.
//!
//! Every request goes through the core's `http.send` with `with-login`: the core adds the
//! entry's login as HTTP Basic (manifest `[http] auth`), so this code never sees it and holds no
//! session token. The entry is read-only unless its "Allow changes (power, snapshots)" field is
//! on; then each power or snapshot action is confirmed first (`ui.confirm`), and forced actions
//! say they are forced. Connecting to a VM asks the app through `open.connection`, which the
//! user confirms in the app's own sheet.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use bastion_plugin_sdk::bindings::bastion::plugin::events::{ChildrenAsk, RowsAsk};
use bastion_plugin_sdk::bindings::bastion::plugin::ui::{Cell, Column, MenuItem, Row, Tree, TreeItem};
use bastion_plugin_sdk::http::{self as http, Method};
use bastion_plugin_sdk::library;
use bastion_plugin_sdk::open::{self, Protocol};
use bastion_plugin_sdk::ui::{self, BannerLevel, Component, ConfirmKind, Tone, ViewBuilder};
use bastion_plugin_sdk::{host, log, task, Failure, Input, NodeId, Plugin, Task, View};

use crate::api::{backend, backend_for, calls, check_id, set_backend, Access, Backend, Call, Error, Power};
use crate::model::{Host, PowerState, Vm};
use crate::Response;

/// Node ids of the dashboard, in the order [`dashboard`] adds them.
pub const TOOLBAR: NodeId = 1;
pub const REFRESH: NodeId = 2;
pub const SUMMARY: NodeId = 3;
/// Messages: a busy mark, a banner, or an empty label.
pub const STATUS: NodeId = 4;
/// The row of tiles (API 1.6 `stat`): VMs, vCPU, memory, hosts.
pub const HOSTS: NodeId = 5;
pub const TABLE: NodeId = 6;
pub const TREE: NodeId = 7;

pub const COLUMNS: [&str; 4] = ["Name", "vCPU", "Memory", "ID"];
pub const TREE_COLUMNS: [&str; 4] = ["Name", "State", "vCPU", "Memory"];

/// The entry field that allows power and snapshot actions (manifest `connection_types.fields`).
pub const ALLOW_CHANGES: &str = "allow-changes";

/// The name of a snapshot taken from the tree.
pub const SNAPSHOT_NAME: &str = "Taken in Gantry";
/// Entry field: take a disk-only snapshot before each connect (API 1.3 plan, section 4). Needs "Allow changes".
pub const SNAPSHOT_BEFORE_CONNECT: &str = "snapshot-before-connect";
/// The name of that snapshot.
pub const CONNECT_SNAPSHOT_NAME: &str = "Taken by Gantry before connect";
/// The tree's node id in the library-sidebar view (its only node, the root).
pub const SIDEBAR_TREE: NodeId = 0;
/// The view name the app opens for the library sidebar (plugin API 1.3).
pub const SIDEBAR: &str = "sidebar";

/// The dashboard, laid out like the Proxmox one: a toolbar with the summary, a message line,
/// four tiles (VMs, vCPU, memory, hosts), the VM table and the host → VM tree.
/// vSphere's REST lists give no live usage, so the tiles show what running VMs are given.
pub fn dashboard(summary: &str, status: Component, hosts: &[Host], vms: &[Vm], rows: usize) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, Component::Toolbar), TOOLBAR);
    assert_eq!(b.add(TOOLBAR, ui::icon_button("Refresh", "refresh", true)), REFRESH);
    assert_eq!(b.add(TOOLBAR, ui::label(summary)), SUMMARY);
    assert_eq!(b.add(root, status), STATUS);
    assert_eq!(b.add(root, ui::row()), HOSTS);
    let mut table = ui::table(&COLUMNS);
    if let Component::Table(t) = &mut table {
        t.total_rows = Some(rows as u64);
    }
    assert_eq!(b.add(root, table), TABLE);
    let tree = Component::Tree(Tree {
        columns: TREE_COLUMNS.iter().map(|t| Column { title: (*t).into(), sortable: false, editable: false }).collect(),
    });
    assert_eq!(b.add(root, tree), TREE);
    if !hosts.is_empty() || !vms.is_empty() {
        for tile in tiles(hosts, vms) {
            b.add(HOSTS, tile);
        }
    }
    b.finish()
}

/// The four tiles. Values stay under 32 characters.
pub fn tiles(hosts: &[Host], vms: &[Vm]) -> [Component; 4] {
    let on: Vec<&Vm> = vms.iter().filter(|v| v.power() == PowerState::Running).collect();
    let cpus_on: u64 = on.iter().filter_map(|v| v.cpu_count).sum();
    let cpus_all: u64 = vms.iter().filter_map(|v| v.cpu_count).sum();
    let mem_on: u64 = on.iter().filter_map(|v| v.memory_mib).sum();
    let mem_all: u64 = vms.iter().filter_map(|v| v.memory_mib).sum();
    let connected = hosts.iter().filter(|h| h.connection_state == "CONNECTED").count();
    let gib = |m: u64| m as f64 / 1024.0;
    [
        ui::stat("VMs", &format!("{} / {}", on.len(), vms.len()), &format!("{} off", vms.len() - on.len()), None),
        ui::stat("vCPU", &format!("{cpus_on} on"), &format!("{cpus_all} configured"), None),
        ui::stat("Memory", &format!("{:.1} GiB on", gib(mem_on)), &format!("{:.1} GiB configured", gib(mem_all)), None),
        ui::stat("Hosts", &format!("{connected} / {} connected", hosts.len()), &host_names(hosts), None),
    ]
}

/// The host names for the Hosts tile, cut to fit one line.
fn host_names(hosts: &[Host]) -> String {
    let all = hosts.iter().map(|h| if h.name.is_empty() { h.host.as_str() } else { h.name.as_str() }).collect::<Vec<_>>().join(", ");
    if all.chars().count() <= 40 { all } else { format!("{}…", all.chars().take(39).collect::<String>()) }
}

/// A host's state in the vSphere Client's words.
pub fn host_state(h: &Host) -> &'static str {
    match (h.connection_state.as_str(), h.power_state.as_deref()) {
        ("CONNECTED", Some("STANDBY")) => "Standby",
        ("CONNECTED", Some("POWERED_OFF")) => "Powered off",
        ("CONNECTED", _) => "Connected",
        ("DISCONNECTED", _) => "Disconnected",
        ("NOT_RESPONDING", _) => "Not responding",
        _ => "Unknown",
    }
}

fn memory(mib: Option<u64>) -> String {
    mib.map_or(String::new(), |m| format!("{:.1} GiB", m as f64 / 1024.0))
}

fn state_text(v: &Vm) -> &'static str {
    match v.power() {
        PowerState::Running => "Powered on",
        PowerState::Stopped => "Powered off",
        PowerState::Suspended => "Suspended",
        PowerState::Unknown => "Unknown",
    }
}

/// The state dot's tone: powered off dims the row.
fn tone(v: &Vm) -> Tone {
    match v.power() {
        PowerState::Running => Tone::Good,
        PowerState::Suspended => Tone::Warning,
        PowerState::Stopped => Tone::Off,
        PowerState::Unknown => Tone::Neutral,
    }
}

fn cpus(v: &Vm) -> Cell {
    v.cpu_count.map_or(Cell::Text(String::new()), |n| Cell::Number(n as f64))
}

/// One table row per VM, by name.
pub fn rows(vms: &[Vm]) -> Vec<Row> {
    let mut list: Vec<&Vm> = vms.iter().collect();
    list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    list.into_iter()
        .map(|v| Row {
            key: v.vm.clone(),
            cells: vec![
                ui::status_cell(tone(v), &v.name),
                cpus(v),
                Cell::Text(memory(v.memory_mib)),
                Cell::Text(v.vm.clone()),
            ],
        })
        .collect()
}

fn item(id: &str, title: &str) -> MenuItem {
    MenuItem { id: id.into(), title: title.into() }
}

/// The power actions a VM in this state can take.
pub fn power_actions(state: PowerState) -> &'static [Power] {
    match state {
        PowerState::Stopped | PowerState::Suspended => &[Power::Start],
        PowerState::Running => &[Power::Shutdown, Power::Reboot, Power::Suspend, Power::Stop, Power::Reset],
        PowerState::Unknown => &[],
    }
}

fn power_id(p: Power) -> &'static str {
    match p {
        Power::Start => "start",
        Power::Shutdown => "shutdown",
        Power::Reboot => "reboot",
        Power::Stop => "stop",
        Power::Reset => "reset",
        Power::Suspend => "suspend",
    }
}

fn power_of(id: &str) -> Option<Power> {
    [Power::Start, Power::Shutdown, Power::Reboot, Power::Stop, Power::Reset, Power::Suspend].into_iter().find(|p| power_id(*p) == id)
}

fn power_title(p: Power) -> &'static str {
    match p {
        Power::Start => "Start",
        Power::Shutdown => "Shut Down Guest",
        Power::Reboot => "Restart Guest",
        Power::Stop => "Power Off (Forced)",
        Power::Reset => "Reset (Forced)",
        Power::Suspend => "Suspend",
    }
}

/// The text of a power confirmation. Forced actions say so.
pub fn power_prompt(p: Power, name: &str) -> String {
    match p {
        Power::Start => format!("Start {name}?"),
        Power::Shutdown => format!("Shut down {name}? VMware Tools asks the guest to shut down."),
        Power::Reboot => format!("Restart {name}? VMware Tools asks the guest to restart."),
        Power::Stop => format!("Power off {name}? This is forced, like pulling the plug: unsaved work in the guest is lost."),
        Power::Reset => format!("Reset {name}? This is forced, like pressing reset: unsaved work in the guest is lost."),
        Power::Suspend => format!("Suspend {name}?"),
    }
}

/// A VM's context menu: connect always (`open`, the double-click, picks RDP for Windows guests and SSH
/// otherwise); power and snapshots only when changes are allowed.
pub fn vm_menu(v: &Vm, may_change: bool) -> Vec<MenuItem> {
    let mut m = vec![item("open", "Connect"), item("connect-ssh", "Connect by SSH"), item("connect-rdp", "Connect by RDP"), item("connect-vnc", "Connect by VNC"), item("save-connection", "Save as Connection…")];
    if may_change {
        m.extend(power_actions(v.power()).iter().map(|p| item(power_id(*p), power_title(*p))));
        m.push(item("snapshot-take", "Take Snapshot"));
    }
    m
}

/// VMware Tools' guest family (`WINDOWS`, `LINUX`, …) as a library OS hint.
pub fn os_hint(family: Option<&str>) -> Option<&'static str> {
    match family?.to_ascii_uppercase().as_str() {
        "WINDOWS" => Some("windows"),
        "LINUX" => Some("linux"),
        "" => None,
        _ => Some("other"),
    }
}

/// What a VM is proposed as: RDP for Windows, SSH otherwise; the user can change it.
pub fn proposal(name: &str, host: Option<std::net::IpAddr>, family: Option<&str>) -> library::Proposal {
    let os = os_hint(family);
    let protocol = if os == Some("windows") { library::Protocol::Rdp } else { library::Protocol::Ssh };
    let label: String = name.trim().chars().take(128).collect();
    library::Proposal { label: label.trim().to_string(), host: host.map(|ip| ip.to_string()), protocol, os_hint: os.map(str::to_string) }
}

/// The status line after the sheet.
pub fn saved_text(n: u32) -> String {
    match n {
        0 => "No connection saved.".into(),
        1 => "Saved 1 connection.".into(),
        n => format!("Saved {n} connections."),
    }
}

/// A tree item per VM; it expands to its snapshots.
pub fn vm_items(vms: &[Vm], may_change: bool) -> Vec<TreeItem> {
    vms.iter()
        .map(|v| TreeItem {
            key: v.vm.clone(),
            label: if v.name.is_empty() { v.vm.clone() } else { v.name.clone() },
            icon: None,
            has_children: true,
            cells: vec![Cell::Text(state_text(v).into()), cpus(v), Cell::Text(memory(v.memory_mib))],
            menu: vm_menu(v, may_change),
        })
        .collect()
}

/// The key of a snapshot item: `vm-42/snapshot-7`.
fn snapshot_key(vm: &str, snapshot: &str) -> String {
    format!("{vm}/{snapshot}")
}

/// Splits and checks a snapshot key.
pub fn parse_snapshot_key(key: &str) -> Option<(&str, &str)> {
    let (vm, snap) = key.split_once('/')?;
    Some((check_id(vm, "vm").ok()?, check_id(snap, "snapshot").ok()?))
}

/// Runs one call through the core's `http.send`, with the entry's login.
pub async fn run<R>(c: Call<R>, access: Access) -> Result<R, Error> {
    c.check(access)?;
    let method = match c.request.method {
        crate::Method::Get => Method::Get,
        crate::Method::Post => Method::Post,
        crate::Method::Delete => Method::Delete,
    };
    let mut req = http::request(method, &c.request.target);
    let soap = c.request.target == crate::soap::SDK;
    req.headers.push(("Accept".into(), if soap { "text/xml" } else { "application/json" }.into()));
    if !c.request.body.is_empty() {
        req.headers.push(("Content-Type".into(), if soap { "text/xml; charset=utf-8" } else { "application/json" }.into()));
        if soap {
            req.headers.push(("SOAPAction".into(), "\"urn:vim25/8.0.0.0\"".into()));
        }
        req.body = c.request.body.clone();
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

/// What the user sees when a call fails, in plain words.
pub fn message(e: &Error) -> String {
    match e {
        Error::Status(401, _) => format!("{} refused the login. Check the entry's user and password.", server_name()),
        Error::Status(403, _) => "The account may not do this. Reading needs the Read-only role; power and snapshots need a role that allows them.".into(),
        Error::Status(404, _) if backend() == Backend::Rest => "No vCenter REST API here. For a standalone ESXi host, use the VMware ESXi entry type.".into(),
        Error::Status(code, text) if text.is_empty() => format!("The server answered {code}."),
        Error::Status(code, text) => format!("The server answered {code}: {text}"),
        Error::Parse(_) => format!("The server's answer was not what {} sends.", server_name()),
        Error::Transport(why) | Error::Refused(why) => why.clone(),
    }
}

/// "vCenter" or "ESXi", for the user's words.
pub fn server_name() -> &'static str {
    match backend() {
        Backend::Rest => "vCenter",
        Backend::Soap => "ESXi",
    }
}

/// The entry field the core adds with the entry's connection type (`:type`, design D).
pub const TYPE_FIELD: &str = ":type";

/// The backend for a view: the view name when it is a connection type, else the entry's type.
pub fn backend_of_view(name: &str) -> Backend {
    if name != SIDEBAR {
        return backend_for(name);
    }
    let ty = host::entry().and_then(|e| e.fields.into_iter().find(|(k, _)| k == TYPE_FIELD).map(|(_, v)| v)).unwrap_or_default();
    backend_for(&ty)
}

/// Whether the entry allows power and snapshot changes. Off unless the field says `true`.
fn field_on(key: &str) -> bool {
    host::entry().is_some_and(|e| e.fields.iter().any(|(k, v)| k == key && v == "true"))
}

pub fn may_change() -> bool {
    field_on(ALLOW_CHANGES)
}

/// A snapshot before each connect: both entry toggles on.
pub fn snapshot_before_connect() -> bool {
    may_change() && field_on(SNAPSHOT_BEFORE_CONNECT)
}

/// The library-sidebar view: one tree, nothing else (the core refuses more).
pub fn sidebar_view() -> Vec<ui::Node> {
    let tree = Component::Tree(Tree { columns: vec![] });
    ViewBuilder::new(tree).finish()
}

fn access() -> Access {
    if may_change() {
        Access::MayChange
    } else {
        Access::ReadOnly
    }
}

#[derive(Default)]
pub struct Vmware {
    /// This helper serves the library-sidebar tree: no prompts there, so no changes are offered.
    sidebar: std::cell::Cell<bool>,
    rows: RefCell<Vec<Row>>,
    /// The VMs the tree last listed, by id: their name and state for menus and prompts.
    vms: RefCell<HashMap<String, Vm>>,
}

fn show(view: View, status: Component) {
    let _ = view.patch(vec![ui::Node { id: STATUS, parent: Some(0), component: status }], vec![]);
}

impl Vmware {
    async fn refresh(self: Rc<Self>, view: View) {
        show(view, Component::Progress(None));
        let result = async {
            let hosts = run(calls::hosts(), Access::ReadOnly).await?;
            let vms = run(calls::vms(), Access::ReadOnly).await?;
            Ok::<_, Error>((hosts, vms))
        }
        .await;
        let (summary, status, hosts, vms, rows) = match result {
            Ok((mut hosts, vms)) => {
                let rows = rows(&vms);
                self.remember(&vms);
                let on = vms.iter().filter(|v| v.power() == PowerState::Running).count();
                hosts.sort_by(|a, b| a.name.cmp(&b.name));
                (format!("{} · {on} of {} VMs on", server_name(), rows.len()), ui::label(""), hosts, vms, rows)
            }
            Err(e) => {
                log::warn("refresh failed");
                (String::new(), ui::banner(BannerLevel::Error, &message(&e)), Vec::new(), Vec::new(), Vec::new())
            }
        };
        let count = rows.len();
        *self.rows.borrow_mut() = rows;
        if let Err(e) = view.set(dashboard(&summary, status, &hosts, &vms, count)) {
            log::error(&format!("view refused: {e:?}"));
        }
    }

    fn remember(&self, vms: &[Vm]) {
        let mut map = self.vms.borrow_mut();
        for v in vms {
            map.insert(v.vm.clone(), v.clone());
        }
    }

    /// The VM's name for a prompt: from the last listing, else asked of vCenter, else its id.
    async fn name_of(&self, vm: &str) -> String {
        let known = self.vms.borrow().get(vm).map(|v| v.name.clone()).filter(|n| !n.is_empty());
        if let Some(n) = known {
            return n;
        }
        match calls::name(vm) {
            Ok(c) => run(c, Access::ReadOnly).await.ok().filter(|n| !n.is_empty()).unwrap_or_else(|| vm.to_string()),
            Err(_) => vm.to_string(),
        }
    }

    async fn children_of(self: Rc<Self>, parent: Option<String>) -> Result<Vec<TreeItem>, Error> {
        let Some(parent) = parent else {
            let hosts = run(calls::hosts(), Access::ReadOnly).await?;
            return Ok(hosts
                .into_iter()
                .map(|h| TreeItem {
                    label: if h.name.is_empty() { h.host.clone() } else { h.name.clone() },
                    key: h.host,
                    icon: None,
                    has_children: true,
                    cells: vec![Cell::Text(h.connection_state.to_lowercase()), Cell::Null, Cell::Null],
                    menu: vec![],
                })
                .collect());
        };
        if parent.starts_with("host-") {
            let vms = run(calls::vms_on(&parent)?, Access::ReadOnly).await?;
            self.remember(&vms);
            return Ok(vm_items(&vms, may_change() && !self.sidebar.get()));
        }
        let snaps = match run(calls::snapshots(&parent)?, Access::ReadOnly).await {
            Err(Error::Status(404, _)) if backend() == Backend::Rest => return Err(Error::Refused("Snapshots in the REST API need vCenter 9.0 or later.".into())),
            other => other?,
        };
        let menu = if may_change() && !self.sidebar.get() { vec![item("snapshot-revert", "Revert to Snapshot"), item("snapshot-delete", "Delete Snapshot")] } else { vec![] };
        Ok(snaps
            .into_iter()
            .map(|s| TreeItem {
                key: snapshot_key(&parent, &s.snapshot),
                label: if s.name.is_empty() { s.snapshot.clone() } else { s.name },
                icon: None,
                has_children: false,
                cells: vec![Cell::Text("snapshot".into()), Cell::Null, Cell::Null],
                menu: menu.clone(),
            })
            .collect())
    }

    /// The double-click protocol: RDP for a Windows guest (VMware Tools' family), SSH otherwise.
    async fn default_protocol(&self, vm: &str) -> Protocol {
        let windows = match calls::identity(vm) {
            Ok(c) => run(c, Access::ReadOnly).await.ok().and_then(|i| i.family).is_some_and(|f| f.eq_ignore_ascii_case("WINDOWS")),
            Err(_) => false,
        };
        if windows { Protocol::Rdp } else { Protocol::Ssh }
    }

    /// Connects to a VM: the address from VMware Tools, then the app's own confirm sheet.
    async fn connect(self: Rc<Self>, view: View, vm: String, protocol: Protocol) -> Result<String, Error> {
        let name = self.name_of(&vm).await;
        let Some(ip) = run(calls::address(&vm)?, Access::ReadOnly).await? else {
            return Err(Error::Refused(format!("VMware Tools reports no address for {name}.")));
        };
        let _ = view;
        // The entry's two toggles are the consent; the core's open sheet that follows confirms the connect.
        if snapshot_before_connect() {
            run(calls::take_snapshot(&vm, CONNECT_SNAPSHOT_NAME)?, Access::MayChange).await?;
        }
        let opened = open::connection(&open::request(protocol, &ip.to_string(), &name)).await.map_err(|f| Error::Transport(describe(&f)))?;
        Ok(if opened { format!("Opened {name} at {ip}.") } else { "Not opened.".into() })
    }

    /// Save as Connection (`library.propose`, API 1.6): the VM's name, its VMware Tools address
    /// when it reports one, and the OS family from VMware Tools. Only reads go to the server;
    /// the user picks folder, protocol, host and credential in the app's sheet.
    async fn save_connection(&self, vm: &str) -> Result<Option<String>, Error> {
        let name = self.name_of(vm).await;
        let host = match calls::address(vm) {
            Ok(c) => run(c, Access::ReadOnly).await.ok().flatten(),
            Err(_) => None,
        };
        let family = match calls::identity(vm) {
            Ok(c) => run(c, Access::ReadOnly).await.ok().and_then(|i| i.family),
            Err(_) => None,
        };
        let p = proposal(&name, host, family.as_deref());
        match library::propose(&[p]).await {
            Ok(n) => Ok(Some(saved_text(n))),
            Err(Failure::Cancelled) => Ok(None),
            Err(f) => Err(Error::Transport(describe(&f))),
        }
    }

    /// A change: confirmed first, then sent; `None` when the user said no.
    async fn change(&self, prompt: String, c: Call<()>, done: String) -> Result<Option<String>, Error> {
        c.check(access())?;
        if !ui::confirm(ConfirmKind::Other, &prompt).await.map_err(|f| Error::Transport(describe(&f)))? {
            return Ok(None);
        }
        run(c, access()).await?;
        Ok(Some(done))
    }

    async fn menu(self: Rc<Self>, view: View, key: String, id: String) {
        let outcome: Result<Option<String>, Error> = async {
            let protocol = match id.as_str() {
                "connect-ssh" => Some(Protocol::Ssh),
                "connect-rdp" => Some(Protocol::Rdp),
                "connect-vnc" => Some(Protocol::Vnc),
                _ => None,
            };
            let protocol = match (protocol, id.as_str()) {
                (None, "open") => Some(self.default_protocol(&key).await),
                (p, _) => p,
            };
            if let Some(p) = protocol {
                return self.clone().connect(view, key, p).await.map(Some);
            }
            if let Some(p) = power_of(&id) {
                let name = self.name_of(&key).await;
                return self.change(power_prompt(p, &name), calls::power(&key, p)?, format!("{}: sent to {name}.", power_title(p))).await;
            }
            match id.as_str() {
                "save-connection" => self.save_connection(&key).await,
                "snapshot-take" => {
                    let name = self.name_of(&key).await;
                    self.change(format!("Take a snapshot of {name}? Disks only, without memory."), calls::take_snapshot(&key, SNAPSHOT_NAME)?, format!("Snapshot taken of {name}.")).await
                }
                "snapshot-revert" | "snapshot-delete" => {
                    let (vm, snap) = parse_snapshot_key(&key).ok_or_else(|| Error::Refused("not a snapshot".into()))?;
                    let name = self.name_of(vm).await;
                    if id == "snapshot-revert" {
                        self.change(format!("Revert {name} to snapshot {snap}? Changes since the snapshot are lost."), calls::revert_snapshot(vm, snap)?, format!("{name} reverted.")).await
                    } else {
                        self.change(format!("Delete snapshot {snap} of {name}? This cannot be undone."), calls::delete_snapshot(vm, snap)?, "Snapshot deleted.".into()).await
                    }
                }
                _ => Ok(None),
            }
        }
        .await;
        match outcome {
            _ if self.sidebar.get() => {} // the sidebar has no status line; the core's sheet is the feedback
            Ok(Some(text)) if id.starts_with("connect-") || id == "open" || id == "save-connection" => show(view, ui::label(&text)),
            Ok(Some(text)) => {
                self.clone().refresh(view).await;
                show(view, ui::label(&text));
            }
            Ok(None) => {}
            Err(e) => show(view, ui::banner(BannerLevel::Error, &message(&e))),
        }
    }
}

impl Plugin for Vmware {
    fn start() -> Self {
        Vmware::default()
    }

    fn open_view(self: Rc<Self>, view: View, name: String) -> Task {
        set_backend(backend_of_view(&name));
        if name == SIDEBAR {
            self.sidebar.set(true);
            if let Err(e) = view.set(sidebar_view()) {
                log::error(&format!("sidebar refused: {e:?}"));
            }
            return bastion_plugin_sdk::done();
        }
        task(async move {
            let _ = view.set(dashboard("Loading", Component::Progress(None), &[], &[], 0));
            self.refresh(view).await;
        })
    }

    fn command(self: Rc<Self>, id: String, view: Option<View>) -> Task {
        match (id.as_str(), view) {
            ("refresh" | "refresh-esxi", Some(view)) => task(self.refresh(view)),
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        match (node, input) {
            (REFRESH, Input::Pressed) => task(self.refresh(view)),
            (SIDEBAR_TREE, Input::Menu((key, id))) if self.sidebar.get() => task(self.menu(view, key, id)),
            (TREE, Input::Menu((key, id))) => task(self.menu(view, key, id)),
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn rows(self: Rc<Self>, ask: RowsAsk) -> Task {
        let all = self.rows.borrow();
        let start = (ask.offset as usize).min(all.len());
        let end = start.saturating_add(ask.count as usize).min(all.len()).min(start + ui::MAX_ROWS);
        let _ = ui::provide_rows(ask.ask, &all[start..end], Some(all.len() as u64));
        bastion_plugin_sdk::done()
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
}

#[cfg(target_arch = "wasm32")]
bastion_plugin_sdk::export_plugin!(Vmware);

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_plugin_sdk::bindings::bastion::plugin::events::{ChildrenAsk, Event, OpenView, ReplyValue, UiEvent};
    use bastion_plugin_sdk::bindings::bastion::plugin::types::HttpResponse;
    use bastion_plugin_sdk::testing::{reply, run_plugin, Call as CoreCall, FakeCore};

    const VMS: &str = r#"[
      {"vm":"vm-42","name":"web","power_state":"POWERED_ON","cpu_count":2,"memory_size_MiB":2048},
      {"vm":"vm-43","name":"dns","power_state":"POWERED_OFF","cpu_count":1,"memory_size_MiB":512}
    ]"#;

    fn ok(body: &str) -> Result<ReplyValue, Failure> {
        Ok(ReplyValue::Http(HttpResponse { status: 200, headers: vec![], body: body.as_bytes().to_vec() }))
    }

    fn status(id: u32, code: u16, body: &[u8]) -> Vec<Event> {
        vec![reply(id, Ok(ReplyValue::Http(HttpResponse { status: code, headers: vec![], body: body.to_vec() })))]
    }

    fn server(id: u32, call: &CoreCall) -> Vec<Event> {
        match call {
            CoreCall::HttpSend(r) if r.target == "/api/vcenter/host" => vec![reply(id, ok(r#"[{"host":"host-21","name":"esx1","connection_state":"CONNECTED"}]"#))],
            CoreCall::HttpSend(r) if r.target == "/api/vcenter/vm" => vec![reply(id, ok(VMS))],
            CoreCall::HttpSend(_) => status(id, 404, b""),
            _ => vec![],
        }
    }

    fn last_view(core: &FakeCore) -> Vec<ui::Node> {
        core.plain_calls().into_iter().rev().find_map(|c| match c {
            CoreCall::SetView(_, nodes) => Some(nodes.clone()),
            _ => None,
        }).expect("a view")
    }

    fn open() -> Event {
        Event::OpenView(OpenView { view: 1, name: "vcenter".into() })
    }

    #[test]
    fn the_dashboard_passes_the_checks() {
        assert_eq!(ui::check(&dashboard("Loading", Component::Progress(None), &[], &[], 0)), Ok(()));
        assert_eq!(ui::check(&dashboard("Not loaded", ui::banner(BannerLevel::Error, &"x".repeat(500)), &[], &[], 10_000)), Ok(()));
        let many: Vec<Host> = (0..40)
            .map(|i| Host { host: format!("host-{i}"), name: "e".repeat(80), connection_state: "CONNECTED".into(), power_state: None })
            .collect();
        let view = dashboard("vCenter · 0 of 0 VMs on", ui::label(""), &many, &[], 0);
        assert_eq!(ui::check(&view), Ok(()));
        assert_eq!(view.iter().filter(|n| n.parent == Some(HOSTS)).count(), 4, "VMs, vCPU, memory, hosts");
    }

    #[test]
    fn opening_reads_the_vms_through_the_core_with_the_login() {
        let core = run_plugin::<Vmware>(FakeCore::new().respond(server).with(open()));
        let sent: Vec<_> = core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::HttpSend(r) => Some(r.clone()),
            _ => None,
        }).collect();
        assert_eq!(sent.iter().map(|r| r.target.as_str()).collect::<Vec<_>>(), vec!["/api/vcenter/host", "/api/vcenter/vm"]);
        for r in &sent {
            assert_eq!(r.method, Method::Get);
            assert!(r.with_login, "the core adds the login");
            assert!(r.body.is_empty());
            assert!(r.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("authorization") && !n.eq_ignore_ascii_case("vmware-api-session-id")), "the plugin never sets a credential");
        }
        let view = last_view(&core);
        assert!(matches!(&view[SUMMARY as usize].component, Component::Label(t) if t == "vCenter · 1 of 2 VMs on"), "{:?}", view[SUMMARY as usize]);
        let tile: Vec<_> = view.iter().filter(|n| n.parent == Some(HOSTS)).map(|n| &n.component).collect();
        assert!(matches!(tile[0], Component::Stat(t) if t.title == "VMs" && t.value == "1 / 2"), "{:?}", tile[0]);
        assert!(matches!(tile[3], Component::Stat(t) if t.value == "1 / 1 connected" && t.detail == "esx1"), "{:?}", tile[3]);
        assert!(matches!(&view[TABLE as usize].component, Component::Table(t) if t.total_rows == Some(2)));
    }

    #[test]
    fn rows_show_state_cpus_and_memory() {
        let vms: Vec<Vm> = serde_json::from_str(VMS).unwrap();
        let r = rows(&vms);
        assert_eq!(r.len(), 2);
        // Sorted by name: dns before web.
        assert_eq!(r[0].key, "vm-43");
        assert_eq!(r[1].key, "vm-42");
        assert!(matches!(&r[1].cells[0], Cell::Status(s) if s.tone == Tone::Good), "name first, with a state dot");
        assert!(matches!(&r[0].cells[0], Cell::Status(s) if s.tone == Tone::Off), "powered off dims the row");
        assert!(matches!(&r[1].cells[1], Cell::Number(n) if *n == 2.0));
        assert!(matches!(&r[1].cells[2], Cell::Text(t) if t == "2.0 GiB"));
    }

    #[test]
    fn a_refused_login_shows_a_banner_in_plain_words() {
        let core = run_plugin::<Vmware>(
            FakeCore::new()
                .respond(|id, c| match c {
                    CoreCall::HttpSend(_) => status(id, 401, br#"{"error_type":"UNAUTHENTICATED","messages":[]}"#),
                    _ => vec![],
                })
                .with(open()),
        );
        let view = last_view(&core);
        assert!(matches!(&view[STATUS as usize].component, Component::Banner(b) if b.text.contains("refused the login")));
        // An ESXi host without the REST API answers 404.
        let core = run_plugin::<Vmware>(FakeCore::new().respond(|id, c| match c {
            CoreCall::HttpSend(_) => status(id, 404, b""),
            _ => vec![],
        }).with(open()));
        let view = last_view(&core);
        assert!(matches!(&view[STATUS as usize].component, Component::Banner(b) if b.text.contains("ESXi")));
        // A login the core cannot give is passed on as the core's words.
        let core = run_plugin::<Vmware>(
            FakeCore::new()
                .respond(|id, c| match c {
                    CoreCall::HttpSend(_) => vec![reply(id, Err(Failure::Denied("the entry's login is not available".into())))],
                    _ => vec![],
                })
                .with(open())
                .with(Event::Ui(UiEvent { view: 1, node: REFRESH, input: Input::Pressed })),
        );
        let view = last_view(&core);
        assert!(matches!(&view[STATUS as usize].component, Component::Banner(b) if b.text.contains("not available")));
    }

    #[test]
    fn changes_never_leave_a_read_only_plugin() {
        let c = calls::power("vm-42", crate::api::Power::Start).unwrap();
        // Refused before `http.send`: the future is ready at once, with no core to call.
        assert!(matches!(block(run(c, Access::ReadOnly)), Err(Error::Refused(_))));
    }

    fn entry(allow: bool) -> bastion_plugin_sdk::Entry {
        bastion_plugin_sdk::Entry {
            id: "e1".into(),
            name: "vc".into(),
            host: "vc.lab".into(),
            port: 443,
            fields: vec![(ALLOW_CHANGES.into(), allow.to_string())],
        }
    }

    fn tree_server(id: u32, call: &CoreCall) -> Vec<Event> {
        match call {
            CoreCall::HttpSend(r) if r.target == "/api/vcenter/vm?hosts=host-21" => vec![reply(id, ok(VMS))],
            CoreCall::HttpSend(r) if r.target == "/api/vcenter/vm/vm-42/snapshots" => vec![reply(id, ok(r#"[{"snapshot":"snapshot-7","name":"before patch"}]"#))],
            CoreCall::HttpSend(r) if r.target == "/api/vcenter/vm/vm-42/guest/networking/interfaces" => {
                vec![reply(id, ok(r#"[{"ip":{"ip_addresses":[{"ip_address":"fe80::1"},{"ip_address":"10.0.0.5","state":"PREFERRED"}]}}]"#))]
            }
            CoreCall::HttpSend(r) if r.target == "/api/vcenter/vm/vm-42" => vec![reply(id, ok(r#"{"name":"web","power_state":"POWERED_ON"}"#))],
            CoreCall::HttpSend(r) if r.method != Method::Get => status(id, 204, b""),
            CoreCall::Confirm(..) => vec![reply(id, Ok(ReplyValue::Confirmed(true)))],
            CoreCall::OpenConnection(_) => vec![reply(id, Ok(ReplyValue::Connection(true)))],
            _ => server(id, call),
        }
    }

    fn children(core: &FakeCore) -> Vec<(u32, Vec<TreeItem>)> {
        core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::ProvideChildren(a, items) => Some((*a, items.clone())),
            _ => None,
        }).collect()
    }

    fn sent(core: &FakeCore) -> Vec<(Method, String)> {
        core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::HttpSend(r) => Some((r.method, r.target.clone())),
            _ => None,
        }).collect()
    }

    fn menu(key: &str, id: &str) -> Event {
        Event::Ui(UiEvent { view: 1, node: TREE, input: Input::Menu((key.into(), id.into())) })
    }

    #[test]
    fn the_tree_lists_hosts_vms_and_snapshots() {
        let mut core = FakeCore::new().respond(tree_server);
        core.entry = Some(entry(false));
        let core = run_plugin::<Vmware>(core
            .with(Event::Children(ChildrenAsk { ask: 1, view: 1, node: TREE, parent: None }))
            .with(Event::Children(ChildrenAsk { ask: 2, view: 1, node: TREE, parent: Some("host-21".into()) }))
            .with(Event::Children(ChildrenAsk { ask: 3, view: 1, node: TREE, parent: Some("vm-42".into()) })));
        let c = children(&core);
        assert_eq!(c[0].1.iter().map(|i| i.key.as_str()).collect::<Vec<_>>(), vec!["host-21"]);
        assert_eq!(c[1].1.iter().map(|i| i.key.as_str()).collect::<Vec<_>>(), vec!["vm-42", "vm-43"]);
        // Read-only: connect only, no power or snapshot items.
        let ids: Vec<_> = c[1].1[0].menu.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["open", "connect-ssh", "connect-rdp", "connect-vnc", "save-connection"]);
        assert_eq!(c[2].1[0].key, "vm-42/snapshot-7");
        assert!(c[2].1[0].menu.is_empty());
    }

    #[test]
    fn allowed_changes_add_power_by_state_and_forced_ones_say_so() {
        let vms: Vec<Vm> = serde_json::from_str(VMS).unwrap();
        let on: Vec<_> = vm_menu(&vms[0], true).into_iter().map(|m| m.id).collect();
        assert!(on.contains(&"stop".to_string()) && on.contains(&"shutdown".to_string()) && !on.contains(&"start".to_string()));
        let off: Vec<_> = vm_menu(&vms[1], true).into_iter().map(|m| m.id).collect();
        assert!(off.contains(&"start".to_string()) && !off.contains(&"stop".to_string()));
        assert!(power_prompt(Power::Stop, "web").contains("forced"));
        assert!(power_prompt(Power::Reset, "web").contains("forced"));
        assert!(!power_prompt(Power::Shutdown, "web").contains("forced"));
    }

    #[test]
    fn a_power_action_is_confirmed_then_sent() {
        let mut core = FakeCore::new().respond(tree_server);
        core.entry = Some(entry(true));
        let core = run_plugin::<Vmware>(core.with(Event::Children(ChildrenAsk { ask: 1, view: 1, node: TREE, parent: Some("host-21".into()) })).with(menu("vm-42", "stop")));
        let confirms: Vec<_> = core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::Confirm(_, t) => Some(t.clone()),
            _ => None,
        }).collect();
        assert_eq!(confirms.len(), 1);
        assert!(confirms[0].contains("web") && confirms[0].contains("forced"), "{confirms:?}");
        assert!(sent(&core).contains(&(Method::Post, "/api/vcenter/vm/vm-42/power?action=stop".into())));
    }

    #[test]
    fn a_declined_confirm_sends_nothing() {
        let mut core = FakeCore::new().respond(|id, c| match c {
            CoreCall::Confirm(..) => vec![reply(id, Ok(ReplyValue::Confirmed(false)))],
            _ => tree_server(id, c),
        });
        core.entry = Some(entry(true));
        let core = run_plugin::<Vmware>(core.with(menu("vm-42", "snapshot-take")).with(menu("vm-42/snapshot-7", "snapshot-delete")));
        assert!(sent(&core).iter().all(|(m, _)| *m == Method::Get), "{:?}", sent(&core));
    }

    #[test]
    fn a_read_only_entry_refuses_changes_without_asking() {
        let mut core = FakeCore::new().respond(tree_server);
        core.entry = Some(entry(false));
        let core = run_plugin::<Vmware>(core.with(open()).with(menu("vm-42", "start")).with(menu("vm-42/snapshot-7", "snapshot-revert")));
        assert!(core.plain_calls().iter().all(|c| !matches!(c, CoreCall::Confirm(..))));
        assert!(sent(&core).iter().all(|(m, _)| *m == Method::Get));
    }

    #[test]
    fn snapshot_changes_send_the_right_requests() {
        let mut core = FakeCore::new().respond(tree_server);
        core.entry = Some(entry(true));
        let core = run_plugin::<Vmware>(core.with(menu("vm-42", "snapshot-take")).with(menu("vm-42/snapshot-7", "snapshot-revert")).with(menu("vm-42/snapshot-7", "snapshot-delete")).with(menu("vm-42/../x", "snapshot-delete")));
        let changes: Vec<_> = sent(&core).into_iter().filter(|(m, _)| *m != Method::Get).collect();
        assert_eq!(changes, vec![
            (Method::Post, "/api/vcenter/vm/vm-42/snapshots".into()),
            (Method::Post, "/api/vcenter/vm/vm-42/snapshots/snapshot-7?action=revert".into()),
            (Method::Delete, "/api/vcenter/vm/vm-42/snapshots/snapshot-7".into()),
        ]);
    }

    #[test]
    fn connect_asks_the_app_with_the_tools_address() {
        let mut core = FakeCore::new().respond(tree_server);
        core.entry = Some(entry(false));
        let core = run_plugin::<Vmware>(core.with(Event::Children(ChildrenAsk { ask: 1, view: 1, node: TREE, parent: Some("host-21".into()) })).with(menu("vm-42", "connect-rdp")));
        let opens: Vec<_> = core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::OpenConnection(r) => Some(r.clone()),
            _ => None,
        }).collect();
        assert_eq!(opens.len(), 1);
        assert_eq!(opens[0].host, "10.0.0.5");
        assert_eq!(opens[0].label, "web");
        assert!(matches!(opens[0].protocol, Protocol::Rdp));
        assert!(opens[0].via_entry_route);
    }

    #[test]
    fn save_as_connection_proposes_the_vm_with_tools_address_and_family() {
        let mut core = FakeCore::new().respond(move |id, c| match c {
            CoreCall::LibraryPropose(p) => vec![reply(id, Ok(ReplyValue::Created(p.len() as u32)))],
            _ => identity_server("WINDOWS")(id, c),
        });
        core.entry = Some(entry(false));
        let core = run_plugin::<Vmware>(core.with(Event::Children(ChildrenAsk { ask: 1, view: 1, node: TREE, parent: Some("host-21".into()) })).with(menu("vm-42", "save-connection")));
        let proposals: Vec<_> = core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::LibraryPropose(p) => Some(p.clone()),
            _ => None,
        }).collect();
        assert_eq!(proposals.len(), 1);
        let p = &proposals[0][0];
        assert_eq!(p.host.as_deref(), Some("10.0.0.5"));
        assert_eq!(p.os_hint.as_deref(), Some("windows"));
        assert!(matches!(p.protocol, library::Protocol::Rdp));
        assert!(sent(&core).iter().all(|(m, _)| *m == Method::Get), "only reads reach the server");
    }

    #[test]
    fn families_map_to_hints_and_every_vm_menu_offers_save() {
        assert_eq!(os_hint(Some("WINDOWS")), Some("windows"));
        assert_eq!(os_hint(Some("linux")), Some("linux"));
        assert_eq!(os_hint(Some("SOLARIS")), Some("other"));
        assert_eq!(os_hint(None), None);
        assert_eq!(proposal("  db  ", None, None).label, "db");
        assert_eq!(saved_text(2), "Saved 2 connections.");
    }

    #[test]
    fn snapshots_on_an_old_vcenter_are_refused_in_plain_words() {
        let core = run_plugin::<Vmware>(FakeCore::new().respond(server)
            .with(Event::Children(ChildrenAsk { ask: 9, view: 1, node: TREE, parent: Some("vm-42".into()) })));
        assert!(core.plain_calls().iter().any(|c| matches!(c, CoreCall::Refuse(9, t) if t.contains("9.0"))), "{:?}", core.plain_calls());
    }

    /// The refusal happens before any await, so polling once is enough.
    fn block<F: std::future::Future>(f: F) -> F::Output {
        let mut f = Box::pin(f);
        let waker = std::task::Waker::noop();
        match f.as_mut().poll(&mut std::task::Context::from_waker(waker)) {
            std::task::Poll::Ready(v) => v,
            std::task::Poll::Pending => panic!("it waited"),
        }
    }

    fn entry_with(allow: bool, snapshot: bool) -> bastion_plugin_sdk::Entry {
        let mut e = entry(allow);
        e.fields.push((SNAPSHOT_BEFORE_CONNECT.into(), snapshot.to_string()));
        e
    }

    fn identity_server(family: &'static str) -> impl Fn(u32, &CoreCall) -> Vec<Event> {
        move |id, call| match call {
            CoreCall::HttpSend(r) if r.target == "/api/vcenter/vm/vm-42/guest/identity" => vec![reply(id, ok(&format!(r#"{{"family":"{family}"}}"#)))],
            _ => tree_server(id, call),
        }
    }

    fn opened(core: &FakeCore) -> Vec<(Protocol, String)> {
        core.plain_calls().into_iter().filter_map(|c| match c {
            CoreCall::OpenConnection(r) => Some((r.protocol, r.host.clone())),
            _ => None,
        }).collect()
    }

    #[test]
    fn the_sidebar_view_is_one_tree_and_offers_no_changes() {
        assert_eq!(ui::check(&sidebar_view()), Ok(()));
        assert_eq!(sidebar_view().len(), 1);
        let mut core = FakeCore::new().respond(tree_server);
        core.entry = Some(entry(true));
        let core = run_plugin::<Vmware>(core
            .with(Event::OpenView(OpenView { view: 1, name: SIDEBAR.into() }))
            .with(Event::Children(ChildrenAsk { ask: 1, view: 1, node: SIDEBAR_TREE, parent: Some("host-21".into()) })));
        let view = last_view(&core);
        assert_eq!(view.len(), 1);
        assert!(matches!(view[0].component, Component::Tree(_)) && view[0].parent.is_none());
        assert!(sent(&core).iter().all(|(m, _)| *m == Method::Get), "opening the sidebar loads no dashboard and changes nothing");
        let ids: Vec<_> = children(&core)[0].1[0].menu.iter().map(|m| m.id.clone()).collect();
        assert_eq!(ids, vec!["open", "connect-ssh", "connect-rdp", "connect-vnc", "save-connection"], "no power or snapshots in the sidebar, even with changes allowed");
    }

    #[test]
    fn double_click_connects_by_rdp_to_windows_and_ssh_to_others() {
        for (family, want) in [("WINDOWS", Protocol::Rdp), ("LINUX", Protocol::Ssh)] {
            let mut core = FakeCore::new().respond(identity_server(family));
            core.entry = Some(entry(false));
            let core = run_plugin::<Vmware>(core.with(Event::OpenView(OpenView { view: 1, name: SIDEBAR.into() })).with(Event::Ui(UiEvent { view: 1, node: SIDEBAR_TREE, input: Input::Menu(("vm-42".into(), "open".into())) })));
            assert_eq!(opened(&core), vec![(want, "10.0.0.5".to_string())], "{family}");
        }
    }

    #[test]
    fn snapshot_before_connect_needs_both_toggles_and_comes_first() {
        let mut core = FakeCore::new().respond(identity_server("LINUX"));
        core.entry = Some(entry_with(true, true));
        let core = run_plugin::<Vmware>(core.with(menu("vm-42", "connect-ssh")));
        let calls = core.plain_calls();
        let snap = calls.iter().position(|c| matches!(c, CoreCall::HttpSend(r) if r.method == Method::Post && r.target == "/api/vcenter/vm/vm-42/snapshots")).expect("a snapshot");
        let open = calls.iter().position(|c| matches!(c, CoreCall::OpenConnection(_))).expect("then the connect");
        assert!(snap < open);
        assert!(!calls.iter().any(|c| matches!(c, CoreCall::Confirm(..))), "the entry toggles are the consent; the core's sheet confirms the connect");
        for (allow, snapshot) in [(false, true), (true, false)] {
            let mut core = FakeCore::new().respond(identity_server("LINUX"));
            core.entry = Some(entry_with(allow, snapshot));
            let core = run_plugin::<Vmware>(core.with(menu("vm-42", "connect-ssh")));
            assert!(sent(&core).iter().all(|(m, _)| *m == Method::Get), "no snapshot with allow={allow} snapshot={snapshot}");
            assert_eq!(opened(&core).len(), 1);
        }
    }

    // ---- standalone ESXi (VMW-ESXI): the same tree and menus over SOAP, against the mock host ----

    use crate::test_esxi as esxi;

    use std::cell::RefCell as Shared;

    /// Plays the core for an ESXi entry: every request must be a SOAP POST to /sdk/ with the
    /// login asked for; the core's session login is simulated once.
    fn esxi_core(host: Rc<Shared<esxi::Esxi>>, entry: bastion_plugin_sdk::Entry) -> FakeCore {
        let mut core = FakeCore::new().respond(move |id, call| match call {
            CoreCall::HttpSend(r) => {
                assert_eq!((r.method, r.target.as_str()), (Method::Post, "/sdk/"), "SOAP only");
                assert!(r.with_login, "the core adds the session");
                assert!(r.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("authorization") && !n.eq_ignore_ascii_case("cookie")));
                let body = String::from_utf8(r.body.clone()).unwrap();
                assert!(!body.contains("Login"), "the plugin never logs in");
                let mut h = host.borrow_mut();
                if h.session.is_none() {
                    let login = format!("<Login><userName>{}</userName><password>{}</password></Login>", esxi::USER, esxi::PASSWORD);
                    h.answer(&login, None);
                }
                let session = h.session.clone();
                let (code, out, _) = h.answer(&body, session.as_deref());
                status(id, code, out.as_bytes())
            }
            CoreCall::Confirm(..) => vec![reply(id, Ok(ReplyValue::Confirmed(true)))],
            CoreCall::OpenConnection(_) => vec![reply(id, Ok(ReplyValue::Connection(true)))],
            _ => vec![],
        });
        core.entry = Some(entry);
        core
    }

    fn esxi_entry(allow: bool) -> bastion_plugin_sdk::Entry {
        bastion_plugin_sdk::Entry { id: "e2".into(), name: "esxi".into(), host: "esxi.lab".into(), port: 443, fields: vec![(ALLOW_CHANGES.into(), allow.to_string()), (TYPE_FIELD.into(), "esxi".into())] }
    }

    #[test]
    fn an_esxi_tab_reads_the_host_over_soap() {
        let host = Rc::new(Shared::new(esxi::Esxi::default()));
        let core = run_plugin::<Vmware>(esxi_core(host.clone(), esxi_entry(false)).with(Event::OpenView(OpenView { view: 1, name: "esxi".into() })));
        let view = last_view(&core);
        assert!(matches!(&view[SUMMARY as usize].component, Component::Label(t) if t == "ESXi · 2 of 3 VMs on"), "{:?}", view[SUMMARY as usize]);
        assert!(matches!(&view[TABLE as usize].component, Component::Table(t) if t.total_rows == Some(3)));
        assert_eq!(host.borrow().logins, 1);
    }

    #[test]
    fn the_esxi_sidebar_lists_host_and_vms_and_double_click_connects() {
        let host = Rc::new(Shared::new(esxi::Esxi::default()));
        let core = run_plugin::<Vmware>(esxi_core(host.clone(), esxi_entry(true))
            .with(Event::OpenView(OpenView { view: 1, name: SIDEBAR.into() }))
            .with(Event::Children(ChildrenAsk { ask: 1, view: 1, node: SIDEBAR_TREE, parent: None }))
            .with(Event::Children(ChildrenAsk { ask: 2, view: 1, node: SIDEBAR_TREE, parent: Some("host-ha-host".into()) }))
            .with(Event::Ui(UiEvent { view: 1, node: SIDEBAR_TREE, input: Input::Menu(("vm-2".into(), "open".into())) }))
            .with(Event::Ui(UiEvent { view: 1, node: SIDEBAR_TREE, input: Input::Menu(("vm-1".into(), "open".into())) })));
        let c = children(&core);
        assert_eq!((c[0].1[0].key.as_str(), c[0].1[0].label.as_str()), ("host-ha-host", "esxi-mock.lab.example"));
        assert_eq!(c[1].1.iter().map(|i| i.label.as_str()).collect::<Vec<_>>(), vec!["web01", "dc01", "build"], "the host's order, as for vCenter");
        let ids: Vec<_> = c[1].1[0].menu.iter().map(|m| m.id.as_str()).collect();
        assert_eq!(ids, vec!["open", "connect-ssh", "connect-rdp", "connect-vnc", "save-connection"], "the sidebar offers no changes");
        assert_eq!(opened(&core), vec![(Protocol::Rdp, "192.0.2.12".to_string()), (Protocol::Ssh, "192.0.2.11".to_string())], "RDP to the Windows guest, SSH to Linux");
        assert!(host.borrow().calls.iter().all(|m| m.starts_with("RetrievePropertiesEx")), "{:?}", host.borrow().calls);
    }

    #[test]
    fn esxi_power_and_snapshots_need_allow_changes_and_a_confirm() {
        let host = Rc::new(Shared::new(esxi::Esxi::default()));
        let esxi_menu = |key: &str, id: &str| Event::Ui(UiEvent { view: 1, node: TREE, input: Input::Menu((key.into(), id.into())) });
        let core = run_plugin::<Vmware>(esxi_core(host.clone(), esxi_entry(false)).with(Event::OpenView(OpenView { view: 1, name: "esxi".into() })).with(esxi_menu("vm-1", "stop")));
        assert!(core.plain_calls().iter().all(|c| !matches!(c, CoreCall::Confirm(..))), "read-only: refused without asking");
        assert!(host.borrow().calls.iter().all(|m| m.starts_with("RetrievePropertiesEx")));
        let host = Rc::new(Shared::new(esxi::Esxi::default()));
        let core = run_plugin::<Vmware>(esxi_core(host.clone(), esxi_entry(true))
            .with(Event::OpenView(OpenView { view: 1, name: "esxi".into() }))
            .with(Event::Children(ChildrenAsk { ask: 1, view: 1, node: TREE, parent: Some("host-ha-host".into()) }))
            .with(esxi_menu("vm-1", "stop"))
            .with(esxi_menu("vm-1", "snapshot-take")));
        let confirms = core.plain_calls().iter().filter(|c| matches!(c, CoreCall::Confirm(..))).count();
        assert_eq!(confirms, 2);
        let calls = host.borrow().calls.clone();
        assert!(calls.contains(&"PowerOffVM_Task 1".to_string()), "{calls:?}");
        assert!(calls.iter().any(|m| m.starts_with("CreateSnapshot_Task 1 ")), "{calls:?}");
        assert_eq!(host.borrow().vms["1"].power, "poweredOff");
    }

}
