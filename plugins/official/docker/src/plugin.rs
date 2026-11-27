//! The plugin component (feature `plugin`): a Docker host dashboard.
//!
//! Every command is one of the manifest's `[[exec]]` templates, run by the core over the entry's
//! SSH login and route (plugin API 1.5); this code never sees the login. Start, stop, restart,
//! remove and the shell show only when the entry's "Allow changes" is on, and the core asks the
//! user to confirm each one in its own words, so the plugin adds no confirmation of its own.

use std::cell::RefCell;
use std::rc::Rc;

use bastion_plugin_sdk::bindings::bastion::plugin::events::RowsAsk;
use bastion_plugin_sdk::bindings::bastion::plugin::ui::{Cell, CodeEditor, Column, MenuItem, Row, Tree, TreeItem};
use bastion_plugin_sdk::exec;
use bastion_plugin_sdk::ui::{self, BannerLevel, Component, ViewBuilder};
use bastion_plugin_sdk::{host, task, Failure, Input, NodeId, Plugin, Task, View};

use crate::{classify, parse_lines, stats_for, valid_name, Container, DockerError, Image, Network, Stats, Volume};

/// Node ids of the dashboard, in the order [`dashboard`] adds them.
pub const TOOLBAR: NodeId = 1;
pub const REFRESH: NodeId = 2;
pub const SUMMARY: NodeId = 3;
/// Messages: a busy mark, a banner, or an empty label.
pub const STATUS: NodeId = 4;
pub const TABS: NodeId = 5;
pub const CONTAINERS_TAB: NodeId = 6;
pub const CONTAINERS: NodeId = 7;
pub const IMAGES_TAB: NodeId = 8;
pub const IMAGES: NodeId = 9;
pub const VOLUMES_TAB: NodeId = 10;
pub const VOLUMES: NodeId = 11;
pub const NETWORKS_TAB: NodeId = 12;
pub const NETWORKS: NodeId = 13;

pub const CONTAINER_COLUMNS: [&str; 5] = ["Image", "State", "Ports", "CPU", "Memory"];
pub const IMAGE_COLUMNS: [&str; 4] = ["Repository:Tag", "ID", "Size", "Created"];
pub const VOLUME_COLUMNS: [&str; 3] = ["Name", "Driver", "Mount point"];
pub const NETWORK_COLUMNS: [&str; 4] = ["Name", "Driver", "Scope", "ID"];

/// The entry field that allows changes (manifest `connection_types.fields`).
pub const ALLOW_CHANGES: &str = "allow-changes";
/// Log lines shown in the Logs dialog.
pub const LOG_LINES: &str = "500";
/// Time limits, ms: reading, and a change (stop waits up to 10 s for the container).
const READ_MS: u32 = 30_000;
const CHANGE_MS: u32 = 60_000;

fn columns(titles: &[&str]) -> Vec<Column> {
    titles.iter().map(|t| Column { title: (*t).into(), sortable: false, editable: false }).collect()
}

fn table_of(titles: &[&str], rows: usize) -> Component {
    let mut t = ui::table(titles);
    if let Component::Table(t) = &mut t {
        t.total_rows = Some(rows as u64);
    }
    t
}

/// The dashboard: a toolbar with Refresh and the summary, a message line, and a tab each for
/// containers (a list with actions), images, volumes and networks.
pub fn dashboard(summary: &str, status: Component, counts: [usize; 3]) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, Component::Toolbar), TOOLBAR);
    assert_eq!(b.add(TOOLBAR, ui::button("Refresh")), REFRESH);
    assert_eq!(b.add(TOOLBAR, ui::label(summary)), SUMMARY);
    assert_eq!(b.add(root, status), STATUS);
    assert_eq!(b.add(root, Component::Tabs), TABS);
    assert_eq!(b.add(TABS, Component::Tab("Containers".into())), CONTAINERS_TAB);
    assert_eq!(b.add(CONTAINERS_TAB, Component::Tree(Tree { columns: columns(&CONTAINER_COLUMNS) })), CONTAINERS);
    assert_eq!(b.add(TABS, Component::Tab("Images".into())), IMAGES_TAB);
    assert_eq!(b.add(IMAGES_TAB, table_of(&IMAGE_COLUMNS, counts[0])), IMAGES);
    assert_eq!(b.add(TABS, Component::Tab("Volumes".into())), VOLUMES_TAB);
    assert_eq!(b.add(VOLUMES_TAB, table_of(&VOLUME_COLUMNS, counts[1])), VOLUMES);
    assert_eq!(b.add(TABS, Component::Tab("Networks".into())), NETWORKS_TAB);
    assert_eq!(b.add(NETWORKS_TAB, table_of(&NETWORK_COLUMNS, counts[2])), NETWORKS);
    b.finish()
}

fn item(id: &str, title: &str) -> MenuItem {
    MenuItem { id: id.into(), title: title.into() }
}

/// A container's menu: Logs always; the rest only when changes are allowed.
pub fn container_menu(c: &Container, may_change: bool) -> Vec<MenuItem> {
    let mut m = vec![item("logs", "Logs")];
    if may_change {
        if c.running() {
            m.push(item("shell", "Open Shell"));
            m.push(item("stop", "Stop"));
            m.push(item("restart", "Restart"));
        } else {
            m.push(item("start", "Start"));
            m.push(item("remove", "Remove"));
        }
    }
    m
}

/// One tree item per container, keyed by its full id.
pub fn container_items(cs: &[Container], stats: &[Stats], may_change: bool) -> Vec<TreeItem> {
    cs.iter()
        .filter(|c| valid_name(&c.id))
        .map(|c| {
            let s = stats_for(stats, &c.id);
            TreeItem {
                key: c.id.clone(),
                label: if c.name().is_empty() { c.short_id().into() } else { c.name().into() },
                icon: None,
                has_children: false,
                cells: vec![
                    Cell::Text(c.image.clone()),
                    Cell::Text(c.status.clone()),
                    Cell::Text(c.ports.clone()),
                    Cell::Text(s.map(|s| s.cpu.clone()).unwrap_or_default()),
                    Cell::Text(s.map(|s| s.mem_usage.clone()).unwrap_or_default()),
                ],
                menu: container_menu(c, may_change),
            }
        })
        .collect()
}

pub fn image_rows(is: &[Image]) -> Vec<Row> {
    is.iter().map(|i| Row { key: i.id.clone(), cells: vec![Cell::Text(i.reference()), Cell::Text(i.short_id().into()), Cell::Text(i.size.clone()), Cell::Text(i.created.clone())] }).collect()
}

pub fn volume_rows(vs: &[Volume]) -> Vec<Row> {
    vs.iter().map(|v| Row { key: v.name.clone(), cells: vec![Cell::Text(v.name.clone()), Cell::Text(v.driver.clone()), Cell::Text(v.mountpoint.clone())] }).collect()
}

pub fn network_rows(ns: &[Network]) -> Vec<Row> {
    ns.iter().map(|n| Row { key: n.id.clone(), cells: vec![Cell::Text(n.name.clone()), Cell::Text(n.driver.clone()), Cell::Text(n.scope.clone()), Cell::Text(n.id[..n.id.len().min(12)].into())] }).collect()
}

/// The summary in the toolbar.
pub fn summary(version: &str, cs: &[Container]) -> String {
    let running = cs.iter().filter(|c| c.running()).count();
    let v = version.trim().trim_matches('"');
    if v.is_empty() {
        format!("{running} of {} containers running", cs.len())
    } else {
        format!("Docker {v} · {running} of {} containers running", cs.len())
    }
}

fn may_change() -> bool {
    host::entry().is_some_and(|e| e.fields.iter().any(|(k, v)| k == ALLOW_CHANGES && v == "true"))
}

/// What a failed call says.
#[derive(Debug, Clone)]
pub enum Error {
    Docker(DockerError),
    /// The core or the app refused or could not run the command (no login, host key, policy,
    /// time out, the user declined a change).
    Core(Failure),
}

pub fn message(e: &Error) -> String {
    match e {
        Error::Docker(d) => d.message(),
        Error::Core(Failure::Denied(t)) => format!("Not run: {t}"),
        Error::Core(Failure::TimedOut) => "Docker did not answer in time.".into(),
        Error::Core(Failure::Io(t)) => format!("The SSH connection failed: {t}"),
        Error::Core(f) => format!("{f:?}"),
    }
}

/// Runs a template; a non-zero exit becomes a [`DockerError`].
pub async fn run(template: &str, args: &[(&str, &str)], ms: u32) -> Result<String, Error> {
    let out = exec::run(template, args, ms).await.map_err(Error::Core)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.exit != Some(0) {
        return Err(Error::Docker(classify(out.exit, &stderr)));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[derive(Default)]
pub struct Docker {
    containers: RefCell<Vec<Container>>,
    stats: RefCell<Vec<Stats>>,
    images: RefCell<Vec<Row>>,
    volumes: RefCell<Vec<Row>>,
    networks: RefCell<Vec<Row>>,
}

fn show(view: View, status: Component) {
    let _ = view.patch(vec![ui::Node { id: STATUS, parent: Some(0), component: status }], vec![]);
}

impl Docker {
    async fn refresh(self: Rc<Self>, view: View) {
        show(view, Component::Progress(None));
        let result: Result<(String, usize), Error> = async {
            let version = run("version", &[], READ_MS).await?;
            let ps = parse_lines::<Container>(&run("ps", &[], READ_MS).await?);
            // Stats only cover running containers; a failure here leaves the columns empty.
            let stats = match run("stats", &[], READ_MS).await {
                Ok(t) => parse_lines::<Stats>(&t).items,
                Err(_) => Vec::new(),
            };
            let images = parse_lines::<Image>(&run("images", &[], READ_MS).await?);
            let volumes = parse_lines::<Volume>(&run("volumes", &[], READ_MS).await?);
            let networks = parse_lines::<Network>(&run("networks", &[], READ_MS).await?);
            let skipped = ps.skipped + images.skipped + volumes.skipped + networks.skipped;
            let text = summary(&version, &ps.items);
            *self.containers.borrow_mut() = ps.items;
            *self.stats.borrow_mut() = stats;
            *self.images.borrow_mut() = image_rows(&images.items);
            *self.volumes.borrow_mut() = volume_rows(&volumes.items);
            *self.networks.borrow_mut() = network_rows(&networks.items);
            let counts = [self.images.borrow().len(), self.volumes.borrow().len(), self.networks.borrow().len()];
            let status = if skipped > 0 { ui::label(&format!("{skipped} lines of Docker's output could not be read.")) } else { ui::label("") };
            // The tree then asks for its items (`children`), the tables for their rows (`rows`).
            let nodes = dashboard(&text, status, counts);
            let tree = nodes.iter().find(|n| n.id == CONTAINERS).cloned();
            let _ = view.set(nodes);
            // Sent again as a patch, the tree is reloaded by both apps (as PostgreSQL's Refresh does): a
            // whole new view keeps the answer to an ask made while "Loading" showed (docker02).
            if let Some(tree) = tree {
                let _ = view.patch(vec![tree], vec![]);
            }
            Ok((text, skipped))
        }
        .await;
        if let Err(e) = result {
            let _ = view.set(dashboard("Not connected", ui::banner(BannerLevel::Error, &message(&e)), [0, 0, 0]));
        }
    }

    fn name_of(&self, id: &str) -> String {
        self.containers.borrow().iter().find(|c| c.id == id).map(|c| c.name().to_string()).unwrap_or_else(|| id[..id.len().min(12)].into())
    }

    async fn logs(self: Rc<Self>, view: View, id: String) {
        let name = self.name_of(&id);
        match exec::run("logs", &[("lines", LOG_LINES), ("id", &id)], READ_MS).await {
            Ok(out) if out.exit == Some(0) => {
                // `docker logs` writes the container's stderr to stderr: show both, in order of stream.
                let mut text = format!("Last {LOG_LINES} lines\n");
                text.push_str(&String::from_utf8_lossy(&out.stdout));
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                if out.truncated {
                    text.push_str("\n[cut at 4 MiB]");
                }
                let mut b = ViewBuilder::new(ui::stack());
                let root = b.root();
                b.add(root, Component::CodeEditor(CodeEditor { language: "text".into(), text, read_only: true }));
                let title: String = format!("Logs: {name}").chars().take(ui::MAX_LABEL).collect();
                if view.open_dialog(&title, b.finish()).is_err() {
                    show(view, ui::banner(BannerLevel::Error, "The logs could not be shown."));
                }
            }
            Ok(out) => show(view, ui::banner(BannerLevel::Error, &DockerError::message(&classify(out.exit, &String::from_utf8_lossy(&out.stderr))))),
            Err(f) => show(view, ui::banner(BannerLevel::Error, &message(&Error::Core(f)))),
        }
    }

    async fn menu(self: Rc<Self>, view: View, id: String, action: String) {
        if !valid_name(&id) {
            return;
        }
        let name = self.name_of(&id);
        match action.as_str() {
            "logs" => return self.logs(view, id).await,
            "shell" => {
                match exec::terminal("shell", &[("id", &id)], &format!("{name} shell")).await {
                    Ok(true) | Ok(false) => {}
                    Err(f) => show(view, ui::banner(BannerLevel::Error, &message(&Error::Core(f)))),
                }
                return;
            }
            "start" | "stop" | "restart" | "remove" => {}
            _ => return,
        }
        show(view, Component::Progress(None));
        match run(&action, &[("id", &id)], CHANGE_MS).await {
            Ok(_) => {
                self.clone().refresh(view).await;
                show(view, ui::label(&format!("{name}: {action} done.")));
            }
            Err(e) => show(view, ui::banner(BannerLevel::Error, &message(&e))),
        }
    }
}

impl Plugin for Docker {
    fn start() -> Self {
        Docker::default()
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        task(async move {
            let _ = view.set(dashboard("Loading", Component::Progress(None), [0, 0, 0]));
            self.refresh(view).await;
        })
    }

    fn command(self: Rc<Self>, id: String, view: Option<View>) -> Task {
        match (id.as_str(), view) {
            ("refresh", Some(view)) => task(self.refresh(view)),
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        match (node, input) {
            (REFRESH, Input::Pressed) => task(self.refresh(view)),
            (CONTAINERS, Input::Menu((key, id))) => task(self.menu(view, key, id)),
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn rows(self: Rc<Self>, ask: RowsAsk) -> Task {
        let all = match ask.node {
            IMAGES => self.images.borrow().clone(),
            VOLUMES => self.volumes.borrow().clone(),
            NETWORKS => self.networks.borrow().clone(),
            _ => Vec::new(),
        };
        let start = (ask.offset as usize).min(all.len());
        let end = start.saturating_add(ask.count as usize).min(all.len()).min(start + ui::MAX_ROWS);
        let _ = ui::provide_rows(ask.ask, &all[start..end], Some(all.len() as u64));
        bastion_plugin_sdk::done()
    }

    /// The container list, read when the app asks for it (as the Proxmox plugin does): an app may
    /// ask once, while "Loading" shows, and not again after the dashboard is set, so the answer
    /// never comes from a cache that may still be empty.
    fn children(self: Rc<Self>, ask: bastion_plugin_sdk::bindings::bastion::plugin::events::ChildrenAsk) -> Task {
        if ask.parent.is_some() {
            let _ = ui::provide_children(ask.ask, &[]);
            return bastion_plugin_sdk::done();
        }
        task(async move {
            match run("ps", &[], READ_MS).await {
                Ok(text) => {
                    let stats = match run("stats", &[], READ_MS).await {
                        Ok(t) => parse_lines::<Stats>(&t).items,
                        Err(_) => Vec::new(),
                    };
                    *self.containers.borrow_mut() = parse_lines::<Container>(&text).items;
                    *self.stats.borrow_mut() = stats;
                    let items = container_items(&self.containers.borrow(), &self.stats.borrow(), may_change());
                    let _ = ui::provide_children(ask.ask, &items);
                }
                Err(e) => ui::refuse(ask.ask, &message(&e)),
            }
        })
    }
}

#[cfg(target_arch = "wasm32")]
bastion_plugin_sdk::export_plugin!(Docker);

#[cfg(test)]
mod tests {
    use super::*;
    use bastion_plugin_sdk::bindings::bastion::plugin::events::{ChildrenAsk, Event, OpenView, ReplyValue, UiEvent};
    use bastion_plugin_sdk::bindings::bastion::plugin::types::{Entry, ExecOutput};
    use bastion_plugin_sdk::testing::{reply, run_plugin, Call as CoreCall, FakeCore};

    const PS: &str = include_str!("../tests/fixtures/ps.jsonl");
    const STATS: &str = include_str!("../tests/fixtures/stats.jsonl");
    const IMAGES: &str = include_str!("../tests/fixtures/images.jsonl");
    const VOLUMES: &str = include_str!("../tests/fixtures/volumes.jsonl");
    const NETWORKS: &str = include_str!("../tests/fixtures/networks.jsonl");
    const WEB: &str = "3f1c9a2b7d8e4f60a1b2c3d4e5f60718293a4b5c6d7e8f9012345678abcdef01";

    fn out(exit: i32, stdout: &str, stderr: &str) -> Result<ReplyValue, Failure> {
        Ok(ReplyValue::Exec(ExecOutput { exit: Some(exit), stdout: stdout.as_bytes().to_vec(), stderr: stderr.as_bytes().to_vec(), truncated: false }))
    }

    fn host(id: u32, call: &CoreCall) -> Vec<Event> {
        let CoreCall::ExecRun(t, _, _) = call else { return vec![] };
        let text = match t.as_str() {
            "version" => "\"27.3.1\"\n",
            "ps" => PS,
            "stats" => STATS,
            "images" => IMAGES,
            "volumes" => VOLUMES,
            "networks" => NETWORKS,
            "logs" => "2026-11-23T10:00:00Z started\n",
            _ => "",
        };
        vec![reply(id, out(0, text, ""))]
    }

    fn open() -> Event {
        Event::OpenView(OpenView { view: 1, name: "host".into() })
    }

    fn entry(allow: bool) -> Option<Entry> {
        Some(Entry { id: "e1".into(), name: "docker1".into(), host: "docker1.lab".into(), port: 22, fields: vec![(ALLOW_CHANGES.into(), allow.to_string())] })
    }

    fn templates(core: &FakeCore) -> Vec<String> {
        core.plain_calls().into_iter().filter_map(|c| if let CoreCall::ExecRun(t, _, _) = c { Some(t.clone()) } else { None }).collect()
    }

    fn last_view(core: &FakeCore) -> Vec<ui::Node> {
        core.plain_calls().into_iter().rev().find_map(|c| if let CoreCall::SetView(_, n) = c { Some(n.clone()) } else { None }).unwrap()
    }

    #[test]
    fn the_dashboard_passes_the_checks() {
        assert_eq!(ui::check(&dashboard("Loading", Component::Progress(None), [0, 0, 0])), Ok(()));
        assert_eq!(ui::check(&dashboard("x", ui::banner(BannerLevel::Error, &"x".repeat(500)), [10_000, 5, 5])), Ok(()));
    }

    #[test]
    fn opening_reads_everything_through_declared_commands_only() {
        let mut core = FakeCore::new().respond(host).with(open());
        core.entry = entry(false);
        let core = run_plugin::<Docker>(core);
        assert_eq!(templates(&core), ["version", "ps", "stats", "images", "volumes", "networks"]);
        let view = last_view(&core);
        let summary = view.iter().find(|n| n.id == SUMMARY).unwrap();
        assert!(matches!(&summary.component, Component::Label(t) if t == "Docker 27.3.1 · 1 of 2 containers running"), "{:?}", summary.component);
    }

    #[test]
    fn container_items_carry_stats_and_menus_follow_allow_changes() {
        let cs = parse_lines::<Container>(PS).items;
        let st = parse_lines::<Stats>(STATS).items;
        let ro = container_items(&cs, &st, false);
        assert_eq!(ro[0].label, "web");
        assert!(matches!(&ro[0].cells[3], Cell::Text(t) if t == "0.12%"));
        assert_eq!(ro[0].menu.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), ["logs"]);
        let rw = container_items(&cs, &st, true);
        assert_eq!(rw[0].menu.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), ["logs", "shell", "stop", "restart"]);
        assert_eq!(rw[1].menu.iter().map(|m| m.id.as_str()).collect::<Vec<_>>(), ["logs", "start", "remove"]);
    }

    #[test]
    fn a_stop_runs_the_template_with_the_container_id_then_refreshes() {
        let mut core = FakeCore::new()
            .respond(host)
            .with(open())
            .with(Event::Ui(UiEvent { view: 1, node: CONTAINERS, input: Input::Menu((WEB.into(), "stop".into())) }));
        core.entry = entry(true);
        let core = run_plugin::<Docker>(core);
        let stop = core.plain_calls().into_iter().find_map(|c| match c {
            CoreCall::ExecRun(t, a, _) if t == "stop" => Some(a.clone()),
            _ => None,
        });
        assert_eq!(stop, Some(vec![("id".to_string(), WEB.to_string())]));
        assert!(!core.plain_calls().iter().any(|c| matches!(c, CoreCall::Confirm(..))), "the core confirms a change, not the plugin");
        assert_eq!(templates(&core).iter().filter(|t| *t == "ps").count(), 2, "refreshed after the change");
    }

    #[test]
    fn a_bad_key_never_reaches_a_command() {
        let mut core = FakeCore::new()
            .respond(host)
            .with(Event::Ui(UiEvent { view: 1, node: CONTAINERS, input: Input::Menu(("-v".into(), "remove".into())) }));
        core.entry = entry(true);
        assert!(templates(&run_plugin::<Docker>(core)).is_empty());
    }

    #[test]
    fn logs_open_in_a_read_only_dialog_and_the_shell_in_a_terminal() {
        let mut core = FakeCore::new()
            .respond(|id, c| match c {
                CoreCall::ExecTerminal(..) => vec![reply(id, Ok(ReplyValue::Connection(true)))],
                _ => host(id, c),
            })
            .with(open())
            .with(Event::Ui(UiEvent { view: 1, node: CONTAINERS, input: Input::Menu((WEB.into(), "logs".into())) }))
            .with(Event::Ui(UiEvent { view: 1, node: CONTAINERS, input: Input::Menu((WEB.into(), "shell".into())) }));
        core.entry = entry(true);
        let core = run_plugin::<Docker>(core);
        let dialog = core.plain_calls().into_iter().find_map(|c| if let CoreCall::OpenDialog(_, t, n) = c { Some((t.clone(), n.clone())) } else { None }).unwrap();
        assert!(dialog.0.starts_with("Logs: "));
        assert!(dialog.1.iter().any(|n| matches!(&n.component, Component::CodeEditor(e) if e.read_only && e.text.contains("started"))));
        assert!(core.plain_calls().iter().any(|c| matches!(c, CoreCall::ExecTerminal(t, a, _) if t == "shell" && a[0].1 == WEB)));
    }

    #[test]
    fn a_permission_error_says_what_to_do_with_its_code() {
        let mut core = FakeCore::new()
            .respond(|id, c| match c {
                CoreCall::ExecRun(t, _, _) if t == "version" => vec![reply(id, out(1, "", "permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock"))],
                _ => host(id, c),
            })
            .with(open());
        core.entry = entry(false);
        let view = last_view(&run_plugin::<Docker>(core));
        let status = view.iter().find(|n| n.id == STATUS).unwrap();
        assert!(matches!(&status.component, Component::Banner(b) if b.text.contains("docker group") && b.text.contains("GT-PLUG-004")), "{:?}", status.component);
    }

    #[test]
    fn the_tree_asks_for_containers_and_tables_for_rows() {
        // The app asks for the tree's items once the dashboard is set: after the last command.
        let mut core = FakeCore::new()
            .respond(|id, c| {
                let mut events = host(id, c);
                if matches!(c, CoreCall::ExecRun(t, _, _) if t == "networks") {
                    events.push(Event::Children(ChildrenAsk { ask: 9, view: 1, node: CONTAINERS, parent: None }));
                }
                events
            })
            .with(open());
        core.entry = entry(false);
        let core = run_plugin::<Docker>(core);
        let items = core.plain_calls().into_iter().find_map(|c| if let CoreCall::ProvideChildren(9, i) = c { Some(i.clone()) } else { None }).unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn each_load_patches_the_container_tree_so_the_apps_reload_it() {
        let mut core = FakeCore::new().respond(host).with(open());
        core.entry = entry(false);
        let core = run_plugin::<Docker>(core);
        let patched = core.plain_calls().into_iter().any(|c| matches!(c, CoreCall::PatchView(_, up, _) if up.iter().any(|n| n.id == CONTAINERS && matches!(n.component, Component::Tree(_)))));
        assert!(patched, "the tree is re-sent after the dashboard");
    }

    #[test]
    fn an_ask_before_the_dashboard_is_set_still_gets_the_containers() {
        // Windows asks once, while "Loading" shows, before the first command has answered.
        let mut core = FakeCore::new().respond(host).with(open()).with(Event::Children(ChildrenAsk { ask: 8, view: 1, node: CONTAINERS, parent: None }));
        core.entry = entry(false);
        let core = run_plugin::<Docker>(core);
        let items = core.plain_calls().into_iter().find_map(|c| if let CoreCall::ProvideChildren(8, i) = c { Some(i.clone()) } else { None }).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].label, "web");
    }
}
