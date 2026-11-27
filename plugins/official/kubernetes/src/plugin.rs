//! The plugin component (feature `plugin`): a cluster dashboard with a namespace filter and
//! tabs for pods, deployments, services and nodes; pod logs in a dialog; and, when the entry
//! allows changes, delete pod, scale and rollout restart, each confirmed first (`ui.confirm`).
//!
//! Every request goes through the core's `http.send` with `with-login`: the core adds the
//! entry's ServiceAccount token as `Authorization: Bearer …` (manifest `[http] auth`), runs TLS
//! against the entry's trust (verify-full or a pinned certificate) and the entry's route (an
//! SSH jump or tunnel). This code never sees the token. No kubectl and no Docker are involved.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use bastion_plugin_sdk::bindings::bastion::plugin::events::RowsAsk;
use bastion_plugin_sdk::bindings::bastion::plugin::ui::{Button, Cell, ChoiceField, CodeEditor, NumberField, Row};
use bastion_plugin_sdk::http::{self as http, Method as HttpMethod};
use bastion_plugin_sdk::ui::{self, BannerLevel, Component, ConfirmKind, ViewBuilder};
use bastion_plugin_sdk::{host, log, task, Failure, Input, NodeId, Plugin, Task, View};

use crate::api::{calls, message, Access, Call, Error, MAX_REPLICAS};
use crate::model::{self, age, Deployment, Node, Pod, PodMetrics, Service};
use crate::{Method, Response};

pub const TOOLBAR: NodeId = 1;
pub const REFRESH: NodeId = 2;
pub const NAMESPACE: NodeId = 3;
pub const LOGS: NodeId = 4;
pub const DELETE: NodeId = 5;
pub const SCALE: NodeId = 6;
pub const RESTART: NodeId = 7;
pub const SUMMARY: NodeId = 8;
/// A busy mark, a banner, or a one-line outcome.
pub const STATUS: NodeId = 9;
pub const TABS: NodeId = 10;
pub const PODS: NodeId = 12;
pub const DEPLOYMENTS: NodeId = 14;
pub const SERVICES: NodeId = 16;
pub const NODES: NodeId = 18;

pub const POD_COLUMNS: [&str; 9] = ["Name", "Namespace", "Status", "Ready", "Restarts", "Node", "Age", "CPU", "Memory"];
pub const DEPLOYMENT_COLUMNS: [&str; 6] = ["Name", "Namespace", "Ready", "Up-to-date", "Available", "Age"];
pub const SERVICE_COLUMNS: [&str; 6] = ["Name", "Namespace", "Type", "Cluster IP", "Ports", "Age"];
pub const NODE_COLUMNS: [&str; 4] = ["Name", "Status", "Version", "Age"];

/// Entry fields (manifest `connection_types.fields`).
pub const ALLOW_CHANGES: &str = "allow-changes";
pub const NAMESPACE_FIELD: &str = "namespace";

pub const ALL_NAMESPACES: &str = "All namespaces";

/// Dialog node ids.
const D_VALUE: NodeId = 2;
const D_OK: NodeId = 4;
const D_CLOSE: NodeId = 5;

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn field(key: &str) -> Option<String> {
    host::entry().and_then(|e| e.fields.into_iter().find(|(k, _)| k == key).map(|(_, v)| v))
}

pub fn may_change() -> bool {
    field(ALLOW_CHANGES).as_deref() == Some("true")
}

fn access() -> Access {
    if may_change() { Access::MayChange } else { Access::ReadOnly }
}

fn short(s: &str) -> String {
    if s.chars().count() <= ui::MAX_LABEL {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(ui::MAX_LABEL - 1).collect();
        t.push('…');
        t
    }
}

fn button(label: &str, enabled: bool) -> Component {
    Component::Button(Button { label: label.into(), icon: None, enabled })
}

/// The dashboard: toolbar (Refresh, namespace filter, actions, summary), a status line, and a
/// tab per kind, each a table.
pub fn dashboard(summary: &str, status: Component, namespaces: &[String], selected: Option<usize>, counts: [usize; 4], changes: bool) -> Vec<ui::Node> {
    let mut b = ViewBuilder::new(ui::stack());
    let root = b.root();
    assert_eq!(b.add(root, Component::Toolbar), TOOLBAR);
    assert_eq!(b.add(TOOLBAR, ui::button("Refresh")), REFRESH);
    let mut options = vec![ALL_NAMESPACES.to_string()];
    options.extend(namespaces.iter().map(|n| short(n)));
    let choice = Component::Choice(ChoiceField { label: "Namespace".into(), options, selected: Some(selected.map_or(0, |i| i as u32 + 1)) });
    assert_eq!(b.add(TOOLBAR, choice), NAMESPACE);
    assert_eq!(b.add(TOOLBAR, ui::button("Logs")), LOGS);
    assert_eq!(b.add(TOOLBAR, button("Delete Pod", changes)), DELETE);
    assert_eq!(b.add(TOOLBAR, button("Scale", changes)), SCALE);
    assert_eq!(b.add(TOOLBAR, button("Restart", changes)), RESTART);
    assert_eq!(b.add(TOOLBAR, ui::label(&short(summary))), SUMMARY);
    assert_eq!(b.add(root, status), STATUS);
    assert_eq!(b.add(root, Component::Tabs), TABS);
    let tabs: [(&str, &[&str]); 4] = [("Pods", &POD_COLUMNS), ("Deployments", &DEPLOYMENT_COLUMNS), ("Services", &SERVICE_COLUMNS), ("Nodes", &NODE_COLUMNS)];
    for (i, (title, cols)) in tabs.iter().enumerate() {
        let tab = b.add(TABS, Component::Tab((*title).into()));
        let mut table = ui::table(cols);
        if let Component::Table(t) = &mut table {
            t.total_rows = Some(counts[i] as u64);
        }
        assert_eq!(b.add(tab, table), [PODS, DEPLOYMENTS, SERVICES, NODES][i]);
    }
    b.finish()
}

fn key(ns: &str, name: &str) -> String {
    format!("{ns}/{name}")
}

fn split_key(k: &str) -> Option<(&str, &str)> {
    k.split_once('/')
}

fn t(s: impl Into<String>) -> Cell {
    Cell::Text(s.into())
}

pub fn pod_rows(pods: &[Pod], metrics: Option<&[PodMetrics]>, now: i64) -> Vec<Row> {
    let usage: HashMap<String, (u64, u64)> = metrics.unwrap_or(&[]).iter().map(|m| (key(&m.metadata.namespace, &m.metadata.name), m.totals())).collect();
    let mut list: Vec<&Pod> = pods.iter().collect();
    list.sort_by(|a, b| (&a.metadata.namespace, &a.metadata.name).cmp(&(&b.metadata.namespace, &b.metadata.name)));
    list.into_iter()
        .map(|p| {
            let k = key(&p.metadata.namespace, &p.metadata.name);
            let (ready, all) = p.ready();
            let (cpu, mem) = match (metrics.is_some(), usage.get(&k)) {
                (true, Some((c, m))) => (t(model::cpu_text(*c)), t(model::mem_text(*m))),
                _ => (t("—"), t("—")),
            };
            Row {
                cells: vec![
                    t(p.metadata.name.clone()),
                    t(p.metadata.namespace.clone()),
                    t(p.status_text()),
                    t(format!("{ready}/{all}")),
                    Cell::Number(p.restarts() as f64),
                    t(p.spec.node_name.clone()),
                    t(age(&p.metadata.creation_timestamp, now)),
                    cpu,
                    mem,
                ],
                key: k,
            }
        })
        .collect()
}

pub fn deployment_rows(ds: &[Deployment], now: i64) -> Vec<Row> {
    ds.iter()
        .map(|d| Row {
            key: key(&d.metadata.namespace, &d.metadata.name),
            cells: vec![
                t(d.metadata.name.clone()),
                t(d.metadata.namespace.clone()),
                t(format!("{}/{}", d.status.ready_replicas, d.desired())),
                Cell::Number(d.status.updated_replicas as f64),
                Cell::Number(d.status.available_replicas as f64),
                t(age(&d.metadata.creation_timestamp, now)),
            ],
        })
        .collect()
}

pub fn service_rows(ss: &[Service], now: i64) -> Vec<Row> {
    ss.iter()
        .map(|s| Row {
            key: key(&s.metadata.namespace, &s.metadata.name),
            cells: vec![
                t(s.metadata.name.clone()),
                t(s.metadata.namespace.clone()),
                t(s.spec.kind.clone()),
                t(s.spec.cluster_ip.clone()),
                t(s.ports_text()),
                t(age(&s.metadata.creation_timestamp, now)),
            ],
        })
        .collect()
}

pub fn node_rows(ns: &[Node], now: i64) -> Vec<Row> {
    ns.iter()
        .map(|n| Row {
            key: n.metadata.name.clone(),
            cells: vec![
                t(n.metadata.name.clone()),
                t(if n.ready() { "Ready" } else { "NotReady" }),
                t(n.status.node_info.kubelet_version.clone()),
                t(age(&n.metadata.creation_timestamp, now)),
            ],
        })
        .collect()
}

/// Runs one call through the core's `http.send`, with the entry's login.
pub async fn run<R>(c: Call<R>, access: Access) -> Result<R, Error> {
    c.check(access)?;
    let method = match c.request.method {
        Method::Get => HttpMethod::Get,
        Method::Delete => HttpMethod::Delete,
        Method::Patch => HttpMethod::Patch,
    };
    let mut req = http::request(method, &c.request.target);
    req.headers.push(("Accept".into(), "application/json".into()));
    if let Some(ct) = c.request.content_type() {
        req.headers.push(("Content-Type".into(), ct.into()));
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
        Failure::TimedOut => "the server did not answer in time.".into(),
        Failure::Cancelled => "cancelled.".into(),
    }
}

/// An open Scale dialog: which deployment and the number in its field.
struct ScaleDialog {
    view: View,
    over: View,
    ns: String,
    name: String,
    replicas: u64,
}

#[derive(Default)]
pub struct Kubernetes {
    namespaces: RefCell<Vec<String>>,
    /// The namespace filter; `None` is all.
    namespace: RefCell<Option<String>>,
    rows: RefCell<HashMap<NodeId, Vec<Row>>>,
    /// Desired replicas by deployment key, for the Scale dialog's start value.
    desired: RefCell<HashMap<String, u64>>,
    selected_pod: RefCell<Option<String>>,
    selected_deployment: RefCell<Option<String>>,
    scale: RefCell<Option<ScaleDialog>>,
    logs: RefCell<Vec<View>>,
}

fn show(view: View, status: Component) {
    let _ = view.patch(vec![ui::Node { id: STATUS, parent: Some(0), component: status }], vec![]);
}

/// A read that may be missing (metrics-server not installed, or RBAC hides it): `None`.
async fn optional<R>(c: Result<Call<R>, Error>) -> Option<R> {
    run(c.ok()?, Access::ReadOnly).await.ok()
}

impl Kubernetes {
    async fn refresh(self: Rc<Self>, view: View) {
        show(view, Component::Progress(None));
        let ns = self.namespace.borrow().clone();
        let result = async {
            // Namespaces first: it is the cheapest call that proves the address, TLS and token.
            let mut names: Vec<String> = match run(calls::namespaces(), Access::ReadOnly).await {
                Ok(list) => list.into_iter().map(|n| n.metadata.name).collect(),
                // A namespaced token may not list namespaces; the filter then shows its own.
                Err(Error::Status(403, _)) => ns.iter().cloned().collect(),
                Err(e) => return Err(e),
            };
            names.sort();
            let n = ns.as_deref();
            let pods = run(calls::pods(n)?, Access::ReadOnly).await?;
            let deps = run(calls::deployments(n)?, Access::ReadOnly).await?;
            let svcs = run(calls::services(n)?, Access::ReadOnly).await?;
            let nodes = optional(Ok(calls::nodes())).await.unwrap_or_default();
            let metrics = optional(calls::pod_metrics(n)).await;
            Ok::<_, Error>((names, pods, deps, svcs, nodes, metrics))
        }
        .await;
        let now = now();
        let (summary, status) = match result {
            Ok((names, pods, deps, svcs, nodes, metrics)) => {
                let mut rows = HashMap::new();
                rows.insert(PODS, pod_rows(&pods, metrics.as_deref(), now));
                rows.insert(DEPLOYMENTS, deployment_rows(&deps, now));
                rows.insert(SERVICES, service_rows(&svcs, now));
                rows.insert(NODES, node_rows(&nodes, now));
                *self.desired.borrow_mut() = deps.iter().map(|d| (key(&d.metadata.namespace, &d.metadata.name), d.desired())).collect();
                *self.rows.borrow_mut() = rows;
                *self.namespaces.borrow_mut() = names;
                let running = pods.iter().filter(|p| p.status.phase == "Running").count();
                (format!("{running}/{} pods · {} nodes", pods.len(), nodes.len()), ui::label(""))
            }
            Err(e) => {
                log::warn("refresh failed");
                self.rows.borrow_mut().clear();
                ("Not loaded".to_string(), ui::banner(BannerLevel::Error, &message(&e)))
            }
        };
        self.redraw(view, &summary, status);
    }

    fn redraw(&self, view: View, summary: &str, status: Component) {
        let names = self.namespaces.borrow();
        let selected = self.namespace.borrow().as_ref().and_then(|n| names.iter().position(|x| x == n));
        let rows = self.rows.borrow();
        let count = |id| rows.get(&id).map_or(0, Vec::len);
        let counts = [count(PODS), count(DEPLOYMENTS), count(SERVICES), count(NODES)];
        if let Err(e) = view.set(dashboard(summary, status, &names, selected, counts, may_change())) {
            log::error(&format!("view refused: {e:?}"));
        }
    }

    fn pick_namespace(self: Rc<Self>, view: View, index: u32) -> Task {
        let pick = match index {
            0 => None,
            i => self.namespaces.borrow().get(i as usize - 1).cloned(),
        };
        *self.namespace.borrow_mut() = pick;
        *self.selected_pod.borrow_mut() = None;
        *self.selected_deployment.borrow_mut() = None;
        task(self.refresh(view))
    }

    fn selected(&self, which: NodeId) -> Result<(String, String), Error> {
        let (cell, what) = if which == PODS { (&self.selected_pod, "pod") } else { (&self.selected_deployment, "deployment") };
        let k = cell.borrow().clone().ok_or_else(|| Error::Refused(format!("Select a {what} first.")))?;
        let (ns, name) = split_key(&k).ok_or_else(|| Error::Refused(format!("Select a {what} first.")))?;
        Ok((ns.to_string(), name.to_string()))
    }

    async fn show_logs(self: Rc<Self>, view: View) -> Result<(), Error> {
        let (ns, pod) = self.selected(PODS)?;
        let text = run(calls::logs(&ns, &pod)?, Access::ReadOnly).await?;
        let text = if text.is_empty() { "(no log lines)".to_string() } else { text };
        let mut b = ViewBuilder::new(ui::stack());
        let root = b.root();
        b.add(root, Component::CodeEditor(CodeEditor { language: "log".into(), text, read_only: true }));
        let row = b.add(root, ui::row());
        b.add(row, ui::button("Close"));
        let dialog = view.open_dialog(&short(&format!("Logs: {pod}")), b.finish()).map_err(|f| Error::Transport(describe(&f)))?;
        self.logs.borrow_mut().push(dialog);
        Ok(())
    }

    /// A change: refused at once on a read-only entry, else confirmed, then sent.
    async fn change(&self, prompt: String, c: Call<()>, done: String) -> Result<Option<String>, Error> {
        c.check(access())?;
        if !ui::confirm(ConfirmKind::Other, &prompt).await.map_err(|f| Error::Transport(describe(&f)))? {
            return Ok(None);
        }
        run(c, access()).await?;
        Ok(Some(done))
    }

    fn entry_name() -> String {
        host::entry().map(|e| e.name).unwrap_or_default()
    }

    async fn action(self: Rc<Self>, view: View, node: NodeId) {
        let outcome: Result<Option<String>, Error> = async {
            match node {
                LOGS => self.clone().show_logs(view).await.map(|_| None),
                DELETE => {
                    let (ns, pod) = self.selected(PODS)?;
                    let c = calls::delete_pod(&ns, &pod)?;
                    self.change(format!("Delete pod {ns}/{pod} on {}? Its controller starts a new one.", Self::entry_name()), c, format!("Deleted {pod}.")).await
                }
                RESTART => {
                    let (ns, d) = self.selected(DEPLOYMENTS)?;
                    let c = calls::rollout_restart(&ns, &d, now())?;
                    self.change(format!("Restart deployment {ns}/{d} on {}? Its pods are replaced one by one.", Self::entry_name()), c, format!("Restarting {d}.")).await
                }
                SCALE => {
                    let (ns, d) = self.selected(DEPLOYMENTS)?;
                    calls::scale(&ns, &d, 0)?.check(access())?;
                    let replicas = self.desired.borrow().get(&key(&ns, &d)).copied().unwrap_or(1);
                    self.open_scale(view, ns, d, replicas)?;
                    Ok(None)
                }
                _ => Ok(None),
            }
        }
        .await;
        self.report(view, outcome).await;
    }

    async fn report(self: Rc<Self>, view: View, outcome: Result<Option<String>, Error>) {
        match outcome {
            Ok(Some(text)) => {
                self.clone().refresh(view).await;
                show(view, ui::label(&text));
            }
            Ok(None) => {}
            Err(e) => show(view, ui::banner(BannerLevel::Error, &message(&e))),
        }
    }

    fn open_scale(&self, over: View, ns: String, name: String, replicas: u64) -> Result<(), Error> {
        let mut b = ViewBuilder::new(ui::stack());
        let root = b.root();
        b.add(root, ui::label(&short(&format!("Replicas of {name}"))));
        b.add(root, Component::NumberField(NumberField { label: "Replicas".into(), value: replicas as f64, min: Some(0.0), max: Some(MAX_REPLICAS as f64) }));
        b.add(root, ui::row());
        b.add(3, ui::button("Scale"));
        b.add(3, ui::button("Cancel"));
        let view = over.open_dialog("Scale Deployment", b.finish()).map_err(|f| Error::Transport(describe(&f)))?;
        *self.scale.borrow_mut() = Some(ScaleDialog { view, over, ns, name, replicas });
        Ok(())
    }

    async fn confirm_scale(self: Rc<Self>) {
        let Some(d) = self.scale.borrow_mut().take() else { return };
        View::close_dialog(d.view);
        let outcome = match calls::scale(&d.ns, &d.name, d.replicas) {
            Ok(c) => {
                let prompt = format!("Scale deployment {}/{} on {} to {} replicas?", d.ns, d.name, Self::entry_name(), d.replicas);
                self.change(prompt, c, format!("Scaled {} to {}.", d.name, d.replicas)).await
            }
            Err(e) => Err(e),
        };
        self.report(d.over, outcome).await;
    }

    fn dialog_input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Option<Task> {
        if self.logs.borrow().contains(&view) {
            if matches!(input, Input::Pressed) {
                self.logs.borrow_mut().retain(|v| *v != view);
                View::close_dialog(view);
            }
            return Some(bastion_plugin_sdk::done());
        }
        let is_scale = self.scale.borrow().as_ref().is_some_and(|d| d.view == view);
        if !is_scale {
            return None;
        }
        match (node, input) {
            (D_VALUE, Input::Number(n)) => {
                if let Some(d) = self.scale.borrow_mut().as_mut() {
                    d.replicas = if n.is_finite() { n.clamp(0.0, MAX_REPLICAS as f64).round() as u64 } else { d.replicas };
                }
                Some(bastion_plugin_sdk::done())
            }
            (D_OK, Input::Pressed) => Some(task(self.confirm_scale())),
            (D_CLOSE, Input::Pressed) => {
                if let Some(d) = self.scale.borrow_mut().take() {
                    View::close_dialog(d.view);
                }
                Some(bastion_plugin_sdk::done())
            }
            _ => Some(bastion_plugin_sdk::done()),
        }
    }
}

impl Plugin for Kubernetes {
    fn start() -> Self {
        Kubernetes::default()
    }

    fn open_view(self: Rc<Self>, view: View, _name: String) -> Task {
        let ns = field(NAMESPACE_FIELD).map(|s| s.trim().to_string()).filter(|s| !s.is_empty() && crate::api::check_name(s).is_ok());
        *self.namespace.borrow_mut() = ns;
        task(async move {
            let _ = view.set(dashboard("Loading", Component::Progress(None), &[], None, [0; 4], may_change()));
            self.refresh(view).await;
        })
    }

    fn close_view(self: Rc<Self>, view: View) -> Task {
        self.logs.borrow_mut().retain(|v| *v != view);
        let mut scale = self.scale.borrow_mut();
        if scale.as_ref().is_some_and(|d| d.view == view || d.over == view) {
            *scale = None;
        }
        bastion_plugin_sdk::done()
    }

    fn command(self: Rc<Self>, id: String, view: Option<View>) -> Task {
        match (id.as_str(), view) {
            ("refresh", Some(view)) => task(self.refresh(view)),
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn input(self: Rc<Self>, view: View, node: NodeId, input: Input) -> Task {
        if let Some(t) = self.clone().dialog_input(view, node, input.clone()) {
            return t;
        }
        match (node, input) {
            (REFRESH, Input::Pressed) => task(self.refresh(view)),
            (NAMESPACE, Input::Choice(i)) => self.pick_namespace(view, i),
            (LOGS | DELETE | SCALE | RESTART, Input::Pressed) => task(self.action(view, node)),
            (PODS, Input::Selected(keys)) => {
                *self.selected_pod.borrow_mut() = keys.into_iter().next();
                bastion_plugin_sdk::done()
            }
            (DEPLOYMENTS, Input::Selected(keys)) => {
                *self.selected_deployment.borrow_mut() = keys.into_iter().next();
                bastion_plugin_sdk::done()
            }
            _ => bastion_plugin_sdk::done(),
        }
    }

    fn rows(self: Rc<Self>, ask: RowsAsk) -> Task {
        let rows = self.rows.borrow();
        let all = rows.get(&ask.node).map_or(&[][..], Vec::as_slice);
        let start = (ask.offset as usize).min(all.len());
        let end = start.saturating_add(ask.count as usize).min(all.len()).min(start + ui::MAX_ROWS);
        let _ = ui::provide_rows(ask.ask, &all[start..end], Some(all.len() as u64));
        bastion_plugin_sdk::done()
    }
}

#[cfg(target_arch = "wasm32")]
bastion_plugin_sdk::export_plugin!(Kubernetes);

#[cfg(test)]
#[path = "plugin_tests.rs"]
mod tests;
