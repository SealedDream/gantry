use super::*;
use bastion_plugin_sdk::bindings::bastion::plugin::events::{Event, OpenView, ReplyValue, UiEvent};
use bastion_plugin_sdk::bindings::bastion::plugin::types::HttpResponse;
use bastion_plugin_sdk::testing::{reply, run_plugin, Call as CoreCall, FakeCore};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn http(id: u32, code: u16, body: Vec<u8>) -> Vec<Event> {
    vec![reply(id, Ok(ReplyValue::Http(HttpResponse { status: code, headers: vec![], body })))]
}

fn cluster(id: u32, call: &CoreCall) -> Vec<Event> {
    let CoreCall::HttpSend(r) = call else {
        return match call {
            CoreCall::Confirm(..) => vec![reply(id, Ok(ReplyValue::Confirmed(true)))],
            _ => vec![],
        };
    };
    let path = r.target.split('?').next().unwrap();
    let file = match (r.method, path) {
        (HttpMethod::Get, "/api/v1/namespaces") => "namespaces.json",
        (HttpMethod::Get, p) if p.ends_with("/log") => return http(id, 200, b"line 1\nline 2\n".to_vec()),
        (HttpMethod::Get, p) if p.starts_with("/apis/metrics") => "metrics.json",
        (HttpMethod::Get, p) if p.ends_with("/pods") => "pods.json",
        (HttpMethod::Get, p) if p.ends_with("/deployments") => "deployments.json",
        (HttpMethod::Get, p) if p.ends_with("/services") => "services.json",
        (HttpMethod::Get, "/api/v1/nodes") => "nodes.json",
        (HttpMethod::Get, _) => return http(id, 404, vec![]),
        _ => return http(id, 200, b"{}".to_vec()),
    };
    http(id, 200, fixture(file))
}

fn entry(allow: bool, ns: &str) -> bastion_plugin_sdk::Entry {
    bastion_plugin_sdk::Entry {
        id: "e1".into(),
        name: "lab-k3s".into(),
        host: "k3s.lab".into(),
        port: 6443,
        fields: vec![(ALLOW_CHANGES.into(), allow.to_string()), (NAMESPACE_FIELD.into(), ns.into())],
    }
}

fn open() -> Event {
    Event::OpenView(OpenView { view: 1, name: "k8s".into() })
}

fn ui_event(view: u32, node: NodeId, input: Input) -> Event {
    Event::Ui(UiEvent { view, node, input })
}

fn core(allow: bool) -> FakeCore {
    let mut c = FakeCore::new().respond(cluster);
    c.entry = Some(entry(allow, ""));
    c
}

fn sent(core: &FakeCore) -> Vec<bastion_plugin_sdk::bindings::bastion::plugin::http::HttpRequest> {
    core.plain_calls().into_iter().filter_map(|c| match c {
        CoreCall::HttpSend(r) => Some(r.clone()),
        _ => None,
    }).collect()
}

fn last_view(core: &FakeCore) -> Vec<ui::Node> {
    core.plain_calls().into_iter().rev().find_map(|c| match c {
        CoreCall::SetView(_, nodes) => Some(nodes.clone()),
        _ => None,
    }).expect("a view")
}

#[test]
fn the_dashboard_passes_the_checks() {
    assert_eq!(ui::check(&dashboard("Loading", Component::Progress(None), &[], None, [0; 4], false)), Ok(()));
    let many: Vec<String> = (0..300).map(|i| format!("namespace-with-a-long-name-{i:04}-xxxxxxxxxx")).collect();
    let v = dashboard(&"x".repeat(80), ui::banner(BannerLevel::Error, &"e".repeat(500)), &many, Some(3), [10_000, 5, 5, 5], true);
    assert_eq!(ui::check(&v), Ok(()));
}

#[test]
fn opening_reads_the_cluster_with_the_core_login_only() {
    let core = run_plugin::<Kubernetes>(core(false).with(open()));
    let reqs = sent(&core);
    let targets: Vec<_> = reqs.iter().map(|r| r.target.as_str()).collect();
    assert_eq!(targets, ["/api/v1/namespaces", "/api/v1/pods", "/apis/apps/v1/deployments", "/api/v1/services", "/api/v1/nodes", "/apis/metrics.k8s.io/v1beta1/pods"]);
    for r in &reqs {
        assert_eq!(r.method, HttpMethod::Get);
        assert!(r.with_login);
        assert!(r.headers.iter().all(|(n, _)| !n.eq_ignore_ascii_case("authorization")), "the core adds the token");
    }
    let view = last_view(&core);
    assert!(matches!(&view.iter().find(|n| n.id == SUMMARY).unwrap().component, Component::Label(t) if t == "3/5 pods · 2 nodes"));
    assert!(matches!(&view.iter().find(|n| n.id == PODS).unwrap().component, Component::Table(t) if t.total_rows == Some(5)));
    // Read-only entry: the change buttons are off.
    for id in [DELETE, SCALE, RESTART] {
        assert!(matches!(&view.iter().find(|n| n.id == id).unwrap().component, Component::Button(b) if !b.enabled));
    }
}

#[test]
fn pod_rows_show_metrics_when_present_and_a_dash_when_not() {
    let pods: crate::model::List<Pod> = serde_json::from_slice(&fixture("pods.json")).unwrap();
    let metrics: crate::model::List<PodMetrics> = serde_json::from_slice(&fixture("metrics.json")).unwrap();
    let now = model::epoch("2026-11-23T10:00:00Z").unwrap();
    let rows = pod_rows(&pods.items, Some(&metrics.items), now);
    let web = rows.iter().find(|r| r.key == "shop/web-7c9f8d6b5-x2kqp").unwrap();
    assert!(matches!(&web.cells[7], Cell::Text(t) if t == "3m"));
    assert!(matches!(&web.cells[8], Cell::Text(t) if t == "12 Mi"));
    assert_eq!(rows[0].key, "kube-system/coredns-ccb96694c-9kd2m", "sorted by namespace then name");
    let rows = pod_rows(&pods.items, None, now);
    assert!(rows.iter().all(|r| matches!(&r.cells[7], Cell::Text(t) if t == "—")));
}

#[test]
fn the_namespace_field_and_filter_scope_the_reads() {
    let mut c = FakeCore::new().respond(cluster);
    c.entry = Some(entry(false, "shop"));
    let core = run_plugin::<Kubernetes>(c.with(open()).with(ui_event(1, NAMESPACE, Input::Choice(0))));
    let targets: Vec<_> = sent(&core).into_iter().map(|r| r.target).collect();
    assert!(targets.contains(&"/api/v1/namespaces/shop/pods".to_string()));
    assert_eq!(targets.last().unwrap(), "/apis/metrics.k8s.io/v1beta1/pods", "All namespaces after the pick");
}

#[test]
fn changes_on_a_read_only_entry_send_nothing_and_ask_nothing() {
    let core = run_plugin::<Kubernetes>(
        core(false)
            .with(open())
            .with(ui_event(1, PODS, Input::Selected(vec!["shop/web-1".into()])))
            .with(ui_event(1, DELETE, Input::Pressed))
            .with(ui_event(1, DEPLOYMENTS, Input::Selected(vec!["shop/web".into()])))
            .with(ui_event(1, RESTART, Input::Pressed))
            .with(ui_event(1, SCALE, Input::Pressed)),
    );
    assert!(sent(&core).iter().all(|r| r.method == HttpMethod::Get));
    assert!(!core.plain_calls().iter().any(|c| matches!(c, CoreCall::Confirm(..) | CoreCall::OpenDialog(..))));
    let banners = core.plain_calls().into_iter().filter(|c| matches!(c, CoreCall::PatchView(_, n, _) if n.iter().any(|n| matches!(&n.component, Component::Banner(b) if b.text.contains("Allow changes"))))).count();
    assert_eq!(banners, 3, "each refused change says why");
}

#[test]
fn delete_pod_is_confirmed_then_sent() {
    let core = run_plugin::<Kubernetes>(
        core(true).with(open()).with(ui_event(1, PODS, Input::Selected(vec!["shop/web-1".into()]))).with(ui_event(1, DELETE, Input::Pressed)),
    );
    let confirms: Vec<_> = core.plain_calls().into_iter().filter_map(|c| match c {
        CoreCall::Confirm(_, t) => Some(t.clone()),
        _ => None,
    }).collect();
    assert_eq!(confirms.len(), 1);
    assert!(confirms[0].contains("shop/web-1") && confirms[0].contains("lab-k3s"), "{confirms:?}");
    let del: Vec<_> = sent(&core).into_iter().filter(|r| r.method == HttpMethod::Delete).collect();
    assert_eq!(del.len(), 1);
    assert_eq!(del[0].target, "/api/v1/namespaces/shop/pods/web-1");
}

#[test]
fn a_declined_confirm_sends_nothing() {
    let mut c = FakeCore::new().respond(|id, call| match call {
        CoreCall::Confirm(..) => vec![reply(id, Ok(ReplyValue::Confirmed(false)))],
        _ => cluster(id, call),
    });
    c.entry = Some(entry(true, ""));
    let core = run_plugin::<Kubernetes>(c.with(open()).with(ui_event(1, DEPLOYMENTS, Input::Selected(vec!["shop/web".into()]))).with(ui_event(1, RESTART, Input::Pressed)));
    assert!(sent(&core).iter().all(|r| r.method == HttpMethod::Get));
}

#[test]
fn restart_patches_the_template_annotation() {
    let core = run_plugin::<Kubernetes>(core(true).with(open()).with(ui_event(1, DEPLOYMENTS, Input::Selected(vec!["shop/web".into()]))).with(ui_event(1, RESTART, Input::Pressed)));
    let p: Vec<_> = sent(&core).into_iter().filter(|r| r.method == HttpMethod::Patch).collect();
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].target, "/apis/apps/v1/namespaces/shop/deployments/web");
    assert!(p[0].headers.contains(&("Content-Type".into(), "application/merge-patch+json".into())));
    assert!(String::from_utf8_lossy(&p[0].body).contains("kubectl.kubernetes.io/restartedAt"));
}

#[test]
fn scale_opens_a_dialog_then_confirms_and_patches() {
    // The fake core numbers the dialog right after the call that opened it; the user types 5
    // into it and presses Scale.
    let mut c = FakeCore::new().respond(|id, call| match call {
        CoreCall::OpenDialog(..) => vec![ui_event(id + 1, D_VALUE, Input::Number(5.0)), ui_event(id + 1, D_OK, Input::Pressed)],
        _ => cluster(id, call),
    });
    c.entry = Some(entry(true, ""));
    let core = run_plugin::<Kubernetes>(
        c.with(open()).with(ui_event(1, DEPLOYMENTS, Input::Selected(vec!["shop/web".into()]))).with(ui_event(1, SCALE, Input::Pressed)),
    );
    let dialog = core.plain_calls().into_iter().find_map(|c| match c {
        CoreCall::OpenDialog(_, title, nodes) => Some((title.clone(), nodes.clone())),
        _ => None,
    }).expect("a dialog");
    assert_eq!(dialog.0, "Scale Deployment");
    assert!(matches!(&dialog.1[D_VALUE as usize].component, Component::NumberField(f) if f.max == Some(MAX_REPLICAS as f64)));
    let p: Vec<_> = sent(&core).into_iter().filter(|r| r.method == HttpMethod::Patch).collect();
    assert_eq!(p.len(), 1, "{:?}", core.plain_calls());
    assert_eq!(p[0].target, "/apis/apps/v1/namespaces/shop/deployments/web/scale");
    assert_eq!(String::from_utf8_lossy(&p[0].body), r#"{"spec":{"replicas":5}}"#);
}

#[test]
fn logs_open_read_only_in_a_dialog() {
    let core = run_plugin::<Kubernetes>(core(false).with(open()).with(ui_event(1, PODS, Input::Selected(vec!["shop/web-1".into()]))).with(ui_event(1, LOGS, Input::Pressed)));
    let (title, nodes) = core.plain_calls().into_iter().find_map(|c| match c {
        CoreCall::OpenDialog(_, t, n) => Some((t.clone(), n.clone())),
        _ => None,
    }).expect("a logs dialog");
    assert_eq!(title, "Logs: web-1");
    assert!(matches!(&nodes[1].component, Component::CodeEditor(e) if e.read_only && e.text.contains("line 2")));
    assert!(sent(&core).iter().any(|r| r.target.starts_with("/api/v1/namespaces/shop/pods/web-1/log?tailLines=")));
}

#[test]
fn errors_show_as_banners_in_plain_words() {
    for (code, file, words) in [(401, "unauthorized.json", "expired"), (403, "forbidden.json", "Forbidden by RBAC")] {
        let mut c = FakeCore::new().respond(move |id, call| match call {
            CoreCall::HttpSend(_) => http(id, code, fixture(file)),
            _ => vec![],
        });
        c.entry = Some(entry(false, ""));
        let core = run_plugin::<Kubernetes>(c.with(open()));
        assert!(matches!(&last_view(&core)[STATUS as usize].component, Component::Banner(b) if b.text.contains(words)), "{code}");
    }
    let mut c = FakeCore::new().respond(|id, call| match call {
        CoreCall::HttpSend(_) => vec![reply(id, Err(Failure::Io("connection refused".into())))],
        _ => vec![],
    });
    c.entry = Some(entry(false, ""));
    let core = run_plugin::<Kubernetes>(c.with(open()));
    assert!(matches!(&last_view(&core)[STATUS as usize].component, Component::Banner(b) if b.text == "API server not reachable: connection refused"));
}
