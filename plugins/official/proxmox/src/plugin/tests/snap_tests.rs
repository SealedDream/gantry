//! PVE-SNAP: the snapshot tree and its confirmed changes, against the fake core.

use super::*;
use bastion_plugin_sdk::bindings::bastion::plugin::events::ChildrenAsk;

const SNAPS: &str = r#"{"data":[{"name":"current","running":1},{"name":"gantry-1","snaptime":1700000000},{"name":"before_patch","snaptime":1600000000,"vmstate":1}]}"#;

fn snap_server(id: u32, call: &CoreCall) -> Vec<Event> {
    match call {
        CoreCall::HttpSend(r) if r.target == "/api2/json/nodes/pve1/qemu/201/snapshot" && r.method == Method::Get => vec![reply(id, ok(SNAPS))],
        CoreCall::HttpSend(r) if r.method != Method::Get => vec![reply(id, ok(r#"{"data":"UPID:pve1:1"}"#))],
        CoreCall::Confirm(..) => vec![reply(id, Ok(ReplyValue::Confirmed(true)))],
        _ => server(id, call),
    }
}

fn entry(allow: bool) -> bastion_plugin_sdk::Entry {
    bastion_plugin_sdk::Entry { id: "e1".into(), name: "pve".into(), host: "pve.lab".into(), port: 8006, fields: vec![(snaps::ALLOW_CHANGES.into(), allow.to_string())] }
}

fn menu(key: &str, id: &str) -> Event {
    Event::Ui(UiEvent { view: 1, node: TREE, input: Input::Menu((key.into(), id.into())) })
}

fn sent(core: &FakeCore) -> Vec<(Method, String, Vec<u8>)> {
    core.plain_calls().into_iter().filter_map(|c| match c {
        CoreCall::HttpSend(r) => Some((r.method, r.target.clone(), r.body.clone())),
        _ => None,
    }).collect()
}

fn changes(core: &FakeCore) -> Vec<(Method, String)> {
    sent(core).into_iter().filter(|(m, ..)| *m != Method::Get).map(|(m, t, _)| (m, t)).collect()
}

fn confirms(core: &FakeCore) -> Vec<String> {
    core.plain_calls().into_iter().filter_map(|c| match c {
        CoreCall::Confirm(_, t) => Some(t.clone()),
        _ => None,
    }).collect()
}

fn snap_core(allow: bool, respond: impl FnMut(u32, &CoreCall) -> Vec<Event> + 'static, user: fn() -> Vec<Event>) -> FakeCore {
    let mut core = FakeCore::new().respond(after_list(respond, user));
    core.entry = Some(entry(allow));
    run_plugin::<Proxmox>(core.with(Event::OpenView(OpenView { view: 1, name: "pve".into() })))
}

fn children(parent: Option<&str>) -> Event {
    Event::Children(ChildrenAsk { ask: 7, view: 1, node: TREE, parent: parent.map(Into::into) })
}

fn provided(core: &FakeCore) -> Vec<Vec<TreeItem>> {
    core.plain_calls().into_iter().filter_map(|c| match c {
        CoreCall::ProvideChildren(_, items) => Some(items.clone()),
        _ => None,
    }).collect()
}

#[test]
fn the_tree_lists_nodes_guests_and_snapshots() {
    for allow in [false, true] {
        let core = snap_core(allow, snap_server, || vec![children(None), children(Some("node:pve1")), children(Some("pve1/201"))]);
        let mut c = provided(&core);
        c.sort_by_key(|items| items.first().map(|i| i.key.matches('/').count() + usize::from(!i.key.starts_with("node:"))).unwrap_or(0));
        assert_eq!(c[0].iter().map(|i| i.key.as_str()).collect::<Vec<_>>(), vec!["node:pve1"]);
        assert_eq!(c[1].iter().map(|i| i.key.as_str()).collect::<Vec<_>>(), vec!["pve1/201", "pve1/202"], "the template is left out");
        assert_eq!(c[2].iter().map(|i| i.key.as_str()).collect::<Vec<_>>(), vec!["pve1/201/before_patch", "pve1/201/gantry-1"], "current is left out, oldest first");
        assert_eq!(c[1][0].menu.is_empty(), !allow);
        assert_eq!(c[2][0].menu.is_empty(), !allow);
        assert!(changes(&core).is_empty());
    }
}

#[test]
fn take_rollback_and_delete_are_confirmed_then_sent() {
    let core = snap_core(true, snap_server, || vec![menu("pve1/201", snaps::TAKE), menu("pve1/201/before_patch", snaps::ROLLBACK), menu("pve1/201/before_patch", snaps::DELETE)]);
    let mut got = changes(&core);
    got.sort_by_key(|(_, t)| t.len());
    assert_eq!(got, vec![
        (Method::Post, "/api2/json/nodes/pve1/qemu/201/snapshot".into()),
        (Method::Delete, "/api2/json/nodes/pve1/qemu/201/snapshot/before_patch".into()),
        (Method::Post, "/api2/json/nodes/pve1/qemu/201/snapshot/before_patch/rollback".into()),
    ]);
    let take = sent(&core).into_iter().find(|(m, t, _)| *m == Method::Post && t.ends_with("/snapshot")).unwrap();
    assert_eq!(String::from_utf8(take.2).unwrap(), "snapname=gantry-2&description=Taken%20in%20Gantry", "the next free name");
    let c = confirms(&core);
    assert_eq!(c.len(), 3);
    assert!(c.iter().any(|t| t.contains("gantry-2") && t.contains("web")), "{c:?}");
    assert!(c.iter().any(|t| t.contains("lost")) && c.iter().any(|t| t.contains("cannot be undone")), "{c:?}");
}

#[test]
fn a_declined_confirm_sends_nothing() {
    let core = snap_core(true, |id, c| match c {
        CoreCall::Confirm(..) => vec![reply(id, Ok(ReplyValue::Confirmed(false)))],
        _ => snap_server(id, c),
    }, || vec![menu("pve1/201", snaps::TAKE), menu("pve1/201/gantry-1", snaps::DELETE)]);
    assert_eq!(confirms(&core).len(), 2);
    assert!(changes(&core).is_empty());
}

#[test]
fn a_read_only_entry_refuses_without_asking() {
    let core = snap_core(false, snap_server, || vec![menu("pve1/201", snaps::TAKE), menu("pve1/201/gantry-1", snaps::ROLLBACK), menu("pve1/201/gantry-1", snaps::DELETE)]);
    assert!(confirms(&core).is_empty());
    assert!(changes(&core).is_empty());
    assert!(matches!(status(&core), Component::Banner(b) if b.text.contains("read-only")), "{:?}", status(&core));
}

#[test]
fn hostile_keys_send_nothing() {
    let core = snap_core(true, snap_server, || vec![menu("pve1/201/../../x", snaps::DELETE), menu("pve1/201/current", snaps::ROLLBACK), menu("pve1/999/a", snaps::DELETE), menu("pve1/201", snaps::DELETE)]);
    assert!(confirms(&core).is_empty());
    assert!(changes(&core).is_empty());
}

