//! Audit DS-01: exporting customer A's connection carries A's dependencies and nothing of B's.
use std::collections::BTreeSet;

use bastion_core::export::{self, Selection};
use bastion_core::gateway::Gateway;
use bastion_core::model::{Connection, Document, Node, Protocol, Settings};
use bastion_core::tasks::{HookWhen, RunOn, TaskDef, TaskHook, TaskKind};
use bastion_core::tunneldefs::{TunnelDef, TunnelSpec};
use uuid::Uuid;

struct Customer {
    conn: Uuid,
    gateway: Uuid,
    task: Uuid,
}

fn add_customer(d: &mut Document, tag: &str, protocol: Protocol) -> Customer {
    let gateway = Gateway { id: Uuid::new_v4(), name: format!("gw-{tag}"), host: format!("GW_HOST_{tag}"), port: None, username: None, notes: String::new() };
    let mut c = Connection::new(format!("conn-{tag}"), protocol, format!("host-{tag}"));
    c.settings.gateway_id = Some(gateway.id);
    let conn = c.id;
    d.insert(None, Node::Connection(c)).unwrap();
    d.gateways.push(gateway.clone());
    let task = TaskDef { id: Uuid::new_v4(), name: format!("task-{tag}"), favorite: true, kind: TaskKind::Custom { program: "echo".into(), args: vec![format!("TASK_ARG_{tag}")], run_on: RunOn::default() }, timeout_secs: 30 };
    d.task_hooks.push(TaskHook::on_connection(conn, task.id, HookWhen::BeforeConnect));
    d.tasks.push(task.clone());
    d.tunnels.push(TunnelDef { id: Uuid::new_v4(), name: format!("tun-{tag}"), via: conn, spec: TunnelSpec::Local { local_port: 15432, dest_host: format!("TUNNEL_DEST_{tag}"), dest_port: 5432 }, start_with_connection: false });
    d.type_defaults.insert(protocol, Settings { terminal_theme: Some(format!("DEFAULTS_{tag}")), ..Default::default() });
    Customer { conn, gateway: gateway.id, task: task.id }
}

fn two_customers() -> (Document, Customer, Customer) {
    let mut d = Document::new("Shared");
    let a = add_customer(&mut d, "A", Protocol::Ssh);
    let b = add_customer(&mut d, "B", Protocol::Rdp);
    d.type_defaults.insert(Protocol::Vnc, Settings { terminal_theme: Some("DEFAULTS_UNUSED".into()), ..Default::default() });
    d.favorite_builtin_tasks.push(Uuid::from_u128(0xb7a5_0000_0000_0000_0000_0000_0000_0001));
    (d, a, b)
}

#[test]
fn exporting_a_leaves_b_and_unreferenced_globals_behind() {
    let (d, a, _) = two_customers();
    let sel = Selection::Nodes(BTreeSet::from([a.conn]));
    let text = String::from_utf8(export::export(&d, &sel).unwrap()).unwrap();
    for leak in ["TASK_ARG_B", "GW_HOST_B", "TUNNEL_DEST_B", "DEFAULTS_B", "DEFAULTS_UNUSED", "conn-B"] {
        assert!(!text.contains(leak), "{leak} leaked into A's export");
    }
    for need in ["TASK_ARG_A", "GW_HOST_A", "TUNNEL_DEST_A", "DEFAULTS_A"] {
        assert!(text.contains(need), "A's dependency {need} missing");
    }
    let p = export::preview(&d, &sel);
    assert_eq!((p.connections, p.gateways, p.tunnels, p.tasks, p.type_defaults), (1, 1, 1, 1, 1));
}

#[test]
fn a_exported_alone_imports_with_working_dependencies() {
    let (d, a, _) = two_customers();
    let back = export::import(&export::export(&d, &Selection::Nodes(BTreeSet::from([a.conn]))).unwrap()).unwrap();
    let r = back.resolve(a.conn).unwrap();
    assert_eq!(r.effective.gateway_id, Some(a.gateway));
    assert!(back.gateways.iter().any(|g| g.id == a.gateway));
    assert_eq!(r.effective.terminal_theme.as_deref(), Some("DEFAULTS_A"), "type defaults still inherited");
    assert_eq!(back.task_hooks.len(), 1);
    assert_eq!(back.task_hooks[0].task_id, a.task);
    assert!(back.tasks.iter().any(|t| t.id == a.task));
    assert!(back.favorite_builtin_tasks.is_empty(), "the user's built-in favourites are not part of a selection");
}

#[test]
fn full_export_still_carries_everything() {
    let (d, _, b) = two_customers();
    let p = export::preview(&d, &Selection::All);
    assert_eq!((p.connections, p.gateways, p.tunnels, p.tasks, p.type_defaults), (2, 2, 2, 2, 3));
    let back = export::import(&export::export(&d, &Selection::All).unwrap()).unwrap();
    assert!(back.tasks.iter().any(|t| t.id == b.task));
    assert_eq!(back.favorite_builtin_tasks.len(), 1);
}
