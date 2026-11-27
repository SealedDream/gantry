//! Saved tunnel definitions: validation, port clashes, persistence.
use bastion_core::model::{Connection, Document, Node, Protocol};
use bastion_core::store::Store;
use bastion_core::tunneldefs::{self, TunnelDef, TunnelSpec};
use uuid::Uuid;

fn fixture() -> (Document, Uuid, Uuid) {
    let mut doc = Document::new("t");
    let ssh = Connection::new("jump", Protocol::Ssh, "127.0.0.1");
    let rdp = Connection::new("win", Protocol::Rdp, "10.0.0.5");
    let (s, r) = (ssh.id, rdp.id);
    doc.insert(None, Node::Connection(ssh)).unwrap();
    doc.insert(None, Node::Connection(rdp)).unwrap();
    (doc, s, r)
}

fn def(name: &str, via: Uuid, spec: TunnelSpec) -> TunnelDef {
    TunnelDef { id: Uuid::new_v4(), name: name.into(), via, spec, start_with_connection: false }
}

#[test]
fn definitions_validate_and_refuse_clashes() {
    let (mut doc, ssh, rdp) = fixture();
    let db = def("DB", ssh, TunnelSpec::Local { local_port: 15432, dest_host: "db.internal".into(), dest_port: 5432 });
    tunneldefs::put(&mut doc, db.clone()).unwrap();
    assert_eq!(doc.tunnels[0].summary(), "L 127.0.0.1:15432 → db.internal:5432");
    assert!(tunneldefs::put(&mut doc, def("db", ssh, TunnelSpec::Dynamic { local_port: 1080 })).is_err(), "unique names");
    assert!(tunneldefs::put(&mut doc, def("Socks", ssh, TunnelSpec::Dynamic { local_port: 15432 })).is_err(), "port clash");
    assert!(tunneldefs::put(&mut doc, def("Via RDP", rdp, TunnelSpec::Dynamic { local_port: 1081 })).is_err(), "SSH only");
    assert!(tunneldefs::put(&mut doc, def("Bad", ssh, TunnelSpec::Local { local_port: 0, dest_host: "x".into(), dest_port: 1 })).is_err());
    assert!(tunneldefs::put(&mut doc, def("Opt", ssh, TunnelSpec::Local { local_port: 2000, dest_host: "-oProxyCommand=x".into(), dest_port: 1 })).is_err());
    tunneldefs::put(&mut doc, def("Back", ssh, TunnelSpec::Remote { remote_port: 18080, local_host: "127.0.0.1".into(), local_port: 8080 })).unwrap();
    // Editing keeps its own port.
    let mut edited = db.clone();
    edited.name = "Postgres".into();
    tunneldefs::put(&mut doc, edited).unwrap();
    assert_eq!(tunneldefs::find(&doc, "postgres").unwrap().id, db.id);
    tunneldefs::remove(&mut doc, db.id).unwrap();
    assert!(tunneldefs::find(&doc, "Postgres").is_none());
}

#[test]
fn definitions_persist_with_the_library() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("library.json"));
    let (mut doc, ssh, _) = fixture();
    tunneldefs::put(&mut doc, def("Socks", ssh, TunnelSpec::Dynamic { local_port: 1080 })).unwrap();
    store.save(&doc).unwrap();
    assert_eq!(store.load().unwrap().tunnels, doc.tunnels);
}

#[test]
fn start_with_connection_lists_only_that_connections_flagged_tunnels() {
    let (mut doc, ssh, _) = fixture();
    let mut auto = def("b auto", ssh, TunnelSpec::Dynamic { local_port: 1080 });
    auto.start_with_connection = true;
    let mut auto2 = def("A auto", ssh, TunnelSpec::Local { local_port: 2000, dest_host: "db".into(), dest_port: 5432 });
    auto2.start_with_connection = true;
    tunneldefs::put(&mut doc, auto.clone()).unwrap();
    tunneldefs::put(&mut doc, auto2.clone()).unwrap();
    tunneldefs::put(&mut doc, def("manual", ssh, TunnelSpec::Dynamic { local_port: 1081 })).unwrap();
    let names: Vec<_> = tunneldefs::starting_with(&doc, ssh).iter().map(|t| t.name.clone()).collect();
    assert_eq!(names, ["A auto", "b auto"]);
    assert!(tunneldefs::starting_with(&doc, Uuid::new_v4()).is_empty());
}

#[test]
fn definitions_saved_before_the_flag_load_as_on_demand() {
    let json = format!(r#"{{"id":"{}","name":"x","via":"{}","spec":{{"kind":"dynamic","local_port":1080}}}}"#, Uuid::new_v4(), Uuid::new_v4());
    let d: TunnelDef = serde_json::from_str(&json).unwrap();
    assert!(!d.start_with_connection);
    assert!(!serde_json::to_string(&d).unwrap().contains("start_with_connection"), "off is not written");
}
