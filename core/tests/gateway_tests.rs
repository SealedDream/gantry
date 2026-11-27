//! Gateway manager: shared definitions, references through inheritance, safe delete.
use bastion_core::gateway::{self, GatewayInput, GatewayUse};
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use bastion_core::properties;
use bastion_core::store::Store;
use uuid::Uuid;

fn input(name: &str, host: &str) -> GatewayInput {
    GatewayInput { name: name.into(), host: host.into(), port: Some(2223), username: Some("tester".into()), notes: String::new() }
}

/// Library with a folder "Prod" holding web (inherits) and db (own setting none).
fn fixture() -> (Document, Uuid, Uuid, Uuid) {
    let mut doc = Document::new("t");
    let web = Connection::new("web", Protocol::Ssh, "10.0.0.1");
    let db = Connection::new("db", Protocol::Ssh, "10.0.0.2");
    let (wid, did) = (web.id, db.id);
    let folder = Folder { id: Uuid::new_v4(), name: "Prod".into(), color: None, defaults: Settings::default(), children: vec![Node::Connection(web), Node::Connection(db)], dynamic_task_id: None, extra: Default::default() };
    let fid = folder.id;
    doc.insert(None, Node::Folder(folder)).unwrap();
    let _ = did;
    (doc, fid, wid, did)
}

#[test]
fn add_validates_and_refuses_duplicates() {
    let (mut doc, ..) = fixture();
    let id = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    assert_eq!(gateway::get(&doc, id).unwrap().port, Some(2223));
    assert!(gateway::add(&mut doc, &input("jump", "10.0.0.9")).is_err(), "names are unique, ignoring case");
    assert!(gateway::add(&mut doc, &input("Other", "-oProxyCommand=x")).is_err(), "option-like host");
    assert!(gateway::add(&mut doc, &input("Other", "two words")).is_err());
    assert!(gateway::add(&mut doc, &input("  ", "h")).is_err());
    let mut bad_user = input("Other", "h");
    bad_user.username = Some("a b".into());
    assert!(gateway::add(&mut doc, &bad_user).is_err());
    let mut blank_user = input("Blank", "h");
    blank_user.username = Some("  ".into());
    let b = gateway::add(&mut doc, &blank_user).unwrap();
    assert_eq!(gateway::get(&doc, b).unwrap().username, None, "blank user means the target's user");
}

#[test]
fn folder_default_is_inherited_and_listed_as_uses() {
    let (mut doc, fid, wid, did) = fixture();
    let id = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    properties::set_value(&mut doc, fid, "gateway_id", Some(&id.to_string())).unwrap();
    assert_eq!(gateway::for_connection(&doc, wid).unwrap().unwrap().name, "Jump");
    let uses = gateway::uses(&doc, id);
    assert!(uses.contains(&GatewayUse::Connection { id: wid, name: "web".into(), inherited: true }));
    assert!(uses.contains(&GatewayUse::Connection { id: did, name: "db".into(), inherited: true }));
    assert!(uses.contains(&GatewayUse::Folder { id: fid, name: "Prod".into() }));
    let values = properties::connection_values(&doc, wid).unwrap();
    let v = values.iter().find(|v| v.key == "gateway_id").unwrap();
    assert_eq!(v.effective.as_deref(), Some(id.to_string().as_str()));
}

#[test]
fn unknown_gateway_ids_are_refused_by_the_property_editor() {
    let (mut doc, _, wid, _) = fixture();
    assert!(properties::set_value(&mut doc, wid, "gateway_id", Some(&Uuid::new_v4().to_string())).is_err());
    assert!(properties::set_value(&mut doc, wid, "gateway_id", Some("not-a-uuid")).is_err());
    assert!(properties::set_type_value(&mut doc, Protocol::Ssh, "gateway_id", Some(&Uuid::new_v4().to_string())).is_err());
    for p in [Protocol::Ssh, Protocol::Rdp, Protocol::Vnc, Protocol::Web] {
        assert!(properties::schema(p).iter().any(|d| d.key == "gateway_id"), "{p:?} honours gateways");
    }
    assert!(!properties::schema(Protocol::Telnet).iter().any(|d| d.key == "gateway_id"), "nothing routes telnet through a gateway");
}

#[test]
fn delete_in_use_is_refused_and_allowed_once_unused() {
    let (mut doc, _, wid, _) = fixture();
    let id = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    properties::set_type_value(&mut doc, Protocol::Ssh, "gateway_id", Some(&id.to_string())).unwrap();
    let err = gateway::remove(&mut doc, id).unwrap_err().to_string();
    assert!(err.contains("web") && err.contains("SSH Default Settings"), "{err}");
    properties::set_type_value(&mut doc, Protocol::Ssh, "gateway_id", None).unwrap();
    assert!(gateway::for_connection(&doc, wid).unwrap().is_none());
    gateway::remove(&mut doc, id).unwrap();
    assert!(doc.gateways.is_empty());
}

#[test]
fn dangling_reference_is_an_error_not_a_direct_connect() {
    let (mut doc, _, wid, _) = fixture();
    let id = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    properties::set_value(&mut doc, wid, "gateway_id", Some(&id.to_string())).unwrap();
    doc.gateways.clear(); // as if the file was edited by hand
    assert!(gateway::for_connection(&doc, wid).unwrap_err().to_string().contains("no longer exists"));
}

#[test]
fn gateways_persist_and_old_files_load() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("library.json"));
    let (mut doc, _, wid, _) = fixture();
    let id = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    properties::set_value(&mut doc, wid, "gateway_id", Some(&id.to_string())).unwrap();
    store.save(&doc).unwrap();
    let back = store.load().unwrap();
    assert_eq!(back.gateways, doc.gateways);
    assert_eq!(gateway::for_connection(&back, wid).unwrap().unwrap().id, id);
    // A library written before gateways existed has no `gateways` key.
    let empty = Document::new("old");
    let json = serde_json::to_string(&empty).unwrap();
    assert!(!json.contains("gateways"));
    let parsed: Document = serde_json::from_str(&json).unwrap();
    assert!(parsed.gateways.is_empty());
}

/// RDP and VNC get a port forward to their own host and port (default port when unset), web
/// a SOCKS proxy, SSH is refused here (it uses the jump path), no gateway means no route.
#[test]
fn routes_for_desktop_and_web_connections() {
    use bastion_core::gateway::RouteKind;
    let mut doc = Document::new("t");
    let gw = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    let mut rdp = Connection::new("win", Protocol::Rdp, " 10.0.0.5 ");
    rdp.settings.gateway_id = Some(gw);
    let mut vnc = Connection::new("vnc", Protocol::Vnc, "10.0.0.6");
    vnc.settings.gateway_id = Some(gw);
    vnc.settings.port = Some(5901);
    let mut web = Connection::new("intranet", Protocol::Web, "https://wiki.internal");
    web.settings.gateway_id = Some(gw);
    let mut ssh = Connection::new("ssh", Protocol::Ssh, "10.0.0.7");
    ssh.settings.gateway_id = Some(gw);
    let mut telnet = Connection::new("old", Protocol::Telnet, "10.0.0.8");
    telnet.settings.gateway_id = Some(gw);
    let direct = Connection::new("direct", Protocol::Rdp, "10.0.0.9");
    let ids: Vec<Uuid> = [&rdp, &vnc, &web, &ssh, &telnet, &direct].iter().map(|c| c.id).collect();
    for c in [rdp, vnc, web, ssh, telnet, direct] {
        doc.insert(None, Node::Connection(c)).unwrap();
    }
    let route = |i: usize| gateway::route_for(&doc, ids[i]);
    let r = route(0).unwrap().unwrap();
    assert_eq!(r.gateway.id, gw);
    assert_eq!(r.kind, RouteKind::Forward { dest_host: "10.0.0.5".into(), dest_port: 3389 });
    assert_eq!(route(1).unwrap().unwrap().kind, RouteKind::Forward { dest_host: "10.0.0.6".into(), dest_port: 5901 });
    assert_eq!(route(2).unwrap().unwrap().kind, RouteKind::Socks);
    assert!(route(3).is_err(), "SSH goes through the jump-host path");
    assert!(route(4).is_err(), "unsupported protocols are refused, not connected directly");
    assert_eq!(route(5).unwrap(), None);
}

/// A gateway set on a folder's defaults applies to the RDP connection inside it.
#[test]
fn route_follows_folder_inheritance() {
    let mut doc = Document::new("t");
    let gw = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    let rdp = Connection::new("win", Protocol::Rdp, "10.0.0.5");
    let rid = rdp.id;
    let defaults = Settings { gateway_id: Some(gw), ..Settings::default() };
    let folder = Folder { id: Uuid::new_v4(), name: "DMZ".into(), color: None, defaults, children: vec![Node::Connection(rdp)], dynamic_task_id: None, extra: Default::default() };
    doc.insert(None, Node::Folder(folder)).unwrap();
    assert_eq!(gateway::route_for(&doc, rid).unwrap().unwrap().gateway.id, gw);
}

/// PLUG-08: a plugin entry in folder "Prod" (gateway on the folder), port 5432.
fn plugin_entry(doc: &mut Document, fid: Uuid, port: Option<u16>) -> Uuid {
    let mut c = Connection::new("pg", Protocol::Unsupported, " db.internal ");
    c.unknown_protocol = Some("dev.bastion.postgres/postgres".into());
    c.settings.port = port;
    let id = c.id;
    doc.insert(Some(fid), Node::Connection(c)).unwrap();
    id
}

#[test]
fn a_plugin_entry_goes_through_its_inherited_gateway_as_a_forward() {
    let (mut doc, fid, ..) = fixture();
    let pg = plugin_entry(&mut doc, fid, Some(5432));
    assert!(gateway::route_for(&doc, pg).unwrap().is_none(), "no gateway: none");
    let id = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    properties::set_value(&mut doc, fid, "gateway_id", Some(&id.to_string())).unwrap();
    let route = gateway::route_for(&doc, pg).unwrap().expect("a route");
    assert_eq!(route.gateway.name, "Jump");
    assert_eq!(route.kind, gateway::RouteKind::Forward { dest_host: "db.internal".into(), dest_port: 5432 });
    assert_eq!(gateway::for_connection(&doc, pg).unwrap().unwrap().id, id);
    assert!(gateway::classification_of(&doc, pg).is_ok());
}

#[test]
fn a_plugin_entry_without_a_port_or_with_a_deleted_gateway_is_refused() {
    let (mut doc, fid, ..) = fixture();
    let pg = plugin_entry(&mut doc, fid, None);
    let id = gateway::add(&mut doc, &input("Jump", "127.0.0.1")).unwrap();
    properties::set_value(&mut doc, fid, "gateway_id", Some(&id.to_string())).unwrap();
    let e = gateway::route_for(&doc, pg).unwrap_err().to_string();
    assert!(e.contains("needs a host and a port"), "{e}");
    doc.gateways.retain(|g| g.id != id);
    let e = gateway::for_connection(&doc, pg).unwrap_err().to_string();
    assert!(e.contains("pg uses a gateway that no longer exists"), "{e}");
}
