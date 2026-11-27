use bastion_core::import;
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use bastion_core::search::search;
use bastion_core::store::Store;
use bastion_core::vars::Variables;
use bastion_core::vault::{generate_password, strength_bits, Credential, CredentialKind, Secret, Vault};
use bastion_core::CoreError;
use uuid::Uuid;

fn folder(name: &str, defaults: Settings) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults, children: vec![], dynamic_task_id: None, extra: Default::default() }
}

fn sample() -> (Document, Uuid, Uuid) {
    let mut doc = Document::new("Lab");
    let prod = folder("Prod", Settings { username: Some("ops".into()), auto_reconnect: Some(true), ..Default::default() });
    let prod_id = prod.id;
    doc.insert(None, Node::Folder(prod)).unwrap();
    let mut web = Connection::new("web-1", Protocol::Ssh, "10.0.0.5");
    web.tags = vec!["linux".into()];
    let web_id = web.id;
    doc.insert(Some(prod_id), Node::Connection(web)).unwrap();
    (doc, prod_id, web_id)
}

#[test]
fn connection_inherits_folder_defaults_and_protocol_port() {
    let (doc, _, web) = sample();
    let r = doc.resolve(web).unwrap();
    assert_eq!(r.effective.username.as_deref(), Some("ops"));
    assert_eq!(r.effective.auto_reconnect, Some(true));
    assert_eq!(r.effective.port, Some(22));
    assert_eq!(r.path, vec!["Prod".to_string()]);
}

#[test]
fn connection_override_beats_folder_default() {
    let (mut doc, prod, _) = sample();
    let mut c = Connection::new("db", Protocol::Rdp, "db.local");
    c.settings.username = Some("admin".into());
    let id = c.id;
    doc.insert(Some(prod), Node::Connection(c)).unwrap();
    assert_eq!(doc.resolve(id).unwrap().effective.username.as_deref(), Some("admin"));
}

#[test]
fn moving_folder_into_its_descendant_is_rejected() {
    let (mut doc, prod, _) = sample();
    let child = folder("Child", Settings::default());
    let child_id = child.id;
    doc.insert(Some(prod), Node::Folder(child)).unwrap();
    assert!(matches!(doc.move_node(prod, Some(child_id)), Err(CoreError::Invalid(_))));
    assert_eq!(doc.connections().len(), 1, "tree must be unchanged");
}

#[test]
fn move_and_duplicate_connection() {
    let (mut doc, _, web) = sample();
    doc.move_node(web, None).unwrap();
    assert!(doc.resolve(web).unwrap().path.is_empty());
    let copy = doc.duplicate(web, None).unwrap();
    assert_ne!(copy, web);
    assert_eq!(doc.resolve(copy).unwrap().connection.name, "web-1 (copy)");
}

#[test]
fn store_round_trip_survives_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lab.bastion.json");
    let (doc, _, web) = sample();
    let saved = Store::new(&path).save(&doc).unwrap();
    assert_eq!(saved.revision, 1);
    let reloaded = Store::new(&path).load().unwrap();
    assert_eq!(reloaded, saved);
    assert_eq!(reloaded.resolve(web).unwrap().connection.host, "10.0.0.5");
}

#[test]
fn concurrent_edit_is_detected_as_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("d.json"));
    let base = store.save(&Document::new("D")).unwrap();
    let mut a = base.clone();
    let mut b = base.clone();
    a.name = "A".into();
    b.name = "B".into();
    store.save(&a).unwrap();
    assert!(matches!(store.save(&b), Err(CoreError::Conflict { expected: 1, found: 2 })));
}

#[test]
fn corrupt_document_is_reported_and_recoverable_from_backup() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d.json");
    let store = Store::new(&path);
    let v1 = store.save(&Document::new("Good")).unwrap();
    store.save(&v1).unwrap(); // creates a backup of v1
    std::fs::write(&path, b"{ not json").unwrap();
    assert!(matches!(store.load(), Err(CoreError::Corrupt(_))));
    assert_eq!(store.recover_latest().unwrap().name, "Good");
}

#[cfg(unix)]
#[test]
fn saved_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("d.json");
    Store::new(&path).save(&Document::new("D")).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[test]
fn vault_round_trip_and_wrong_password() {
    let mut v = Vault::default();
    let id = v.add(Credential {
        id: Uuid::new_v4(),
        name: "prod".into(),
        folder: None,
        scope: None,
        owner: None,
        kind: CredentialKind::Password { username: "ops".into(), password: Secret::new("hunter2-Very-Long") },
    });
    let sealed = v.seal("correct horse").unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("hunter2"), "ciphertext must not contain plaintext");
    let opened = Vault::open(&sealed, "correct horse").unwrap();
    match &opened.get(id).unwrap().kind {
        CredentialKind::Password { password, .. } => assert_eq!(password.expose(), "hunter2-Very-Long"),
        _ => panic!("wrong kind"),
    }
    assert!(matches!(Vault::open(&sealed, "wrong"), Err(CoreError::VaultAuth)));
}

#[test]
fn secret_debug_output_is_redacted() {
    let s = Secret::new("topsecret");
    assert!(!format!("{s:?}").contains("topsecret"));
}

#[test]
fn generated_passwords_are_strong() {
    let p = generate_password(24);
    assert_eq!(p.expose().len(), 24);
    assert!(strength_bits(p.expose()) > 100.0);
    assert!(strength_bits("abc") < 20.0);
}

#[test]
fn substitution_blocks_secrets_unless_authorized() {
    let mut v = Variables::default();
    v.set("Host", "web-1");
    v.set_secret("Password", "s3cr3t");
    assert_eq!(v.substitute("ssh $HOST$ costs $$5", false).unwrap(), "ssh web-1 costs $5");
    assert!(matches!(v.substitute("echo $Password$", false), Err(CoreError::SecretLeak(_))));
    assert_eq!(v.substitute("$PASSWORD$", true).unwrap(), "s3cr3t");
    assert!(v.substitute("$NOPE$", false).is_err());
    assert_eq!(v.redact("output s3cr3t end"), "output *** end");
}

#[test]
fn search_matches_across_fields_with_and_semantics() {
    let (doc, _, _) = sample();
    assert_eq!(search(&doc, "prod linux").len(), 1);
    assert_eq!(search(&doc, "prod windows").len(), 0);
    assert_eq!(search(&doc, "10.0.0").len(), 1);
}

#[test]
fn imports_openssh_config() {
    let cfg = "Host *\n  ServerAliveInterval 30\nHost bastion\n  HostName 1.2.3.4\n  User jump\n  Port 2222\nHost app\n  HostName app.internal\n  ProxyJump bastion\n";
    let conns = import::openssh_config(cfg);
    assert_eq!(conns.len(), 2);
    assert_eq!(conns[0].host, "1.2.3.4");
    assert_eq!(conns[0].settings.port, Some(2222));
    assert_eq!(conns[1].metadata.get("ProxyJump").map(String::as_str), Some("bastion"));
}

#[test]
fn imports_csv_and_rejects_password_columns() {
    let ok = "name,host,protocol,port,tags\n\"Web, primary\",web.local,ssh,2200,a;b\nDC,dc.local,rdp,,\n";
    let conns = import::csv(ok).unwrap();
    assert_eq!(conns[0].name, "Web, primary");
    assert_eq!(conns[0].settings.port, Some(2200));
    assert_eq!(conns[0].tags, vec!["a", "b"]);
    assert_eq!(conns[1].protocol, Protocol::Rdp);
    assert!(import::csv("name,host,protocol,password\na,b,ssh,x\n").is_err());
    assert!(import::csv("name,host,protocol\na,b,gopher\n").is_err());
}

#[test]
fn imports_rdp_file() {
    let c = import::rdp_file("dc", "full address:s:dc01.corp:3390\r\nusername:s:CORP\\admin\r\ngatewayhostname:s:gw.corp\r\n").unwrap();
    assert_eq!(c.host, "dc01.corp");
    assert_eq!(c.settings.port, Some(3390));
    assert_eq!(c.metadata.get("RDGateway").map(String::as_str), Some("gw.corp"));
}

#[test]
fn large_inventory_resolves_quickly() {
    let mut doc = Document::new("Big");
    for f in 0..50 {
        let fo = folder(&format!("F{f}"), Settings::default());
        let fid = fo.id;
        doc.insert(None, Node::Folder(fo)).unwrap();
        for i in 0..100 {
            doc.insert(Some(fid), Node::Connection(Connection::new(format!("h{f}-{i}"), Protocol::Ssh, "x"))).unwrap();
        }
    }
    let t = std::time::Instant::now();
    assert_eq!(doc.connections().len(), 5000);
    assert_eq!(search(&doc, "h49-99").len(), 1);
    assert!(t.elapsed().as_millis() < 500, "took {:?}", t.elapsed());
}

#[test]
fn user_metadata_is_namespaced_away_from_internal_bindings() {
    let (mut doc, _, web) = sample();
    doc.set_metadata(web, "VaultwardenItem", Some("item-1".into())).unwrap();
    doc.set_user_metadata(web, "Owner", Some("ops team")).unwrap();
    doc.set_user_metadata(web, "VaultwardenItem", Some("evil")).unwrap();
    let c = doc.resolve(web).unwrap().connection;
    assert_eq!(c.metadata.get("VaultwardenItem").map(String::as_str), Some("item-1"));
    let user = c.user_metadata();
    assert_eq!(user.get("Owner").map(String::as_str), Some("ops team"));
    assert_eq!(user.get("VaultwardenItem").map(String::as_str), Some("evil"));
    assert!(!user.contains_key("user.Owner"));
    doc.set_user_metadata(web, "VaultwardenItem", None).unwrap();
    let c = doc.resolve(web).unwrap().connection;
    assert_eq!(c.metadata.get("VaultwardenItem").map(String::as_str), Some("item-1"));
    assert_eq!(c.user_metadata().len(), 1);
}

#[test]
fn user_metadata_refuses_bad_keys_secret_names_and_overflow() {
    let (mut doc, _, web) = sample();
    for bad in ["", "   ", "a/b", "line\nbreak", &"k".repeat(65)] {
        assert!(matches!(doc.set_user_metadata(web, bad, Some("v")), Err(CoreError::Invalid(_))), "{bad:?}");
    }
    assert!(matches!(doc.set_user_metadata(web, "Root password", Some("x")), Err(CoreError::Invalid(_))));
    assert!(matches!(doc.set_user_metadata(web, "k", Some(&"v".repeat(1025))), Err(CoreError::Invalid(_))));
    for i in 0..bastion_core::model::MAX_USER_METADATA {
        doc.set_user_metadata(web, &format!("k{i}"), Some("v")).unwrap();
    }
    assert!(doc.set_user_metadata(web, "one-more", Some("v")).is_err());
    doc.set_user_metadata(web, "k0", Some("updated")).unwrap();
}

#[test]
fn icon_accepts_known_names_and_falls_back_to_protocol_default() {
    let (mut doc, _, web) = sample();
    assert_eq!(doc.resolve(web).unwrap().connection.effective_icon(), "terminal");
    doc.set_icon(web, Some("database")).unwrap();
    assert_eq!(doc.resolve(web).unwrap().connection.effective_icon(), "database");
    assert!(matches!(doc.set_icon(web, Some("../x.png")), Err(CoreError::Invalid(_))));
    doc.set_icon(web, None).unwrap();
    let mut c = doc.resolve(web).unwrap().connection;
    c.icon = Some("hand-edited".into());
    assert_eq!(c.effective_icon(), "terminal");
    assert_eq!(Connection::new("r", Protocol::Rdp, "h").effective_icon(), "desktop");
}

#[test]
fn inline_secrets_are_hidden_from_listings_and_pruned_with_their_connection() {
    use bastion_core::vault::{CredentialKind, Secret, Vault};
    let mut v = Vault::default();
    let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    v.set_inline(a, CredentialKind::Password { username: "root".into(), password: Secret::new("pw-a") });
    v.set_inline(b, CredentialKind::Password { username: "root".into(), password: Secret::new("pw-b") });
    assert!(v.list().is_empty(), "inline secrets are not saved credentials");
    assert_eq!(v.get(a).map(|c| c.id), Some(a), "a Vault login with the connection id reads it");
    let sealed = v.seal("master-pass").unwrap();
    assert!(!String::from_utf8_lossy(&sealed).contains("pw-a"));
    let mut back = Vault::open(&sealed, "master-pass").unwrap();
    assert!(back.inline(a).is_some());
    assert_eq!(back.prune_inline(&[a].into_iter().collect()), 1);
    assert!(back.inline(b).is_none() && back.remove_inline(a) && back.inline(a).is_none());
}

#[test]
fn protocol_as_str_is_the_serde_wire_name_for_every_variant() {
    use bastion_core::model::Protocol;
    for p in Protocol::ALL {
        assert_eq!(serde_json::to_value(p).unwrap(), serde_json::Value::String(p.as_str().into()), "{p:?}");
        assert_eq!(serde_json::from_value::<Protocol>(p.as_str().into()).unwrap(), p);
    }
    let unique: std::collections::BTreeSet<_> = Protocol::ALL.iter().collect();
    assert_eq!(unique.len(), Protocol::ALL.len());
}
