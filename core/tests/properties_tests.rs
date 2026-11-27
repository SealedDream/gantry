use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use bastion_core::properties::{self, ValueSource};
use uuid::Uuid;

/// Library > Prod (username=deploy, keepalive 30) > web (ssh), db (ssh, port 2222); root win (rdp).
fn fixture() -> (Document, Uuid, Uuid, Uuid, Uuid) {
    let mut doc = Document::new("t");
    let web = Connection::new("web", Protocol::Ssh, "10.0.0.1");
    let mut db = Connection::new("db", Protocol::Ssh, "10.0.0.2");
    db.settings.port = Some(2222);
    let win = Connection::new("win", Protocol::Rdp, "win.lan");
    let prod = Folder {
        id: Uuid::new_v4(),
        name: "Prod".into(),
        color: None,
        defaults: Settings { username: Some("deploy".into()), keepalive_secs: Some(30), ..Default::default() },
        children: vec![], dynamic_task_id: None, extra: Default::default(),
    };
    let (pid, wid, did, rid) = (prod.id, web.id, db.id, win.id);
    doc.insert(None, Node::Folder(prod)).unwrap();
    doc.insert(Some(pid), Node::Connection(web)).unwrap();
    doc.insert(Some(pid), Node::Connection(db)).unwrap();
    doc.insert(None, Node::Connection(win)).unwrap();
    (doc, pid, wid, did, rid)
}

fn get(values: &[properties::PropertyValue], key: &str) -> properties::PropertyValue {
    values.iter().find(|v| v.key == key).unwrap().clone()
}

#[test]
fn ssh_schema_offers_keepalive_and_rdp_does_not() {
    assert!(properties::schema(Protocol::Ssh).iter().any(|d| d.key == "keepalive_secs"));
    assert!(!properties::schema(Protocol::Rdp).iter().any(|d| d.key == "keepalive_secs"));
}

#[test]
fn connection_reports_inherited_own_and_builtin_sources() {
    let (doc, _, web, db, _) = fixture();
    let w = properties::connection_values(&doc, web).unwrap();
    assert_eq!(get(&w, "username").source, ValueSource::Inherited);
    assert_eq!(get(&w, "username").from.as_deref(), Some("Prod"));
    assert_eq!(get(&w, "port").source, ValueSource::Builtin);
    assert_eq!(get(&w, "port").effective.as_deref(), Some("22"));
    let d = properties::connection_values(&doc, db).unwrap();
    assert_eq!(get(&d, "port").source, ValueSource::Own);
}

#[test]
fn type_defaults_sit_below_folders_and_above_builtins() {
    let (mut doc, _, web, _, win) = fixture();
    properties::set_type_value(&mut doc, Protocol::Ssh, "port", Some("2200")).unwrap();
    properties::set_type_value(&mut doc, Protocol::Ssh, "username", Some("admin")).unwrap();
    let w = properties::connection_values(&doc, web).unwrap();
    assert_eq!(get(&w, "port").source, ValueSource::TypeDefault);
    assert_eq!(get(&w, "username").from.as_deref(), Some("Prod"), "folder beats type default");
    assert_eq!(doc.resolve(web).unwrap().effective.port, Some(2200), "resolve agrees with the editor");
    assert_eq!(doc.resolve(win).unwrap().effective.port, Some(3389), "other types keep built-ins");
}

#[test]
fn reset_returns_a_value_to_inherited() {
    let (mut doc, _, _, db, _) = fixture();
    properties::set_value(&mut doc, db, "port", None).unwrap();
    assert_eq!(get(&properties::connection_values(&doc, db).unwrap(), "port").source, ValueSource::Builtin);
}

#[test]
fn invalid_values_are_rejected_and_leave_the_document_unchanged() {
    let (mut doc, pid, web, _, win) = fixture();
    let before = doc.clone();
    assert!(properties::set_value(&mut doc, web, "port", Some("70000")).is_err());
    assert!(properties::set_value(&mut doc, web, "name", Some("  ")).is_err());
    assert!(properties::set_value(&mut doc, win, "keepalive_secs", Some("10")).is_err());
    assert!(properties::set_value(&mut doc, pid, "keepalive_secs", Some("0")).is_err());
    assert!(properties::set_type_value(&mut doc, Protocol::Rdp, "keepalive_secs", Some("10")).is_err());
    assert_eq!(doc, before);
}

#[test]
fn folder_values_and_affected_preview() {
    let (mut doc, pid, web, _, _) = fixture();
    let f = properties::folder_values(&doc, pid).unwrap();
    assert_eq!(get(&f, "username").source, ValueSource::Own);
    assert_eq!(properties::affected_by(&doc, Some(pid), None, "port"), vec!["web"]);
    assert_eq!(properties::affected_by(&doc, None, Some(Protocol::Ssh), "username"), Vec::<String>::new());
    properties::set_value(&mut doc, web, "username", Some("me")).unwrap();
    assert!(properties::affected_by(&doc, Some(pid), None, "username").contains(&"db".to_string()));
    assert!(!properties::affected_by(&doc, Some(pid), None, "username").contains(&"web".to_string()));
}

#[test]
fn edits_to_name_tags_and_notes_round_trip() {
    let (mut doc, _, web, _, _) = fixture();
    properties::set_value(&mut doc, web, "tags", Some("a, b ,,c")).unwrap();
    properties::set_value(&mut doc, web, "name", Some("web-01")).unwrap();
    let w = properties::connection_values(&doc, web).unwrap();
    assert_eq!(get(&w, "tags").own.as_deref(), Some("a, b, c"));
    assert_eq!(get(&w, "name").own.as_deref(), Some("web-01"));
}

#[test]
fn documents_without_type_defaults_still_load() {
    let doc = Document::new("t");
    let json = serde_json::to_string(&doc).unwrap();
    assert!(!json.contains("type_defaults"));
    let back: Document = serde_json::from_str(&json).unwrap();
    assert_eq!(back, doc);
}

#[test]
fn catalog_only_marks_types_with_a_session_as_connecting() {
    use bastion_core::catalog::{catalog, Support};
    let connects: Vec<_> = catalog().into_iter().filter(|t| t.support == Support::Connects).map(|t| t.id).collect();
    assert_eq!(connects, vec!["folder", "ssh", "local", "services", "processes", "eventlog"]);
    let ids: Vec<_> = catalog().iter().map(|t| t.id).collect();
    let mut unique = ids.clone();
    unique.dedup();
    assert_eq!(ids.len(), unique.len());
}

#[test]
fn a_host_app_declares_which_types_it_opens() {
    use bastion_core::catalog::{catalog, catalog_for, Support};
    let support = |cat: &[bastion_core::catalog::TypeDescriptor], id: &str| cat.iter().find(|t| t.id == id).unwrap().support;
    let mac = catalog_for(&["rdp", "vnc", "web", "sftp", "made-up"]);
    for id in ["rdp", "vnc", "web", "sftp"] {
        assert_eq!(support(&mac, id), Support::Connects, "{id}");
        assert!(!mac.iter().find(|t| t.id == id).unwrap().summary.contains("not implemented"), "{id}");
    }
    // Types the host did not name, and types with no session at all, keep the shared status.
    assert_eq!(support(&mac, "telnet"), Support::Planned);
    assert_eq!(support(&mac, "hyperv"), Support::Planned);
    assert_eq!(catalog_for(&["hyperv", "credential"]), catalog());
    assert_eq!(catalog_for(&[]), catalog());
    assert_eq!(mac.len(), catalog().len());
}

#[test]
fn hosts_and_lengths_are_validated() {
    let (mut doc, _, web, _, _) = fixture();
    let before = doc.clone();
    for bad in ["a b", "-oProxyCommand=x", "host\nname", "\u{7}bell"] {
        assert!(properties::set_value(&mut doc, web, "host", Some(bad)).is_err(), "{bad:?} accepted");
    }
    assert!(properties::set_value(&mut doc, web, "host", Some(&"h".repeat(254))).is_err());
    assert!(properties::set_value(&mut doc, web, "name", Some(&"n".repeat(257))).is_err());
    assert!(properties::set_value(&mut doc, web, "notes", Some(&"x".repeat(64 * 1024 + 1))).is_err());
    assert_eq!(doc, before);
    properties::set_value(&mut doc, web, "host", Some(" fe80::1 ")).unwrap();
    assert_eq!(get(&properties::connection_values(&doc, web).unwrap(), "host").effective.as_deref(), Some("fe80::1"));
}

#[test]
fn favourites_toggle_and_unknown_ids_are_errors() {
    let (mut doc, _, web, _, _) = fixture();
    doc.set_favorite(web, true).unwrap();
    assert!(doc.connections().iter().any(|r| r.connection.id == web && r.connection.favorite));
    doc.set_favorite(web, false).unwrap();
    assert!(doc.connections().iter().all(|r| !r.connection.favorite));
    assert!(doc.set_favorite(Uuid::new_v4(), true).is_err());
}

#[test]
fn classification_edits_make_a_connection_sensitive() {
    let (mut doc, pid, web, _, win) = fixture();
    let sensitive = |doc: &Document, id| doc.connections().into_iter().find(|r| r.connection.id == id).unwrap().connection.classification.is_sensitive();
    let v = properties::connection_values(&doc, web).unwrap();
    assert_eq!(get(&v, "environment").effective.as_deref(), Some("unclassified"));
    assert_eq!(get(&v, "privileged").effective.as_deref(), Some("false"));
    assert!(!sensitive(&doc, web));

    properties::set_value(&mut doc, web, "environment", Some("production")).unwrap();
    assert!(sensitive(&doc, web));
    assert_eq!(get(&properties::connection_values(&doc, web).unwrap(), "environment").own.as_deref(), Some("production"));
    properties::set_value(&mut doc, web, "environment", None).unwrap();
    assert!(!sensitive(&doc, web), "blank resets to unclassified");

    properties::set_value(&mut doc, win, "privileged", Some("true")).unwrap();
    assert!(sensitive(&doc, win), "every connection type has the Security properties");
    properties::set_value(&mut doc, win, "customer_sensitive", Some("true")).unwrap();
    properties::set_value(&mut doc, win, "privileged", Some("false")).unwrap();
    assert!(sensitive(&doc, win));

    let before = doc.clone();
    assert!(properties::set_value(&mut doc, web, "environment", Some("prod")).is_err());
    assert!(properties::set_value(&mut doc, web, "privileged", Some("yes")).is_err());
    assert!(properties::set_value(&mut doc, pid, "environment", Some("production")).is_err(), "not a folder default");
    assert_eq!(doc, before);
    assert!(properties::default_schema(None).iter().all(|d| d.category != "Security"), "classification is per connection");
    let env = properties::schema(Protocol::Ssh).into_iter().find(|d| d.key == "environment").unwrap();
    assert_eq!(env.options.len(), 5);
}

#[test]
fn auto_reconnect_is_an_inheritable_ssh_toggle_on_by_default() {
    let (mut doc, _, web, _, _) = fixture();
    assert!(!properties::schema(Protocol::Rdp).iter().any(|d| d.key == "auto_reconnect"));
    let w = properties::connection_values(&doc, web).unwrap();
    assert_eq!(get(&w, "auto_reconnect").effective.as_deref(), Some("true"));
    assert_eq!(get(&w, "auto_reconnect").source, ValueSource::Builtin);
    properties::set_type_value(&mut doc, Protocol::Ssh, "auto_reconnect", Some("false")).unwrap();
    assert_eq!(doc.resolve(web).unwrap().effective.auto_reconnect, Some(false));
    assert!(properties::set_type_value(&mut doc, Protocol::Ssh, "auto_reconnect", Some("yes")).is_err());
}

/// RDP redirection: clipboard and sound default on (like mstsc), no folder is shared unless one
/// is set, and a folder default on a folder reaches its RDP connections.
#[test]
fn rdp_redirection_defaults_and_inheritance() {
    let (mut doc, pid, _, _, rid) = fixture();
    let keys: Vec<_> = properties::schema(Protocol::Rdp).iter().map(|d| d.key).collect();
    for k in ["rdp_clipboard", "rdp_audio", "rdp_shared_folder"] {
        assert!(keys.contains(&k), "{k} offered for RDP");
        assert!(!properties::schema(Protocol::Ssh).iter().any(|d| d.key == k), "{k} not for SSH");
    }
    let v = properties::connection_values(&doc, rid).unwrap();
    assert_eq!(get(&v, "rdp_clipboard").effective.as_deref(), Some("true"));
    assert_eq!(get(&v, "rdp_audio").effective.as_deref(), Some("true"));
    assert_eq!(get(&v, "rdp_shared_folder").effective, None);

    properties::set_value(&mut doc, rid, "rdp_clipboard", Some("false")).unwrap();
    properties::set_value(&mut doc, rid, "rdp_shared_folder", Some("/Users/me/Transfer")).unwrap();
    let r = doc.resolve(rid).unwrap();
    assert_eq!((r.effective.rdp_clipboard, r.effective.rdp_shared_folder.as_deref()), (Some(false), Some("/Users/me/Transfer")));

    // A folder default reaches a connection moved inside it.
    let mut inner = Connection::new("win2", Protocol::Rdp, "win2.lan");
    let iid = inner.id;
    inner.settings = Settings::default();
    doc.insert(Some(pid), Node::Connection(inner)).unwrap();
    properties::set_value(&mut doc, pid, "rdp_audio", Some("false")).unwrap();
    assert_eq!(doc.resolve(iid).unwrap().effective.rdp_audio, Some(false));
}

#[test]
fn shared_folder_must_be_a_full_path_and_not_the_whole_disk() {
    let (mut doc, _, _, _, rid) = fixture();
    for bad in ["Transfer", "~/Transfer", "/", "///", "/Users/me/../../etc", "/a\nb"] {
        assert!(properties::set_value(&mut doc, rid, "rdp_shared_folder", Some(bad)).is_err(), "{bad:?}");
    }
    assert_eq!(doc.resolve(rid).unwrap().effective.rdp_shared_folder, None, "refused values leave nothing behind");
    properties::set_value(&mut doc, rid, "rdp_shared_folder", Some("  /Volumes/USB/Share  ")).unwrap();
    assert_eq!(doc.resolve(rid).unwrap().effective.rdp_shared_folder.as_deref(), Some("/Volumes/USB/Share"));
}

#[test]
fn credential_is_inherited_from_the_nearest_folder_and_named_ones_count_as_set() {
    use bastion_core::properties::{effective_credential, CredentialRef, ValueSource};
    let mut doc = Document::new("t");
    let (outer, inner) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let cred = uuid::Uuid::new_v4();
    doc.insert(None, Node::Folder(Folder { id: outer, name: "Acme".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() })).unwrap();
    doc.insert(Some(outer), Node::Folder(Folder { id: inner, name: "Web".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() })).unwrap();
    let c = Connection::new("web1", Protocol::Ssh, "10.0.0.1");
    let id = c.id;
    doc.insert(Some(inner), Node::Connection(c)).unwrap();
    assert_eq!(effective_credential(&doc, id).unwrap(), None);

    properties::set_value(&mut doc, outer, "credential_id", Some(&cred.to_string())).unwrap();
    assert_eq!(effective_credential(&doc, id).unwrap(), Some((CredentialRef::Id(cred), ValueSource::Inherited, Some("Acme".into()))));
    // A name on a nearer folder wins over an id further up.
    properties::set_value(&mut doc, inner, "credential_name", Some("deploy")).unwrap();
    assert_eq!(effective_credential(&doc, id).unwrap().unwrap().0, CredentialRef::Name("deploy".into()));
    let v = properties::connection_values(&doc, id).unwrap();
    let name = v.iter().find(|p| p.key == "credential_name").unwrap();
    assert_eq!((name.source, name.from.as_deref()), (ValueSource::Inherited, Some("Web")));
    // Reset on the inner folder falls back to the outer id.
    properties::set_value(&mut doc, inner, "credential_name", None).unwrap();
    assert_eq!(effective_credential(&doc, id).unwrap().unwrap().0, CredentialRef::Id(cred));
    assert!(properties::set_value(&mut doc, outer, "credential_id", Some("nope")).is_err());
}

#[test]
fn local_terminal_offers_only_shell_settings() {
    let keys: Vec<_> = properties::schema(Protocol::Local).into_iter().map(|d| d.key).collect();
    assert!(keys.contains(&"local.shell") && keys.contains(&"local.cwd"));
    assert!(!keys.contains(&"host") && !keys.contains(&"port") && !keys.contains(&"credential_id"));
    let mut doc = Document::new("t");
    let c = Connection::new("zsh", Protocol::Local, "");
    let id = c.id;
    doc.insert(None, Node::Connection(c)).unwrap();
    assert!(properties::set_value(&mut doc, id, "local.shell", Some("tcsh; rm -rf")).is_err());
    properties::set_value(&mut doc, id, "local.shell", Some("fish")).unwrap();
    // A WSL distribution is stored as `wsl:<name>`; option-like or malformed names are refused.
    properties::set_value(&mut doc, id, "local.shell", Some("wsl:Ubuntu-24.04")).unwrap();
    for bad in ["wsl:--exec", "wsl:", "wsl:a b", "wsl2:Ubuntu"] {
        assert!(properties::set_value(&mut doc, id, "local.shell", Some(bad)).is_err(), "{bad}");
    }
    assert!(properties::set_value(&mut doc, id, "local.cwd", Some("relative")).is_err());
}

#[test]
fn wake_on_lan_settings_validate_and_inherit() {
    use bastion_core::properties::ValueSource;
    let mut doc = Document::new("t");
    let office = uuid::Uuid::new_v4();
    doc.insert(None, Node::Folder(Folder { id: office, name: "Office".into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() })).unwrap();
    let c = Connection::new("pc", Protocol::Rdp, "192.168.1.20");
    let id = c.id;
    doc.insert(Some(office), Node::Connection(c)).unwrap();

    properties::set_value(&mut doc, id, "wol_mac", Some("00-11-22-AA-BB-CC")).unwrap();
    assert_eq!(doc.resolve(id).unwrap().effective.wol_mac.as_deref(), Some("00:11:22:aa:bb:cc"), "stored in one form");
    for (k, v) in [("wol_mac", "01:00:5e:00:00:01"), ("wol_broadcast", "8.8.8.255"), ("wol_port", "0"), ("wol_secureon", "12"), ("wol_wait_secs", "999"), ("wol_before_connect", "maybe")] {
        assert!(properties::set_value(&mut doc, id, k, Some(v)).is_err(), "{k}={v}");
    }
    assert!(!properties::default_schema(None).iter().any(|d| d.key == "wol_mac"), "a MAC belongs to one host");

    properties::set_value(&mut doc, office, "wol_broadcast", Some("192.168.1.0/24")).unwrap();
    properties::set_value(&mut doc, office, "wol_before_connect", Some("true")).unwrap();
    let v = properties::connection_values(&doc, id).unwrap();
    let b = v.iter().find(|p| p.key == "wol_broadcast").unwrap();
    assert_eq!((b.source, b.from.as_deref()), (ValueSource::Inherited, Some("Office")));
    let port = v.iter().find(|p| p.key == "wol_port").unwrap();
    assert_eq!((port.effective.as_deref(), port.source), (Some("9"), ValueSource::Builtin));
    let plan = bastion_core::wol::plan_for(&doc, id).unwrap().unwrap();
    assert!(plan.before_connect);
    assert!(!properties::schema(Protocol::Local).iter().any(|d| d.key.starts_with("wol_")));
}

#[test]
fn no_preview_defaults_off_inherits_from_folder_and_can_be_overridden() {
    let (mut doc, prod, web, db, win) = fixture();
    assert_eq!(get(&properties::connection_values(&doc, web).unwrap(), "no_preview").effective.as_deref(), Some("false"));
    assert_ne!(doc.resolve(web).unwrap().effective.no_preview, Some(true), "off by default");
    assert!(properties::schema(Protocol::Rdp).iter().any(|d| d.key == "no_preview"), "offered on desktop types");
    assert!(properties::folder_schema().iter().any(|d| d.key == "no_preview"), "settable on folders");

    properties::set_value(&mut doc, prod, "no_preview", Some("true")).unwrap();
    let w = get(&properties::connection_values(&doc, web).unwrap(), "no_preview");
    assert_eq!((w.effective.as_deref(), w.source), (Some("true"), ValueSource::Inherited));
    assert_eq!(doc.resolve(web).unwrap().effective.no_preview, Some(true));
    assert_ne!(doc.resolve(win).unwrap().effective.no_preview, Some(true), "outside the folder");

    properties::set_value(&mut doc, db, "no_preview", Some("false")).unwrap();
    assert_eq!(doc.resolve(db).unwrap().effective.no_preview, Some(false), "own value beats the folder");
    assert!(properties::set_value(&mut doc, db, "no_preview", Some("maybe")).is_err());
}

#[test]
fn no_preview_round_trips_through_json() {
    let (mut doc, _, web, _, _) = fixture();
    properties::set_value(&mut doc, web, "no_preview", Some("true")).unwrap();
    let back: Document = serde_json::from_str(&serde_json::to_string(&doc).unwrap()).unwrap();
    assert_eq!(back.resolve(web).unwrap().effective.no_preview, Some(true));
    let plain = Settings::default();
    assert!(!serde_json::to_string(&plain).unwrap().contains("no_preview"), "unset is not written");
}
