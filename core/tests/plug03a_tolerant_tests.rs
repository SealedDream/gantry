//! PLUG-03a: readers keep connection types and fields this app does not know, mark such
//! entries, refuse to connect to them, and still report damaged files as corrupt.
use std::path::Path;

use bastion_core::ansible_inventory;
use bastion_core::docfile::{self, DocumentFile, VERSION};
use bastion_core::error::CoreError;
use bastion_core::export::{self, Selection};
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, NEEDS_NEWER};
use bastion_core::properties;
use bastion_core::store::Store;
use bastion_core::unknown::{MAX_PROTOCOL_NAME_BYTES, MAX_UNKNOWN_DEPTH, MAX_UNKNOWN_ENTRY_BYTES, MAX_UNKNOWN_TOTAL_BYTES};
use serde_json::{json, Value};
use uuid::Uuid;

const LIBRARY: &str = include_str!("fixtures/plug03a/library-unknown.json");
const GOLDEN_DOCUMENT: &str = include_str!("fixtures/plug03a/v1-golden.bastion");
const GOLDEN_LIBRARY: &str = include_str!("fixtures/plug03a/v1-golden-library.json");

const UNKNOWN_ID: &str = "0a000000-0000-4000-8000-000000000004";
const SSH_ID: &str = "0a000000-0000-4000-8000-000000000005";
const FOLDER_ID: &str = "0a000000-0000-4000-8000-000000000003";

/// Where the fixture holds data this app does not know, as JSON pointers into the document.
const UNKNOWN_POINTERS: &[&str] = &[
    "/root/defaults/future_default",
    "/root/children/0/folder_badge",
    "/root/children/0/children/0/protocol",
    "/root/children/0/children/0/plugin",
    "/root/children/0/children/0/settings/sslmode",
    "/root/children/0/children/1/future_flag",
    "/type_defaults/postgresql",
    "/type_defaults/ssh/future_ssh_default",
    "/plugins",
];

fn id(s: &str) -> Uuid {
    Uuid::parse_str(s).unwrap()
}

fn library_value() -> Value {
    serde_json::from_str(LIBRARY).unwrap()
}

fn document_value(version: u32) -> Value {
    json!({
        "format": "bastion-document", "version": version,
        "id": "0a000000-0000-4000-8000-000000000001", "name": "Shared", "revision": 3,
        "contents": { "document": library_value(), "future_contents": { "k": [1, "two"] } }
    })
}

fn write(path: &Path, v: &Value) {
    std::fs::write(path, serde_json::to_vec_pretty(v).unwrap()).unwrap();
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Every unknown value of the fixture is in `saved` (a library document as JSON), unchanged.
fn assert_unknown_kept(saved: &Value) {
    let original = library_value();
    for p in UNKNOWN_POINTERS {
        let want = original.pointer(p).unwrap_or_else(|| panic!("fixture has {p}"));
        assert_eq!(saved.pointer(p), Some(want), "unknown data at {p} changed");
    }
}

fn find(doc: &Document, id: Uuid) -> Connection {
    fn walk(f: &Folder, id: Uuid) -> Option<Connection> {
        f.children.iter().find_map(|n| match n {
            Node::Connection(c) if c.id == id => Some(c.clone()),
            Node::Folder(sub) => walk(sub, id),
            _ => None,
        })
    }
    walk(&doc.root, id).expect("the connection is in the tree")
}

fn assert_marked(doc: &Document) {
    let unknown = find(doc, id(UNKNOWN_ID));
    assert_eq!(unknown.unavailable(), Some(NEEDS_NEWER));
    assert_eq!(unknown.protocol, Protocol::Unsupported);
    assert_eq!(unknown.protocol_name(), "postgresql");
    assert_eq!((unknown.name.as_str(), unknown.host.as_str()), ("orders-db", "db.lab.example"));
    let known = find(doc, id(SSH_ID));
    assert_eq!((known.unavailable(), known.protocol, known.protocol_name()), (None, Protocol::Ssh, "ssh"));
}

fn message(e: CoreError) -> String {
    assert!(!matches!(e, CoreError::Corrupt(_)), "must not be reported as corrupt: {e}");
    e.to_string()
}

fn loaded() -> Document {
    serde_json::from_str(LIBRARY).unwrap()
}

#[test]
fn the_marker_is_one_fixed_text() {
    assert_eq!(NEEDS_NEWER, "Needs a newer Gantry or a plugin");
}

// --- unknown protocols and fields load, are marked, and save unchanged -------------------------

#[test]
fn old_library_json_keeps_unknown_data_through_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, LIBRARY).unwrap();
    let store = Store::new(&path);

    let doc = store.load().expect("an unknown connection type is not corruption");
    assert_marked(&doc);
    assert_eq!(doc.schema, 1, "SCHEMA_VERSION is unchanged");
    assert_eq!(bastion_core::model::SCHEMA_VERSION, 1);

    let saved = store.save(&doc).unwrap();
    assert_unknown_kept(&read(&path));
    assert_eq!(store.load().unwrap(), saved, "reloading gives the same document, unknown data included");
    // The backup the save took is the same tolerant format, so recovery can read it too.
    assert_marked(&store.recover_latest().unwrap());
}

#[test]
fn old_library_json_opens_as_a_document_and_keeps_unknown_data() {
    let dir = tempfile::tempdir().unwrap();
    let mut d = DocumentFile::parse(LIBRARY.as_bytes()).unwrap();
    assert_eq!(d.loaded_version(), 0);
    assert_marked(d.document().unwrap());

    let path = dir.path().join("Shared.bastion");
    d.save_as(&path).unwrap();
    let saved = read(&path);
    // PLUG-03b (spec section 10, step 3): it holds unknown data, so it is written as VERSION + 1.
    assert_eq!(saved["version"], json!(VERSION + 1), "an old library holding unknown data is raised on save");
    assert_unknown_kept(&saved["contents"]["document"]);
}

#[test]
fn document_keeps_unknown_data_value_for_value() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Shared.bastion");
    write(&path, &document_value(VERSION));

    let mut d = DocumentFile::open(&path).unwrap();
    assert_eq!(d.loaded_version(), VERSION);
    assert_marked(d.document().unwrap());
    let before = d.document().unwrap().clone();
    d.document_mut().unwrap();
    d.save().unwrap();

    let saved = read(&path);
    assert_eq!(saved["version"], json!(VERSION + 1), "raised on save: it holds unknown data (PLUG-03b)");
    assert_unknown_kept(&saved["contents"]["document"]);
    assert_eq!(saved.pointer("/contents/future_contents"), document_value(VERSION).pointer("/contents/future_contents"));

    let back = DocumentFile::open(&path).unwrap();
    let mut expected = before;
    expected.revision = back.revision();
    assert_eq!(back.document().unwrap(), &expected);
}

#[test]
fn saving_twice_is_stable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Shared.bastion");
    write(&path, &document_value(VERSION));
    let mut d = DocumentFile::open(&path).unwrap();
    d.document_mut().unwrap();
    d.save().unwrap();
    let first = std::fs::read_to_string(&path).unwrap();
    let mut d = DocumentFile::open(&path).unwrap();
    d.document_mut().unwrap();
    d.save().unwrap();
    let second = std::fs::read_to_string(&path).unwrap();
    assert_eq!(second, first.replace("\"revision\": 4", "\"revision\": 5"));
}

// --- format VERSION + 1 ---------------------------------------------------------------------

#[test]
fn version_plus_one_loads_and_is_saved_as_version_plus_one() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Newer.bastion");
    write(&path, &document_value(VERSION + 1));

    let mut d = DocumentFile::open(&path).unwrap();
    assert_eq!(d.loaded_version(), VERSION + 1);
    assert_marked(d.document().unwrap());
    d.document_mut().unwrap().rename(id(SSH_ID), "web01-renamed").unwrap();
    d.save().unwrap();

    let saved = read(&path);
    assert_eq!(saved["version"], json!(VERSION + 1), "never silently downgraded");
    assert_unknown_kept(&saved["contents"]["document"]);

    let mut back = DocumentFile::open(&path).unwrap();
    assert_eq!(back.loaded_version(), VERSION + 1);
    assert_eq!(find(back.document().unwrap(), id(SSH_ID)).name, "web01-renamed");
    // Save As keeps the format too, and so do the bytes handed to a share target.
    let copy = dir.path().join("Copy.bastion");
    back.save_as(&copy).unwrap();
    assert_eq!(read(&copy)["version"], json!(VERSION + 1));
    let bytes: Value = serde_json::from_slice(&back.to_bytes().unwrap()).unwrap();
    assert_eq!(bytes["version"], json!(VERSION + 1));
}

#[test]
fn a_version_document_is_raised_only_when_saved_with_unknown_data() {
    // PLUG-03b: opening never raises; a save raises a document that holds unknown data.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Shared.bastion");
    write(&path, &document_value(VERSION));
    let mut d = DocumentFile::open(&path).unwrap();
    assert_eq!(read(&path)["version"], json!(VERSION), "opening does not raise");
    d.document_mut().unwrap();
    d.save().unwrap();
    assert_eq!(read(&path)["version"], json!(VERSION + 1));
    // A new document and one made from a tree are VERSION as well.
    let fresh = dir.path().join("Fresh.bastion");
    DocumentFile::new("Fresh").unwrap().save_as(&fresh).unwrap();
    assert_eq!(read(&fresh)["version"], json!(VERSION));
    let from_tree = dir.path().join("Tree.bastion");
    DocumentFile::from_document(loaded()).save_as(&from_tree).unwrap();
    assert_eq!(read(&from_tree)["version"], json!(VERSION + 1), "the tree holds unknown data");
}

#[test]
fn version_plus_two_is_newer_bastion_not_corrupt() {
    for version in [VERSION + 2, VERSION + 40] {
        let bytes = serde_json::to_vec(&document_value(version)).unwrap();
        let e = DocumentFile::parse(&bytes).unwrap_err();
        assert!(matches!(e, CoreError::Invalid(_)), "{e}");
        assert!(message(e).contains("saved by a newer Gantry"));
    }
    let e = DocumentFile::parse(&serde_json::to_vec(&document_value(0)).unwrap()).unwrap_err();
    assert!(matches!(e, CoreError::Corrupt(_)), "format 0 was never written: {e}");
}

// --- no format drift ------------------------------------------------------------------------

/// `v1-golden.*` were saved at revision 1 by the commit before this change
/// (`plug03a_baseline::generate_golden`). Opening and saving them must give the same bytes.
#[test]
fn a_version_document_without_unknown_data_is_byte_stable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("golden.bastion");
    std::fs::write(&path, GOLDEN_DOCUMENT).unwrap();
    let mut d = DocumentFile::open(&path).unwrap();
    d.document_mut().unwrap();
    d.save().unwrap();
    assert_eq!(std::fs::read_to_string(&path).unwrap(), GOLDEN_DOCUMENT.replace("\"revision\": 1", "\"revision\": 2"));

    let lib = dir.path().join("library.json");
    std::fs::write(&lib, GOLDEN_LIBRARY).unwrap();
    let store = Store::new(&lib);
    store.save(&store.load().unwrap()).unwrap();
    assert_eq!(std::fs::read_to_string(&lib).unwrap(), GOLDEN_LIBRARY.replace("\"revision\": 1", "\"revision\": 2"));
}

/// Writes what the previous app is then asked to open (`plug03a_baseline`, evidence file).
#[test]
#[ignore = "run by hand; writes into PLUG03A_OUT for the previous-app check"]
fn save_for_the_previous_app() {
    let out = std::path::PathBuf::from(std::env::var("PLUG03A_OUT").expect("set PLUG03A_OUT"));
    std::fs::create_dir_all(&out).unwrap();
    let path = out.join("saved.bastion");
    std::fs::write(&path, GOLDEN_DOCUMENT).unwrap();
    let mut d = DocumentFile::open(&path).unwrap();
    d.document_mut().unwrap();
    d.save().unwrap();
    let lib = out.join("saved-library.json");
    std::fs::write(&lib, GOLDEN_LIBRARY).unwrap();
    let store = Store::new(&lib);
    store.save(&store.load().unwrap()).unwrap();
}

// --- such entries cannot be connected to, and bulk actions leave them out ---------------------

#[test]
fn connect_paths_refuse_an_unknown_entry_with_the_fixed_text() {
    let doc = loaded();
    assert!(message(doc.resolve(id(UNKNOWN_ID)).unwrap_err()).contains(NEEDS_NEWER));
    assert!(message(doc.resolve_many(&[id(SSH_ID), id(UNKNOWN_ID)]).unwrap_err()).contains(NEEDS_NEWER));
    assert_eq!(doc.resolve(id(SSH_ID)).unwrap().connection.name, "web01");
    // Whole-library walks (connect all, multi-host exec, search, host status) never see it.
    let names: Vec<String> = doc.connections().into_iter().map(|r| r.connection.name).collect();
    assert_eq!(names, ["web01"]);
    assert!(doc.resolve_where(|_, _| true).iter().all(|r| r.connection.protocol != Protocol::Unsupported));
}

#[test]
fn export_leaves_unknown_entries_and_unknown_data_behind() {
    let doc = loaded();
    for selection in [Selection::All, Selection::Nodes([id(FOLDER_ID)].into()), Selection::Nodes([id(UNKNOWN_ID)].into())] {
        let (exported, preview) = export::prepare(&doc, &selection);
        let text = serde_json::to_string(&exported).unwrap();
        for leaked in ["postgresql", "plugin", "sslmode", "future_", "folder_badge", "orders-db"] {
            assert!(!text.contains(leaked), "{leaked} must not be exported");
        }
        assert!(preview.connections <= 1);
        let bytes = export::export(&doc, &selection).unwrap();
        assert!(!String::from_utf8(bytes).unwrap().contains("postgresql"));
    }
    let source = DocumentFile::from_document(doc);
    let (out, summary) = docfile::export(&source, &Selection::All, "Share", false, None).unwrap();
    assert_eq!(summary.connections, 1);
    assert!(!String::from_utf8(out.to_bytes().unwrap()).unwrap().contains("postgresql"));
}

#[test]
fn ansible_inventory_skips_an_unknown_entry() {
    let (text, _skipped) = ansible_inventory::export_document(&loaded(), &Selection::All);
    assert!(text.contains("web01"));
    assert!(!text.contains("orders-db") && !text.contains("db.lab.example"));
}

#[test]
fn import_leaves_unknown_entries_behind() {
    let source = DocumentFile::from_document(loaded());
    let mut target = DocumentFile::new("Mine").unwrap();
    let (plan, folder) = docfile::import_into(&mut target, &source, true).unwrap();
    assert_eq!(plan.connections, 1);
    assert!(folder.is_some());
    let text = serde_json::to_string(target.document().unwrap()).unwrap();
    assert!(text.contains("web01") && !text.contains("postgresql") && !text.contains("future_"));
}

#[test]
fn an_unknown_entry_can_be_renamed_moved_and_deleted_but_not_edited() {
    let mut doc = loaded();
    let unknown = id(UNKNOWN_ID);
    doc.rename(unknown, "orders-db-2").unwrap();
    doc.move_node(unknown, None).unwrap();
    assert_eq!(doc.parent_of(unknown), Some(doc.root.id));
    properties::set_value(&mut doc, unknown, "name", Some("orders-db-3")).unwrap();

    for (key, value) in [("host", "other.example"), ("port", "1"), ("username", "root"), ("protocol", "ssh")] {
        let e = properties::set_value(&mut doc, unknown, key, Some(value)).unwrap_err();
        assert!(message(e).contains(NEEDS_NEWER), "{key} must be read-only");
    }
    assert!(message(doc.duplicate(unknown, None).unwrap_err()).contains(NEEDS_NEWER));

    // Still the same entry underneath, and its unknown data went with it.
    let v = serde_json::to_value(&doc).unwrap();
    let moved = v["root"]["children"].as_array().unwrap().iter().find(|n| n["id"] == json!(UNKNOWN_ID)).unwrap();
    assert_eq!((moved["name"].as_str(), moved["protocol"].as_str(), moved["host"].as_str()), (Some("orders-db-3"), Some("postgresql"), Some("db.lab.example")));
    assert_eq!(moved.get("plugin"), library_value().pointer("/root/children/0/children/0/plugin"));

    assert!(matches!(doc.remove(unknown).unwrap(), Node::Connection(c) if c.id == unknown));
    assert!(matches!(doc.resolve(unknown).unwrap_err(), CoreError::NotFound(_)));
}

#[test]
fn the_menu_of_an_unknown_entry_offers_rename_move_delete_and_no_connect() {
    use bastion_core::actions::{self, ActionContext, ActionId, ObjectKind};
    let cx = ActionContext { kind: Some(ObjectKind::Connection), protocol: Some(Protocol::Unsupported), ..Default::default() };
    let ids: Vec<ActionId> = actions::menu(&cx, &bastion_core::policy::Policy::default(), &actions::all_ids()).into_iter().map(|m| m.id).collect();
    for wanted in [ActionId::Rename, ActionId::Move, ActionId::Delete] {
        assert!(ids.contains(&wanted), "{wanted:?} is offered");
    }
    for hidden in [ActionId::Connect, ActionId::ConnectNewTab, ActionId::Reconnect, ActionId::OpenSftp, ActionId::ConnectAs, ActionId::Duplicate, ActionId::SaveAsTemplate, ActionId::CopyHostname, ActionId::CopyAddress, ActionId::CopyUsername, ActionId::CopySshCommand, ActionId::FullScreen, ActionId::AddToWorkspace] {
        assert!(!ids.contains(&hidden), "{hidden:?} is not offered");
    }
    assert_ne!(actions::default_action(&cx), Some(ActionId::Connect));
}

#[test]
fn an_unknown_type_cannot_be_created_or_given_defaults_by_name() {
    assert!(properties::set_type_value(&mut loaded(), Protocol::Unsupported, "port", Some("1")).is_err());
    assert!(serde_json::from_value::<Protocol>(json!("unsupported")).is_err());
    assert!(serde_json::from_value::<Protocol>(json!("postgresql")).is_err());
    assert!(!Protocol::ALL.contains(&Protocol::Unsupported));
    assert!(serde_json::to_string(&Protocol::Unsupported).is_err());
    let made = Connection::new("x", Protocol::Unsupported, "h");
    assert!(serde_json::to_string(&made).is_err(), "an unknown entry without its original type name is never written");
}

// --- node reading: `kind` first is the fast road, anywhere else reads the same ---------------

#[test]
fn a_node_reads_the_same_wherever_kind_is() {
    let first: Document = serde_json::from_str(LIBRARY).unwrap();
    // serde_json::Value sorts keys, so `kind` comes after `children`, `host` and `id` here.
    let sorted: Document = serde_json::from_value(library_value()).unwrap();
    assert!(first == sorted);
    let last = LIBRARY.replace("\"kind\": \"connection\",\n            \"id\": \"0a000000-0000-4000-8000-000000000005\",", "\"id\": \"0a000000-0000-4000-8000-000000000005\",").replace("\"settings\": { \"port\": 2222 }", "\"settings\": { \"port\": 2222 }, \"kind\": \"connection\"");
    assert_ne!(last, LIBRARY);
    assert!(serde_json::from_str::<Document>(&last).unwrap() == first);
}

#[test]
fn a_missing_repeated_or_unknown_kind_is_corrupt() {
    let text = |from: &str, to: &str| {
        let changed = LIBRARY.replace(from, to);
        assert_ne!(changed, LIBRARY, "the fixture has {from}");
        changed
    };
    let ssh = "\"kind\": \"connection\",\n            \"id\": \"0a000000-0000-4000-8000-000000000005\",";
    let id_only = "\"id\": \"0a000000-0000-4000-8000-000000000005\",";
    assert_corrupt(text(ssh, id_only).as_bytes(), "no kind");
    assert_corrupt(text(ssh, &format!("\"kind\": \"connection\", \"kind\": \"connection\", {id_only}")).as_bytes(), "kind twice, first");
    assert_corrupt(text(ssh, &format!("\"kind\": \"connection\", {id_only} \"kind\": \"folder\",")).as_bytes(), "kind twice, later");
    assert_corrupt(text(ssh, &format!("{id_only} \"kind\": \"connection\", \"kind\": \"connection\",")).as_bytes(), "kind twice, not first");
    assert_corrupt(text(ssh, &format!("\"kind\": 7, {id_only}")).as_bytes(), "kind that is not text");
    assert_corrupt(text(ssh, &format!("{id_only} \"kind\": \"widget\",")).as_bytes(), "unknown kind, not first");
    assert_corrupt(text(ssh, &format!("{id_only} \"host\": \"twice.example\", \"kind\": \"connection\",")).as_bytes(), "a known field twice");
    assert_corrupt(text("\"children\": [\n      {", "\"children\": [\n      [\"folder\"], {").as_bytes(), "a node that is not an object");
}

// --- caps -----------------------------------------------------------------------------------

fn with_plugin_field(value: Value) -> Vec<u8> {
    let mut v = library_value();
    *v.pointer_mut("/root/children/0/children/0/plugin").unwrap() = value;
    serde_json::to_vec(&v).unwrap()
}

fn assert_refused_over_cap(bytes: &[u8]) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, bytes).unwrap();
    for e in [Store::new(&path).load().unwrap_err(), DocumentFile::parse(bytes).unwrap_err()] {
        assert!(matches!(e, CoreError::Invalid(_)), "{e}");
        assert!(message(e).contains("more than this app can keep"));
    }
}

#[test]
fn unknown_data_over_the_entry_cap_is_refused() {
    assert_refused_over_cap(&with_plugin_field(json!("x".repeat(MAX_UNKNOWN_ENTRY_BYTES + 1))));
    // Under the cap is kept.
    let ok = with_plugin_field(json!("x".repeat(MAX_UNKNOWN_ENTRY_BYTES / 2)));
    assert!(DocumentFile::parse(&ok).is_ok());
}

#[test]
fn unknown_data_nested_too_deep_is_refused() {
    let mut deep = json!(1);
    for _ in 0..=MAX_UNKNOWN_DEPTH {
        deep = json!([deep]);
    }
    assert_refused_over_cap(&with_plugin_field(deep));
}

#[test]
fn an_overlong_or_unprintable_unknown_type_name_is_refused() {
    let mut v = library_value();
    *v.pointer_mut("/root/children/0/children/0/protocol").unwrap() = json!("p".repeat(MAX_PROTOCOL_NAME_BYTES + 1));
    assert_refused_over_cap(&serde_json::to_vec(&v).unwrap());
    let mut v = library_value();
    *v.pointer_mut("/root/children/0/children/0/protocol").unwrap() = json!("post\u{0007}gres");
    assert_refused_over_cap(&serde_json::to_vec(&v).unwrap());
}

#[test]
fn unknown_data_over_the_document_cap_is_refused() {
    let mut v = library_value();
    let entry = v.pointer("/root/children/0/children/0").unwrap().clone();
    let per_entry = MAX_UNKNOWN_ENTRY_BYTES / 2;
    let children = v.pointer_mut("/root/children/0/children").unwrap().as_array_mut().unwrap();
    for i in 0..(MAX_UNKNOWN_TOTAL_BYTES / per_entry + 2) {
        let mut e = entry.clone();
        e["id"] = json!(Uuid::from_u128(0x0c00_0000_0000_4000_8000_0000_0000_0000 + i as u128));
        e["plugin"] = json!("y".repeat(per_entry));
        children.push(e);
    }
    assert_refused_over_cap(&serde_json::to_vec(&v).unwrap());
}

// --- damaged files are still corrupt --------------------------------------------------------

fn assert_corrupt(bytes: &[u8], why: &str) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(Store::new(&path).load(), Err(CoreError::Corrupt(_))), "store: {why}");
    assert!(matches!(DocumentFile::parse(bytes), Err(CoreError::Corrupt(_))), "document: {why}");
}

#[test]
fn damaged_data_is_still_corrupt() {
    assert_corrupt(b"{ \"schema\": 1, \"id\": ", "not valid JSON");
    assert_corrupt(&LIBRARY.as_bytes()[..LIBRARY.len() / 2], "truncated");
    assert_corrupt(b"[1, 2, 3]", "not an object");

    let damage: &[(&str, Value, &str)] = &[
        ("/root/children/0/children/0/protocol", json!(5), "type name that is not text"),
        ("/root/children/0/children/0/protocol", json!(""), "empty type name"),
        ("/root/children/0/children/0/favorite", json!("yes"), "known field of the wrong type on an unknown entry"),
        ("/root/children/0/children/0/settings/port", json!("5432"), "known setting of the wrong type on an unknown entry"),
        ("/root/children/0/children/1/host", json!(7), "known field of the wrong type"),
        ("/root/children/0/children/1/settings", json!([1]), "settings that are not an object"),
        ("/root/children/0/children/1/kind", json!("widget"), "unknown node kind"),
        ("/root/children/0/defaults/keepalive_secs", json!(-1), "known default out of range"),
        ("/type_defaults/ssh", json!(3), "known type default that is not an object"),
        ("/type_defaults/ssh/port", json!("22"), "known type default of the wrong type"),
        ("/type_defaults", json!([]), "type defaults that are not an object"),
        ("/revision", json!("3"), "revision that is not a number"),
        ("/id", json!("not-a-uuid"), "bad id"),
    ];
    for (pointer, value, why) in damage {
        let mut v = library_value();
        // Set (or add) the field on its parent object.
        let (parent, key) = pointer.rsplit_once('/').unwrap();
        let holder = if parent.is_empty() { &mut v } else { v.pointer_mut(parent).unwrap_or_else(|| panic!("fixture has {parent}")) };
        holder.as_object_mut().unwrap().insert(key.to_string(), value.clone());
        assert_corrupt(&serde_json::to_vec(&v).unwrap(), why);
    }

    let mut missing = library_value();
    missing["root"]["children"][0]["children"][0].as_object_mut().unwrap().remove("protocol");
    assert_corrupt(&serde_json::to_vec(&missing).unwrap(), "missing type name");

    let mut newer_schema = library_value();
    newer_schema["schema"] = json!(2);
    assert_corrupt(&serde_json::to_vec(&newer_schema).unwrap(), "a newer schema is refused as before");
}

#[test]
fn a_document_without_a_format_marker_or_with_a_damaged_envelope_is_corrupt() {
    let corrupt = |v: Value, why: &str| assert!(matches!(DocumentFile::parse(&serde_json::to_vec(&v).unwrap()), Err(CoreError::Corrupt(_))), "{why}");
    let mut v = document_value(VERSION);
    v.as_object_mut().unwrap().remove("format");
    corrupt(v, "no format marker");
    let mut v = document_value(VERSION);
    v["format"] = json!("something-else");
    corrupt(v, "wrong format marker");
    let mut v = document_value(VERSION);
    v.as_object_mut().unwrap().remove("version");
    corrupt(v, "no version");
    for version in [VERSION, VERSION + 1] {
        let mut v = document_value(version);
        v["contents"]["document"]["root"]["children"][0]["children"][1]["host"] = json!(false);
        corrupt(v, "known field of the wrong type inside a document");
        let mut v = document_value(version);
        v["revision"] = json!("3");
        corrupt(v, "revision of the wrong type");
        let mut v = document_value(version);
        v.as_object_mut().unwrap().remove("contents");
        corrupt(v, "neither stored nor sealed");
        let mut v = document_value(version);
        v["contents"]["vault"] = json!({});
        corrupt(v, "an unprotected document carrying a vault");
    }
}

// --- review round 1 -------------------------------------------------------------------------

use bastion_core::logins::{login_candidates, may_use, LoginPurpose};
use bastion_core::unknown::MAX_FOLDER_DEPTH;
use bastion_core::vault::{Credential, CredentialKind, Secret, Vault};

/// The stack of a macOS secondary thread, where Native Mac does its library work.
const SMALL_STACK: usize = 512 * 1024;

/// A library of `depth` folders, each inside the one before, written with `kind` first or last.
fn nested_library(depth: usize, kind_first: bool) -> Vec<u8> {
    let mut s = String::from(r#"{"schema":1,"id":"0a000000-0000-4000-8000-000000000001","name":"Deep","revision":0,"root":{"id":"0a000000-0000-4000-8000-000000000002","name":"Root","children":["#);
    for i in 0..depth {
        let id = Uuid::from_u128(0x0d00_0000_0000_4000_8000_0000_0000_0000 + i as u128);
        if kind_first {
            s += &format!(r#"{{"kind":"folder","id":"{id}","name":"f","children":["#);
        } else {
            s += &format!(r#"{{"id":"{id}","name":"f","children":["#);
        }
    }
    for _ in 0..depth {
        s += if kind_first { "]}" } else { r#"],"kind":"folder"}"# };
    }
    s += "]}}";
    s.into_bytes()
}

fn folder_depth(f: &Folder) -> usize {
    f.children.iter().map(|n| if let Node::Folder(sub) = n { 1 + folder_depth(sub) } else { 0 }).max().unwrap_or(0)
}

#[test]
fn deep_folder_nesting_on_a_small_stack_loads_or_is_refused_and_never_aborts() {
    let dir = tempfile::tempdir().unwrap();
    // 61 to 63 is around the deepest nesting the JSON reader itself allows.
    for depth in [8, MAX_FOLDER_DEPTH, MAX_FOLDER_DEPTH + 1, 61, 62, 63, 200, 5000] {
        for kind_first in [true, false] {
            let bytes = nested_library(depth, kind_first);
            let path = dir.path().join(format!("deep-{depth}-{kind_first}.json"));
            std::fs::write(&path, &bytes).unwrap();
            let read = std::thread::Builder::new()
                .stack_size(SMALL_STACK)
                .spawn(move || (Store::new(&path).load(), DocumentFile::parse(&bytes).map(|d| d.document().unwrap().clone())))
                .unwrap();
            let (store, document) = read.join().expect("the reader must not panic");
            for got in [store, document] {
                match got {
                    Ok(doc) if depth <= MAX_FOLDER_DEPTH => assert_eq!(folder_depth(&doc.root), depth),
                    Ok(_) => panic!("{depth} nested folders (kind first: {kind_first}) is over the limit and must be refused"),
                    Err(e) => {
                        assert!(depth > MAX_FOLDER_DEPTH, "{depth} nested folders (kind first: {kind_first}) must load: {e}");
                        assert!(matches!(&e, CoreError::Invalid(m) if m.contains("nested")), "depth {depth}, kind first {kind_first}: {e}");
                    }
                }
            }
        }
    }
}

fn empty_folder(name: &str) -> Folder {
    Folder { id: Uuid::new_v4(), name: name.into(), color: None, defaults: Default::default(), children: vec![], dynamic_task_id: None, extra: Default::default() }
}

#[test]
fn folders_cannot_be_nested_past_the_limit_or_saved_that_way() {
    let dir = tempfile::tempdir().unwrap();
    let too_deep = |r: Result<(), CoreError>| assert!(matches!(r, Err(CoreError::Invalid(m)) if m.contains("nested")));
    let mut doc = Document::new("deep");
    let mut chain = vec![];
    for i in 0..MAX_FOLDER_DEPTH {
        let f = empty_folder(&format!("f{i}"));
        chain.push(f.id);
        doc.insert(chain.iter().rev().nth(1).copied(), Node::Folder(f)).unwrap();
    }
    // One more level is refused, by adding and by moving; a connection at the bottom is fine.
    let deepest = *chain.last().unwrap();
    too_deep(doc.insert(Some(deepest), Node::Folder(empty_folder("one too many"))));
    let side = empty_folder("side");
    let side_id = side.id;
    doc.insert(None, Node::Folder(side)).unwrap();
    too_deep(doc.move_node(side_id, Some(deepest)));
    too_deep(doc.move_node(chain[0], Some(side_id)));
    doc.insert(Some(deepest), Node::Connection(Connection::new("leaf", Protocol::Ssh, "h"))).unwrap();
    let path = dir.path().join("library.json");
    let saved = Store::new(&path).save(&doc).unwrap();
    assert!(Store::new(&path).load().unwrap() == saved, "a library at the limit saves and loads");

    // A tree built deeper by other means is not written.
    fn bottom(f: &mut Folder) -> &mut Folder {
        match f.children.iter().position(|n| matches!(n, Node::Folder(_))) {
            Some(i) => match &mut f.children[i] {
                Node::Folder(sub) => bottom(sub),
                Node::Connection(_) => unreachable!(),
            },
            None => f,
        }
    }
    let mut deeper = saved.clone();
    bottom(&mut deeper.root).children.push(Node::Folder(empty_folder("by hand")));
    let e = Store::new(&path).save(&deeper).unwrap_err();
    assert!(matches!(&e, CoreError::Invalid(m) if m.contains("nested")), "{e}");
    assert!(Store::new(&path).load().unwrap() == saved, "the file is untouched");
    let other = dir.path().join("Deep.bastion");
    assert!(matches!(DocumentFile::from_document(deeper).save_as(&other), Err(CoreError::Invalid(m)) if m.contains("nested")));
    assert!(!other.exists());
}

/// A library of `entries` plain entries, each with `notes_bytes` of notes, in a folder
/// `depth` levels below the root.
fn large_library(depth: usize, entries: usize, notes_bytes: usize) -> Document {
    let mut doc = Document::new("large");
    let mut parent = None;
    for i in 0..depth {
        let f = empty_folder(&format!("f{i}"));
        parent = Some(f.id);
        let above = doc.parent_of(f.id); // not in the tree yet: None
        assert!(above.is_none());
        let into = if i == 0 { None } else { Some(last_folder(&doc.root)) };
        doc.insert(into, Node::Folder(f)).unwrap();
    }
    let notes = "n".repeat(notes_bytes);
    for i in 0..entries {
        let mut c = Connection::new(format!("c{i}"), Protocol::Ssh, "host.example");
        c.notes = notes.clone();
        doc.insert(parent, Node::Connection(c)).unwrap();
    }
    doc
}

fn last_folder(f: &Folder) -> Uuid {
    f.children.iter().find_map(|n| if let Node::Folder(sub) = n { Some(last_folder(sub)) } else { None }).unwrap_or(f.id)
}

/// The rule of review round 3: whatever a save accepts, an open accepts.
#[test]
fn a_deep_and_large_library_this_app_saved_opens_again() {
    let dir = tempfile::tempdir().unwrap();
    // Deeper than the levels where a folder gets a reader of its own (20, 40, 60), and large
    // enough that the text below them, counted once per such level, is over 64 MiB.
    for (depth, megabytes) in [(41, 40), (61, 24)] {
        let doc = large_library(depth, megabytes, 1024 * 1024);
        let path = dir.path().join(format!("library-{depth}.json"));
        let saved = Store::new(&path).save(&doc).unwrap();
        let size = std::fs::metadata(&path).unwrap().len() as usize;
        assert!(size > megabytes * 1024 * 1024 && size < docfile::MAX_BYTES, "{size}");
        assert!(Store::new(&path).load().unwrap() == saved, "the store opens what it saved ({depth} deep, {megabytes} MiB)");
        let file = dir.path().join(format!("Deep-{depth}.bastion"));
        DocumentFile::from_document(saved.clone()).save_as(&file).unwrap();
        assert!(at_same_revision(DocumentFile::open(&file).unwrap().document().unwrap(), &saved), "the document too");
    }
}

#[test]
fn a_library_json_over_64_mib_that_the_store_saved_opens_again() {
    // The store had no size limit before PLUG-03a and has none now: unknown data is capped
    // while it is read, so a large file costs what it always did.
    let dir = tempfile::tempdir().unwrap();
    let doc = large_library(1, 70, 1024 * 1024);
    let path = dir.path().join("library.json");
    let saved = Store::new(&path).save(&doc).unwrap();
    assert!(std::fs::metadata(&path).unwrap().len() as usize > docfile::MAX_BYTES);
    let store = Store::new(&path);
    assert!(store.load().unwrap() == saved);
    // And once more over itself: the save reads the file on disk first.
    let again = store.save(&saved).unwrap();
    assert!(store.load().unwrap() == again);
    assert_eq!(store.recover_latest().unwrap().revision, saved.revision, "its backup reads too");
}

#[test]
fn a_document_over_64_mib_is_not_written() {
    // The document reader refuses a file over `MAX_BYTES`, so the writer must not make one.
    let dir = tempfile::tempdir().unwrap();
    let too_large = |r: Result<(), CoreError>| assert!(matches!(&r, Err(CoreError::Invalid(m)) if m.contains("MB")), "{r:?}");
    let path = dir.path().join("Large.bastion");
    let mut d = DocumentFile::from_document(large_library(1, 70, 1024 * 1024));
    too_large(d.save_as(&path));
    assert!(!path.exists(), "nothing is written");
    assert!(matches!(d.to_bytes(), Err(CoreError::Invalid(m)) if m.contains("MB")));

    // An existing document that grows past the limit keeps its last good file.
    let mut d = DocumentFile::from_document(large_library(1, 2, 1024));
    d.save_as(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let big = Connection::new("big", Protocol::Ssh, "h");
    let big_id = big.id;
    d.document_mut().unwrap().insert(None, Node::Connection(big)).unwrap();
    d.document_mut().unwrap().set_notes(big_id, &"n".repeat(docfile::MAX_BYTES)).unwrap();
    too_large(d.save());
    assert!(std::fs::read(&path).unwrap() == before, "the file on disk is untouched");
    // Made smaller again, it saves and opens.
    d.document_mut().unwrap().set_notes(big_id, "small").unwrap();
    d.save().unwrap();
    assert_eq!(DocumentFile::open(&path).unwrap().document().unwrap().connections().len(), 3);
}

/// `template` with its `"__LARGE__"` replaced by an array of `bytes` bytes of `0,0,0,…`.
fn with_a_large_array(template: &str, bytes: usize) -> Vec<u8> {
    let marker = "\"__LARGE__\"";
    let at = template.find(marker).unwrap();
    let mut out = Vec::with_capacity(template.len() + bytes + 2);
    out.extend_from_slice(template[..at].as_bytes());
    out.push(b'[');
    out.extend(std::iter::repeat_n(*b"0,", bytes / 2).flatten());
    out.extend_from_slice(b"0]");
    out.extend_from_slice(template[at + marker.len()..].as_bytes());
    out
}

#[test]
fn a_large_unknown_value_is_refused_while_it_is_read() {
    // The reviewer's case: 60 MiB of library.json holding one unknown array on an entry. It is
    // refused at the cap for one item, long before the array is built (peak memory is in the
    // evidence). Written the way Bastion writes it (`kind` first), and with sorted keys.
    let as_written = LIBRARY.replacen(r#""notes": "kept","#, r#""notes": "kept", "large": "__LARGE__","#, 1);
    let sorted = String::from_utf8(with_plugin_field(json!("__LARGE__"))).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    for (template, why) in [(as_written, "more than this app can keep"), (sorted, "")] {
        let bytes = with_a_large_array(&template, 60 * 1024 * 1024);
        std::fs::write(&path, &bytes).unwrap();
        for e in [Store::new(&path).load().unwrap_err(), DocumentFile::parse(&bytes).unwrap_err()] {
            assert!(matches!(&e, CoreError::Invalid(m) if m.contains(why)), "{e}");
        }
    }
}

fn password(v: &mut Vault, name: &str) -> Uuid {
    v.add(Credential { id: Uuid::new_v4(), name: name.into(), folder: None, scope: None, owner: None, kind: CredentialKind::Password { username: name.into(), password: Secret::new("typed-for-test") } })
}

#[test]
fn an_unknown_entry_has_no_logins_and_offers_none_to_its_host() {
    let mut vault = Vault::default();
    let cred = password(&mut vault, "app");
    let mut v = library_value();
    v.pointer_mut("/root/children/0/children/0/settings").unwrap()["credential_id"] = json!(cred);
    let mut doc: Document = serde_json::from_value(v).unwrap();
    // A known entry on the same host as the unknown one.
    let rdp = Connection::new("orders-rdp", Protocol::Rdp, "db.lab.example");
    let rdp_id = rdp.id;
    doc.insert(None, Node::Connection(rdp)).unwrap();

    for purpose in [LoginPurpose::Any, LoginPurpose::Password] {
        let e = login_candidates(&doc, &vault, id(UNKNOWN_ID), purpose).unwrap_err();
        assert!(matches!(&e, CoreError::Invalid(m) if m == NEEDS_NEWER), "{e}");
        assert!(matches!(may_use(&doc, &vault, id(UNKNOWN_ID), cred, purpose), Err(CoreError::Invalid(m)) if m == NEEDS_NEWER));
        assert!(login_candidates(&doc, &vault, rdp_id, purpose).unwrap().is_empty(), "an unknown entry offers no same-host login");
        assert!(!may_use(&doc, &vault, rdp_id, cred, purpose).unwrap());
    }
}

#[test]
fn duplicating_a_folder_leaves_unknown_entries_out_of_the_copy() {
    let mut doc = loaded();
    let copy = doc.duplicate_folder(id(FOLDER_ID)).unwrap();
    let copy = doc.folder(copy).unwrap().clone();
    let names: Vec<&str> = copy.children.iter().map(|n| if let Node::Connection(c) = n { c.name.as_str() } else { "folder" }).collect();
    assert_eq!(names, ["web01"], "the entry of an unknown type is not copied");
    assert!(copy.children.iter().all(|n| !matches!(n, Node::Connection(c) if c.protocol == Protocol::Unsupported)));
    // The original is untouched.
    assert_marked(&doc);
    assert_unknown_kept(&serde_json::to_value(&doc).unwrap());
}

#[test]
fn unknown_data_over_the_caps_cannot_be_saved() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = loaded();
    fn unknown_entry(f: &mut Folder) -> Option<&mut Connection> {
        f.children.iter_mut().find_map(|n| match n {
            Node::Connection(c) if c.protocol == Protocol::Unsupported => Some(c),
            Node::Folder(sub) => unknown_entry(sub),
            _ => None,
        })
    }
    unknown_entry(&mut doc.root).unwrap().extra.insert("grown".into(), json!("x".repeat(MAX_UNKNOWN_ENTRY_BYTES + 1)));

    let path = dir.path().join("library.json");
    let e = Store::new(&path).save(&doc).unwrap_err();
    assert!(matches!(&e, CoreError::Invalid(m) if m.contains("more than this app can keep")), "{e}");
    assert!(!path.exists(), "the store writes nothing it would refuse to read");

    let path = dir.path().join("Grown.bastion");
    let e = DocumentFile::from_document(doc).save_as(&path).unwrap_err();
    assert!(matches!(&e, CoreError::Invalid(m) if m.contains("more than this app can keep")), "{e}");
    assert!(!path.exists(), "the document writes nothing it would refuse to read");
}

#[test]
fn a_repeated_unknown_key_is_corrupt_wherever_it_is() {
    let entry = |kind_first: bool, body: &str| {
        let kind = r#""kind":"connection""#;
        let rest = format!(r#""id":"0a000000-0000-4000-8000-000000000009","name":"n","protocol":"ssh","host":"h"{body}"#);
        if kind_first { format!("{{{kind},{rest}}}") } else { format!("{{{rest},{kind}}}") }
    };
    let library = |root_extra: &str, child: &str, doc_extra: &str| {
        format!(r#"{{"schema":1,"id":"0a000000-0000-4000-8000-000000000001","name":"L","revision":0,"root":{{"id":"0a000000-0000-4000-8000-000000000002","name":"Root"{root_extra},"children":[{child}]}}{doc_extra}}}"#)
    };
    let twice = r#","future":1,"future":2"#;
    let cases = [
        ("an entry, kind first", library("", &entry(true, twice), "")),
        ("an entry, kind last", library("", &entry(false, twice), "")),
        ("settings", library("", &entry(true, r#","settings":{"port":22,"future":1,"future":2}"#), "")),
        ("a folder", library(twice, "", "")),
        ("folder defaults", library(r#","defaults":{"future":1,"future":2}"#, "", "")),
        ("the document", library("", "", twice)),
        ("type defaults", library("", "", r#","type_defaults":{"ssh":{"future":1,"future":2}}"#)),
        ("unknown type defaults", library("", "", r#","type_defaults":{"postgresql":{"a":1},"postgresql":{"a":2}}"#)),
        ("inside an unknown value", library("", &entry(true, r#","future":{"a":1,"a":2}"#), "")),
    ];
    for (place, text) in &cases {
        assert_corrupt(text.as_bytes(), &format!("a repeated unknown key in {place}"));
        // The same file with the key written once loads.
        let once = text.replace(r#","future":2"#, "").replace(r#","a":2"#, "").replace(r#","postgresql":{"a":2}"#, "");
        assert!(once != *text && DocumentFile::parse(once.as_bytes()).is_ok(), "{place}: {once}");
    }
    // In the contents of a document file.
    let mut v = document_value(VERSION);
    let text = serde_json::to_string(&v).unwrap().replacen(r#""contents":{"#, r#""contents":{"future_contents":0,"#, 1);
    assert_corrupt(text.as_bytes(), "a repeated unknown key in the contents");
    v["contents"]["other"] = json!(1);
    assert!(DocumentFile::parse(&serde_json::to_vec(&v).unwrap()).is_ok());
}

#[test]
fn a_type_name_outside_the_plain_character_set_is_refused() {
    // "SSH" is not the known type `ssh`, and Native Windows compares type names ignoring case.
    for name in ["SSH", "Ssh", "PostgreSQL", "my type", "plugin:x", "caf\u{e9}"] {
        let mut v = library_value();
        *v.pointer_mut("/root/children/0/children/0/protocol").unwrap() = json!(name);
        assert_refused_over_cap(&serde_json::to_vec(&v).unwrap());
        let mut v = library_value();
        v["type_defaults"][name] = json!({ "port": 1 });
        assert_refused_over_cap(&serde_json::to_vec(&v).unwrap());
    }
    // What a plugin type id looks like (spec section 6) is kept.
    for name in ["postgresql", "org.bastion.postgresql/table-1_x", "a"] {
        let mut v = library_value();
        *v.pointer_mut("/root/children/0/children/0/protocol").unwrap() = json!(name);
        let doc = DocumentFile::parse(&serde_json::to_vec(&v).unwrap()).unwrap().document().unwrap().clone();
        assert_eq!(find(&doc, id(UNKNOWN_ID)).protocol_name(), name);
    }
}

#[test]
fn a_probe_request_for_an_unknown_type_gets_the_fixed_text() {
    for name in ["postgresql", "org.bastion.postgresql/table", "unsupported", ""] {
        let e = Protocol::for_request(name).unwrap_err();
        assert!(matches!(&e, CoreError::Invalid(m) if m == NEEDS_NEWER), "{name}: {e}");
    }
    assert_eq!((Protocol::for_request("ssh").unwrap(), Protocol::for_request("RDP").unwrap()), (Protocol::Ssh, Protocol::Rdp));
}

/// What the JSON reader's own 128-level limit used to decide: a library at the folder limit
/// with a full entry at the very bottom saves and opens again, on both roads.
#[test]
fn a_library_at_the_folder_limit_with_entries_at_the_bottom_saves_and_loads() {
    let dir = tempfile::tempdir().unwrap();
    let mut doc = Document::new("deep");
    let mut parent = None;
    for i in 0..MAX_FOLDER_DEPTH {
        let f = empty_folder(&format!("f{i}"));
        let id = f.id;
        doc.insert(parent, Node::Folder(f)).unwrap();
        // An entry at every level, each with unknown data nested as deep as is kept.
        let mut deep = json!("bottom");
        for _ in 0..MAX_UNKNOWN_DEPTH {
            deep = json!({ "in": [deep] }).get("in").unwrap().clone();
        }
        let mut entry: Value = serde_json::to_value(Connection::new(format!("c{i}"), Protocol::Ssh, "h")).unwrap();
        entry["settings"] = json!({ "port": 22, "logins": [Uuid::from_u128(7)], "future": { "a": [1] } });
        entry["future"] = deep;
        doc.insert(Some(id), Node::Connection(serde_json::from_value(entry).unwrap())).unwrap();
        parent = Some(id);
    }
    let path = dir.path().join("library.json");
    let saved = Store::new(&path).save(&doc).unwrap();
    let from_small_stack = |bytes: Vec<u8>| std::thread::Builder::new().stack_size(SMALL_STACK).spawn(move || DocumentFile::parse(&bytes).map(|d| d.document().unwrap().clone())).unwrap().join().unwrap();
    assert!(Store::new(&path).load().unwrap() == saved, "the store reads what it wrote");
    assert!(from_small_stack(std::fs::read(&path).unwrap()).unwrap() == saved, "the document reader too");
    // The same library with sorted keys (`kind` never first).
    let sorted = serde_json::to_vec(&serde_json::to_value(&saved).unwrap()).unwrap();
    assert!(from_small_stack(sorted).unwrap() == saved, "and with kind not first");
    // And as a document file, and through export and import (which drops the unknown data).
    let file = dir.path().join("Deep.bastion");
    DocumentFile::from_document(saved.clone()).save_as(&file).unwrap();
    assert!(at_same_revision(DocumentFile::open(&file).unwrap().document().unwrap(), &saved));
    let exported = export::export(&saved, &Selection::All).unwrap();
    let imported = std::thread::Builder::new().stack_size(SMALL_STACK).spawn(move || export::import(&exported)).unwrap().join().unwrap().unwrap();
    assert_eq!((folder_depth(&imported.root), imported.connections().len()), (MAX_FOLDER_DEPTH, MAX_FOLDER_DEPTH));
}

fn at_same_revision(a: &Document, b: &Document) -> bool {
    Document { revision: 0, ..a.clone() } == Document { revision: 0, ..b.clone() }
}

#[test]
fn an_export_nested_past_the_limit_is_refused_on_a_small_stack() {
    for kind_first in [true, false] {
        let library = String::from_utf8(nested_library(MAX_FOLDER_DEPTH + 1, kind_first)).unwrap();
        let bytes = format!(r#"{{"format":"bastion-export","version":{},"document":{library}}}"#, export::VERSION).into_bytes();
        let e = std::thread::Builder::new().stack_size(SMALL_STACK).spawn(move || export::import(&bytes)).unwrap().join().unwrap().unwrap_err();
        assert!(matches!(&e, CoreError::Invalid(m) if m.contains("nested")), "{e}");
    }
}

/// By hand: `P_DEPTH=62 P_FIRST=0 P_STACK=512 cargo test --release --test plug03a_tolerant_tests
/// measure_stack -- --ignored --nocapture` reads `P_DEPTH` nested folders (`kind` first when
/// `P_FIRST=1`) straight on a thread with `P_STACK` KiB, without the reader's own thread. It
/// aborts when that is too little. The numbers are in the evidence file.
#[test]
#[ignore = "run by hand; aborts when the stack is too small"]
fn measure_stack() {
    let get = |k: &str| std::env::var(k).unwrap().parse::<usize>().unwrap();
    let (depth, first, stack) = (get("P_DEPTH"), get("P_FIRST") == 1, get("P_STACK") * 1024);
    let bytes = nested_library(depth, first);
    let ok = std::thread::Builder::new().stack_size(stack).spawn(move || serde_json::from_slice::<Document>(&bytes).is_ok()).unwrap().join().unwrap();
    println!("PROBE ok={ok}");
}

/// By hand, under `/usr/bin/time -l`: reads the library at `P_FILE` once and prints how the
/// read ended. Used for the peak memory of a refused file in the evidence.
#[test]
#[ignore = "run by hand under /usr/bin/time -l"]
fn measure_one_load() {
    let path = std::env::var("P_FILE").unwrap();
    println!("LOAD {:?}", Store::new(&path).load().map(|d| d.revision).map_err(|e| message(e).chars().take(90).collect::<String>()));
}

#[test]
#[ignore = "run by hand; writes the 60 MiB file for measure_one_load to P_FILE"]
fn write_a_large_unknown_value() {
    let as_written = LIBRARY.replacen(r#""notes": "kept","#, r#""notes": "kept", "large": "__LARGE__","#, 1);
    std::fs::write(std::env::var("P_FILE").unwrap(), with_a_large_array(&as_written, 60 * 1024 * 1024)).unwrap();
}

/// Names and sizes of the files in a backups folder.
fn backup_set(dir: &Path) -> Vec<(String, u64)> {
    let mut set: Vec<(String, u64)> = match std::fs::read_dir(dir) {
        Ok(entries) => entries.map(|e| e.unwrap()).map(|e| (e.file_name().to_string_lossy().into_owned(), e.metadata().unwrap().len())).collect(),
        Err(_) => vec![],
    };
    set.sort();
    set
}

/// Review round 4: a save that is refused leaves the backups alone. Twenty are kept, so
/// refused saves that each wrote one would push every real backup out.
#[test]
fn a_refused_save_writes_no_backup() {
    let dir = tempfile::tempdir().unwrap();
    let more_than_are_kept = 21;

    // A document with three real backups.
    let path = dir.path().join("Work.bastion");
    let mut d = DocumentFile::from_document(large_library(1, 2, 1024));
    d.save_as(&path).unwrap();
    let entry = d.document().unwrap().connections()[0].connection.id;
    for i in 0..3 {
        d.document_mut().unwrap().set_notes(entry, &format!("edit {i}")).unwrap();
        d.save().unwrap();
    }
    let backups = docfile::backups_dir(&path);
    let (before, file) = (backup_set(&backups), std::fs::read(&path).unwrap());
    assert_eq!(before.len(), 3);

    // Refused for size, for unknown data over the cap, and for both at once.
    let refusals: [(&str, Box<dyn Fn(&mut Document)>); 2] = [
        ("MB", Box::new(move |doc| doc.set_notes(entry, &"n".repeat(docfile::MAX_BYTES)).unwrap())),
        ("more than this app can keep", Box::new(|doc| drop(doc.extra.insert("grown".into(), json!("x".repeat(MAX_UNKNOWN_ENTRY_BYTES + 1)))))),
    ];
    for (why, grow) in &refusals {
        let mut refused = DocumentFile::open(&path).unwrap();
        grow(refused.document_mut().unwrap());
        for _ in 0..more_than_are_kept {
            let e = refused.save().unwrap_err();
            assert!(matches!(&e, CoreError::Invalid(m) if m.contains(why)), "{e}");
        }
        assert!(refused.is_dirty(), "the changes are still unsaved");
        assert_eq!(backup_set(&backups), before, "refused ({why}): the backups are untouched");
        assert!(std::fs::read(&path).unwrap() == file, "refused ({why}): the file is untouched");
    }
    // The next real save still makes its backup.
    d.document_mut().unwrap().set_notes(entry, "after").unwrap();
    d.save().unwrap();
    assert_eq!(backup_set(&backups).len(), 4);

    // The store: the same for its refusals.
    let path = dir.path().join("library.json");
    let store = Store::new(&path);
    let mut saved = store.save(&loaded()).unwrap();
    for _ in 0..3 {
        saved = store.save(&saved).unwrap();
    }
    let (before, file) = (backup_set(&store.backups_dir()), std::fs::read(&path).unwrap());
    assert_eq!(before.len(), 3);
    let mut grown = saved.clone();
    grown.extra.insert("grown".into(), json!("x".repeat(MAX_UNKNOWN_ENTRY_BYTES + 1)));
    let mut lost_its_type = saved.clone();
    fn forget_type(f: &mut Folder) {
        for n in &mut f.children {
            match n {
                Node::Folder(sub) => forget_type(sub),
                Node::Connection(c) => c.unknown_protocol = None,
            }
        }
    }
    forget_type(&mut lost_its_type.root);
    for refused in [&grown, &lost_its_type] {
        for _ in 0..more_than_are_kept {
            assert!(matches!(store.save(refused), Err(CoreError::Invalid(_))));
        }
        assert_eq!(backup_set(&store.backups_dir()), before, "the store's backups are untouched");
        assert!(std::fs::read(&path).unwrap() == file, "the store's file is untouched");
    }
}
