//! PLUG-03b: plugin connection types, their fields, and raising a document to `VERSION + 1`.
use super::*;
use crate::docfile::{DocumentFile, MAX_READ_VERSION, VERSION};
use crate::model::Node;
use crate::plugin::parse_manifest;

const PLUGIN: &str = "org.example.pg";
const TYPE: &str = "org.example.pg/postgres";

fn manifest(name: &str) -> Manifest {
    let text = format!(
        r#"schema = 1
id = "{PLUGIN}"
name = "{name}"
version = "1.0.0"
api = "1.0"
publisher = "Example"
description = "Query databases."
license = "Apache-2.0"
repository = "https://example.org/pg"

[[connection_types]]
id = "postgres"
name = "PostgreSQL"
default_port = 5432

[[connection_types.fields]]
key = "database"
label = "Database"
kind = "text"

[[connection_types.fields]]
key = "rows"
label = "Row limit"
kind = "number"

[[connection_types.fields]]
key = "read-only"
label = "Read only"
kind = "toggle"
"#
    );
    parse_manifest(text.as_bytes()).unwrap()
}

fn registry() -> Registry {
    let mut r = Registry::new();
    r.add(&manifest("PG Tools"), Tier::External);
    r
}

fn entry(r: &Registry) -> Connection {
    new_entry("orders", "db.lab.example", r.get(TYPE).unwrap())
}

#[test]
fn a_manifest_registers_namespaced_types_and_replaces_its_old_version() {
    let mut r = registry();
    let ty = r.get(TYPE).unwrap();
    assert_eq!((ty.plugin_id.as_str(), ty.name.as_str(), ty.default_port, ty.fields.len()), (PLUGIN, "PostgreSQL", Some(5432), 3));
    assert_eq!(ty.group_heading(), "Fields from the plugin \"PG Tools\" (External)");
    r.add(&manifest("PG Tools 2"), Tier::Official);
    assert_eq!(r.types().count(), 1);
    assert_eq!(r.get(TYPE).unwrap().group_heading(), "Fields from the plugin \"PG Tools 2\" (Official)");
    r.remove(PLUGIN);
    assert!(r.is_empty());
}

#[test]
fn type_names_are_split_only_when_well_formed() {
    assert_eq!(split_type_name(TYPE), Some((PLUGIN, "postgres")));
    for bad in ["postgres", "pg/postgres", "org.example.pg/", "/postgres", "org.example.pg/Postgres", "org.example.pg/a/b", "ORG.example.pg/postgres"] {
        assert_eq!(split_type_name(bad), None, "{bad}");
    }
}

#[test]
fn availability_tells_builtin_plugin_missing_plugin_and_unknown_apart() {
    let r = registry();
    let ssh = Connection::new("web", Protocol::Ssh, "h");
    assert_eq!(availability(&ssh, &r), Availability::Builtin);
    let pg = entry(&r);
    assert!(matches!(availability(&pg, &r), Availability::Plugin(t) if t.id == TYPE));
    assert_eq!(availability(&pg, &r).unavailable(), None);
    let empty = Registry::new();
    assert_eq!(availability(&pg, &empty), Availability::NeedsPlugin { plugin_id: PLUGIN });
    assert_eq!(availability(&pg, &empty).unavailable(), Some(NEEDS_NEWER));
    let mut other = Connection::new("x", Protocol::Unsupported, "h");
    other.unknown_protocol = Some("postgresql".into());
    assert_eq!(availability(&other, &r), Availability::NeedsNewer);
    other.unknown_protocol = None;
    assert_eq!(availability(&other, &r), Availability::NeedsNewer);
}

#[test]
fn a_plugin_entry_never_resolves_for_a_builtin_connect() {
    let r = registry();
    let mut doc = Document::new("Lib");
    let c = entry(&r);
    let id = c.id;
    assert_eq!(c.settings.port, Some(5432));
    assert_eq!(c.unavailable(), Some(NEEDS_NEWER), "the built-in marker still says the core cannot connect to it");
    doc.insert(None, Node::Connection(c)).unwrap();
    assert!(matches!(doc.resolve(id), Err(CoreError::Invalid(m)) if m == NEEDS_NEWER));
    let (found, ty) = plugin_entry(&doc, id, &r).unwrap();
    assert_eq!((found.id, ty.id.as_str()), (id, TYPE));
    assert!(matches!(plugin_entry(&doc, id, &Registry::new()), Err(CoreError::Invalid(m)) if m == NEEDS_NEWER));
    assert!(matches!(plugin_entry(&doc, Uuid::new_v4(), &r), Err(CoreError::NotFound(_))));
    let ssh = Connection::new("web", Protocol::Ssh, "h");
    let ssh_id = ssh.id;
    doc.insert(None, Node::Connection(ssh)).unwrap();
    assert!(matches!(plugin_entry(&doc, ssh_id, &r), Err(CoreError::NotFound(_))));
}

#[test]
fn fields_are_set_typed_shown_and_cleared() {
    let r = registry();
    let ty = r.get(TYPE).unwrap();
    let mut c = entry(&r);
    let g = field_group(&c, ty).unwrap();
    assert_eq!(g.heading, "Fields from the plugin \"PG Tools\" (External)");
    assert_eq!(g.fields.iter().map(|f| (f.key.as_str(), f.kind, f.value.clone())).collect::<Vec<_>>(), vec![("database", PropKind::Text, None), ("rows", PropKind::Number, None), ("read-only", PropKind::Toggle, None)]);

    assert_eq!(set_field(&mut c, ty, "database", Some("orders"), None, false).unwrap(), FieldSave::Saved);
    assert_eq!(set_field(&mut c, ty, "rows", Some(" 9007199254740991 "), None, false).unwrap(), FieldSave::Saved);
    assert_eq!(set_field(&mut c, ty, "read-only", Some("true"), None, false).unwrap(), FieldSave::Saved);
    assert_eq!(c.extra[FIELDS_KEY], serde_json::json!({ "database": "orders", "rows": 9007199254740991i64, "read-only": true }));
    let values: Vec<_> = field_group(&c, ty).unwrap().fields.into_iter().map(|f| f.value).collect();
    assert_eq!(values, vec![Some("orders".into()), Some("9007199254740991".into()), Some("true".into())]);

    for k in ["database", "rows", "read-only"] {
        set_field(&mut c, ty, k, None, None, false).unwrap();
    }
    assert!(!c.extra.contains_key(FIELDS_KEY), "an empty group is not stored");
    assert_eq!(set_field(&mut c, ty, "database", Some(""), None, false).unwrap(), FieldSave::Saved);
    assert!(!c.extra.contains_key(FIELDS_KEY));
}

#[test]
fn bad_field_values_are_refused_and_change_nothing() {
    let r = registry();
    let ty = r.get(TYPE).unwrap();
    let mut c = entry(&r);
    set_field(&mut c, ty, "database", Some("orders"), None, false).unwrap();
    let before = c.clone();
    let long = "x".repeat(MAX_TEXT_FIELD_CHARS + 1);
    for (key, value) in [
        ("rows", "9007199254740992"),
        ("rows", "-9007199254740992"),
        ("rows", "1.5"),
        ("rows", "ten"),
        ("read-only", "yes"),
        ("read-only", "True"),
        ("database", "a\u{0}b"),
        ("database", "a\u{202E}b"),
        ("database", "line\nbreak"),
        ("database", long.as_str()),
        ("password", "x"),
    ] {
        assert!(matches!(set_field(&mut c, ty, key, Some(value), None, false), Err(CoreError::Invalid(_))), "{key}={value:?}");
    }
    assert_eq!(c, before);
    assert_eq!(set_field(&mut c, ty, "database", Some(&"y".repeat(MAX_TEXT_FIELD_CHARS)), None, false).unwrap(), FieldSave::Saved);
    assert_eq!(set_field(&mut c, ty, "rows", Some("-9007199254740991"), None, false).unwrap(), FieldSave::Saved);
}

#[test]
fn a_value_holding_the_saved_password_needs_confirming() {
    let r = registry();
    let ty = r.get(TYPE).unwrap();
    let mut c = entry(&r);
    let pw = "hunter2-long";
    assert_eq!(set_field(&mut c, ty, "database", Some("db-hunter2-long"), Some(pw), false).unwrap(), FieldSave::ConfirmPassword(PASSWORD_MATCH_WARNING));
    assert!(!c.extra.contains_key(FIELDS_KEY), "nothing saved before the user confirms");
    assert_eq!(set_field(&mut c, ty, "database", Some("db-hunter2-long"), Some(pw), true).unwrap(), FieldSave::Saved);
    assert_eq!(c.extra[FIELDS_KEY]["database"], "db-hunter2-long");
    // Clearing, other values, and an empty saved password never ask.
    assert_eq!(set_field(&mut c, ty, "database", Some("orders"), Some(pw), false).unwrap(), FieldSave::Saved);
    assert_eq!(set_field(&mut c, ty, "database", Some("orders"), Some(""), false).unwrap(), FieldSave::Saved);
    assert_eq!(set_field(&mut c, ty, "database", None, Some(pw), false).unwrap(), FieldSave::Saved);
    // A number field holding a numeric password asks too.
    assert_eq!(set_field(&mut c, ty, "rows", Some("123456"), Some("123456"), false).unwrap(), FieldSave::ConfirmPassword(PASSWORD_MATCH_WARNING));
}

#[test]
fn stored_values_of_another_kind_and_undeclared_keys_are_kept() {
    let r = registry();
    let ty = r.get(TYPE).unwrap();
    let mut c = entry(&r);
    c.extra.insert(FIELDS_KEY.into(), serde_json::json!({ "database": 5, "rows": "many", "sslmode": "require", "read-only": 1e300 }));
    let values: Vec<_> = field_group(&c, ty).unwrap().fields.into_iter().map(|f| f.value).collect();
    assert_eq!(values, vec![None, None, None]);
    set_field(&mut c, ty, "database", Some("orders"), None, false).unwrap();
    assert_eq!(c.extra[FIELDS_KEY], serde_json::json!({ "database": "orders", "rows": "many", "sslmode": "require", "read-only": 1e300 }));

    let mut odd = entry(&r);
    odd.extra.insert(FIELDS_KEY.into(), serde_json::json!(["not", "an", "object"]));
    let before = odd.clone();
    assert!(set_field(&mut odd, ty, "database", Some("x"), None, false).is_err());
    assert_eq!(odd, before);
}

#[test]
fn fields_of_another_type_are_refused() {
    let r = registry();
    let ty = r.get(TYPE).unwrap();
    let mut ssh = Connection::new("web", Protocol::Ssh, "h");
    assert!(field_group(&ssh, ty).is_err());
    assert!(set_field(&mut ssh, ty, "database", Some("x"), None, false).is_err());
    assert!(ssh.extra.is_empty());
}

fn library_with_plugin_entry() -> (Document, Uuid) {
    let r = registry();
    let ty = r.get(TYPE).unwrap();
    let mut c = entry(&r);
    set_field(&mut c, ty, "database", Some("orders"), None, false).unwrap();
    set_field(&mut c, ty, "rows", Some("500"), None, false).unwrap();
    let id = c.id;
    let mut doc = Document::new("Lib");
    doc.insert(None, Node::Connection(Connection::new("web", Protocol::Ssh, "web01"))).unwrap();
    doc.insert(None, Node::Connection(c)).unwrap();
    (doc, id)
}

fn file_version(path: &std::path::Path) -> u64 {
    let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    v["version"].as_u64().unwrap()
}

fn assert_plugin_entry_kept(d: &DocumentFile, id: Uuid) {
    let r = registry();
    let (c, ty) = plugin_entry(d.document().unwrap(), id, &r).unwrap();
    let values: Vec<_> = field_group(c, ty).unwrap().fields.into_iter().map(|f| f.value).collect();
    assert_eq!(values, vec![Some("orders".into()), Some("500".into()), None]);
    assert_eq!(c.settings.port, Some(5432));
}

#[test]
fn a_plain_document_stays_version_and_one_with_plugin_data_is_raised_on_save_only() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Plain.bastion");
    let mut d = DocumentFile::from_document(Document::new("Lib"));
    d.save_as(&path).unwrap();
    assert_eq!(file_version(&path), VERSION as u64);

    // Adding a plugin entry does not touch the file until a save; the save raises it.
    let (doc, id) = library_with_plugin_entry();
    d.set_document(doc).unwrap();
    assert_eq!(file_version(&path), VERSION as u64, "raising happens only on a save");
    assert_eq!(d.format_version(), VERSION);
    d.save().unwrap();
    assert_eq!(file_version(&path), MAX_READ_VERSION as u64);
    assert_eq!(d.format_version(), MAX_READ_VERSION);
    let back = DocumentFile::open(&path).unwrap();
    assert_eq!(back.loaded_version(), MAX_READ_VERSION);
    assert_plugin_entry_kept(&back, id);

    // Opening never raises: a VERSION file read and not saved stays VERSION on disk.
    let other = dir.path().join("Other.bastion");
    DocumentFile::from_document(Document::new("Lib")).save_as(&other).unwrap();
    let opened = DocumentFile::open(&other).unwrap();
    assert_eq!((opened.loaded_version(), file_version(&other)), (VERSION, VERSION as u64));
}

#[test]
fn a_protected_document_is_raised_and_resealed_in_one_step() {
    const PW: &str = "correct horse battery";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Team.bastion");
    let mut d = DocumentFile::from_document(Document::new("Lib"));
    d.set_password(Some(PW)).unwrap();
    d.save_as(&path).unwrap();
    assert_eq!(file_version(&path), VERSION as u64);

    let mut d = DocumentFile::open(&path).unwrap();
    d.unlock(PW).unwrap();
    let key = d.key().unwrap();
    let (doc, id) = library_with_plugin_entry();
    d.set_document(doc).unwrap();
    d.save().unwrap();
    assert_eq!(file_version(&path), MAX_READ_VERSION as u64);
    assert!(!std::fs::read_to_string(&path).unwrap().contains(TYPE), "plugin data stays in the sealed contents");

    // The contents are bound to the new version: password, key and a re-lock all open them.
    assert!(d.lock());
    d.unlock(PW).unwrap();
    assert_plugin_entry_kept(&d, id);
    let mut by_pw = DocumentFile::open(&path).unwrap();
    by_pw.unlock(PW).unwrap();
    assert_plugin_entry_kept(&by_pw, id);
    let mut by_key = DocumentFile::open(&path).unwrap();
    by_key.unlock_with_key(key).unwrap();
    assert_plugin_entry_kept(&by_key, id);

    // Writing the old version back into the raised file fails authentication.
    let mut v: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    v["version"] = Value::from(VERSION);
    std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
    let mut forged = DocumentFile::open(&path).unwrap();
    assert!(forged.unlock(PW).is_err());
}

#[test]
fn a_raised_document_locked_with_unsaved_changes_still_opens() {
    const PW: &str = "correct horse battery";
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Team.bastion");
    let mut d = DocumentFile::from_document(Document::new("Lib"));
    d.set_password(Some(PW)).unwrap();
    d.save_as(&path).unwrap();
    let (doc, id) = library_with_plugin_entry();
    d.set_document(doc).unwrap();
    // Locked before the save: sealed in memory under the version it has now.
    assert!(d.lock_keeping_changes().unwrap());
    d.unlock(PW).unwrap();
    assert_plugin_entry_kept(&d, id);
    d.save().unwrap();
    assert_eq!(file_version(&path), MAX_READ_VERSION as u64);
    let mut back = DocumentFile::open(&path).unwrap();
    back.unlock(PW).unwrap();
    assert_plugin_entry_kept(&back, id);
}

#[test]
fn a_device_keyed_document_is_raised_and_resealed_in_one_step() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Device.bastion");
    let mut d = DocumentFile::new_device(Document::new("Lib"));
    let key = d.key().unwrap();
    d.save_as(&path).unwrap();
    assert_eq!(file_version(&path), VERSION as u64);
    let (doc, id) = library_with_plugin_entry();
    d.set_document(doc).unwrap();
    d.save().unwrap();
    assert_eq!(file_version(&path), MAX_READ_VERSION as u64);
    let mut back = DocumentFile::open(&path).unwrap();
    back.unlock_with_key(key).unwrap();
    assert_plugin_entry_kept(&back, id);
}

#[test]
fn holds_unknown_sees_every_kind_of_kept_data() {
    let empty = crate::unknown::Extra::new();
    let mut doc = Document::new("Lib");
    doc.insert(None, Node::Connection(Connection::new("web", Protocol::Ssh, "h"))).unwrap();
    assert!(!crate::unknown::holds_unknown(&doc, &empty));
    let (with_entry, _) = library_with_plugin_entry();
    assert!(crate::unknown::holds_unknown(&with_entry, &empty));
    let mut outside = crate::unknown::Extra::new();
    outside.insert("future".into(), Value::Bool(true));
    assert!(crate::unknown::holds_unknown(&doc, &outside));
    let mut d2 = doc.clone();
    d2.extra.insert("future".into(), Value::Bool(true));
    assert!(crate::unknown::holds_unknown(&d2, &empty));
    let mut d3 = doc.clone();
    if let Some(Node::Connection(c)) = d3.root.children.first_mut() {
        c.settings.extra.insert("future".into(), Value::Bool(true));
    }
    assert!(crate::unknown::holds_unknown(&d3, &empty));
}

#[test]
fn i64_min_is_refused_when_typed_and_hidden_when_stored() {
    let r = registry();
    let ty = r.get(TYPE).unwrap();
    let mut c = entry(&r);
    for typed in [i64::MIN.to_string(), i64::MAX.to_string(), (i64::MIN + 1).to_string()] {
        assert!(matches!(set_field(&mut c, ty, "rows", Some(&typed), None, false), Err(CoreError::Invalid(_))), "{typed}");
    }
    assert!(!c.extra.contains_key(FIELDS_KEY));
    c.extra.insert(FIELDS_KEY.into(), serde_json::json!({ "rows": i64::MIN }));
    assert_eq!(field_group(&c, ty).unwrap().fields[1].value, None);
    c.extra.insert(FIELDS_KEY.into(), serde_json::json!({ "rows": i64::MAX }));
    assert_eq!(field_group(&c, ty).unwrap().fields[1].value, None);
    // A crafted library holding it loads and shows nothing, in a debug build too.
    let doc: Document = serde_json::from_value({
        let mut v = serde_json::to_value(&library_with_plugin_entry().0).unwrap();
        v["root"]["children"][1]["plugin_fields"]["rows"] = serde_json::json!(i64::MIN);
        v
    })
    .unwrap();
    let id = match &doc.root.children[1] { Node::Connection(c) => c.id, _ => unreachable!() };
    let (c, ty) = plugin_entry(&doc, id, &r).unwrap();
    assert_eq!(field_group(c, ty).unwrap().fields[1].value, None);
}

#[test]
fn the_cores_type_field_can_never_be_saved() {
    // `:type` is the core's own entry-info field (design D): no manifest key can start with `:`,
    // so saving one is refused and nothing is stored.
    let r = registry();
    let ty = r.get(TYPE).unwrap();
    let mut c = entry(&r);
    for key in [":type", ":", ":database"] {
        assert!(set_field(&mut c, ty, key, Some("esxi"), None, false).is_err(), "{key}");
    }
    assert!(c.extra.get(FIELDS_KEY).is_none(), "nothing was stored");
}

// ---- plugin change flags are turned off on everything that comes from outside (#1439, HIGH 2) ----

fn flagged(name: &str) -> Connection {
    let mut c = Connection::new(name, Protocol::Ssh, "docker1.lab");
    c.extra.insert(
        FIELDS_KEY.to_string(),
        serde_json::json!({ "allow-changes": "true", "snapshot-before-connect": "true", "note": "kept" }),
    );
    c
}

fn flags_of(c: &Connection) -> Option<serde_json::Value> {
    c.extra.get(FIELDS_KEY).cloned()
}

/// No change flag is left on the entry, whatever else survived the path.
fn no_change_flag(c: &Connection) -> bool {
    flags_of(c).is_none_or(|v| CHANGE_FLAGS.iter().all(|k| v.get(*k).is_none()))
}

fn find<'a>(f: &'a crate::model::Folder, name: &str) -> Option<&'a Connection> {
    f.children.iter().find_map(|n| match n {
        Node::Connection(c) if c.name == name => Some(c),
        Node::Folder(sub) => find(sub, name),
        _ => None,
    })
}

#[test]
fn clearing_removes_only_the_change_flags() {
    let mut c = flagged("a");
    clear_change_flags(&mut c);
    assert_eq!(flags_of(&c), Some(serde_json::json!({ "note": "kept" })));
    let mut only = Connection::new("b", Protocol::Ssh, "h");
    only.extra.insert(FIELDS_KEY.to_string(), serde_json::json!({ "allow-changes": "true" }));
    clear_change_flags(&mut only);
    assert_eq!(flags_of(&only), None, "an empty map is removed");
}

#[test]
fn a_file_import_turns_allow_changes_off() {
    let mut doc = Document::new("Library");
    let folder = crate::import::into_folder("Imported x", vec![crate::import::Found { path: vec![], connection: flagged("imported") }]);
    crate::import::merge_import(&mut doc, folder);
    assert_eq!(flags_of(find(&doc.root, "imported").unwrap()), Some(serde_json::json!({ "note": "kept" })));
}

#[test]
fn a_bastion_export_import_turns_allow_changes_off() {
    let mut doc = Document::new("Sender");
    doc.insert(None, Node::Connection(Connection::new("exported", Protocol::Ssh, "docker1.lab"))).unwrap();
    let bytes = crate::export::export(&doc, &crate::export::Selection::All).unwrap();
    // The sender's file says Allow changes is on (export never writes it; a hand-made file can).
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let text = v.to_string().replace("\"name\":\"exported\"", "\"name\":\"exported\",\"plugin_fields\":{\"allow-changes\":\"true\"}");
    v = serde_json::from_str(&text).unwrap();
    let got = crate::export::import(v.to_string().as_bytes()).unwrap();
    let c = find(&got.root, "exported").unwrap();
    assert!(no_change_flag(c));
}

#[test]
fn a_document_import_and_a_received_document_turn_allow_changes_off() {
    let mut src = Document::new("Shared");
    src.insert(None, Node::Connection(flagged("shared"))).unwrap();
    let source = DocumentFile::from_document(src.clone());
    let mut target = DocumentFile::from_document(Document::new("Mine"));
    crate::docfile::import_into(&mut target, &source, true).unwrap();
    assert!(no_change_flag(find(&target.document().unwrap().root, "shared").unwrap()), "document import");
    let mut received = DocumentFile::from_document(src);
    received.mark_as_received(false).unwrap();
    assert_eq!(flags_of(find(&received.document().unwrap().root, "shared").unwrap()), Some(serde_json::json!({ "note": "kept" })), "a received document");
}
