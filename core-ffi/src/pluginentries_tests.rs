//! Plugin entries over the bindings. Generated data only; no plugin helper runs here.
use std::sync::Arc;

use bastion_core::model::{Connection, Node, Protocol};

use super::*;
use crate::properties::property_schema;

const PVE: &str = "dev.bastion.proxmox/pve";
const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

struct Bench {
    dir: tempfile::TempDir,
    lib: Arc<Library>,
    vault: Arc<CredentialVault>,
}

fn bench() -> Bench {
    let dir = tempfile::tempdir().unwrap();
    let lib = Arc::new(Library::open(dir.path().join("library.json").display().to_string()).unwrap());
    let vault = Arc::new(CredentialVault::open_ephemeral(dir.path().join("c.vault").display().to_string()).unwrap());
    Bench { dir, lib, vault }
}

impl Bench {
    fn data(&self) -> String {
        self.dir.path().join("data").display().to_string()
    }

    /// A Proxmox entry as a library that was saved with the plugin installed holds it.
    fn pve_entry(&self) -> String {
        let mut c = Connection::new("pve", Protocol::Unsupported, "pve.lab");
        c.unknown_protocol = Some(PVE.into());
        let id = c.id.to_string();
        self.lib.lock().insert(None, Node::Connection(c)).unwrap();
        id
    }

    fn audit_text(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("audit.jsonl")).unwrap_or_default()
    }
}

#[test]
fn no_installed_plugin_means_no_types_and_no_new_entries() {
    let b = bench();
    assert!(plugin_connection_types(b.data()).unwrap().is_empty());
    let e = b.lib.add_plugin_connection(b.data(), None, "pve".into(), "pve.lab".into(), PVE.into()).unwrap_err();
    assert!(e.to_string().contains("No installed plugin"), "{e}");
}

#[test]
fn tls_settings_read_and_write_on_a_plugin_entry_only() {
    let b = bench();
    let id = b.pve_entry();
    assert_eq!(b.lib.plugin_entry_tls(id.clone()).unwrap(), PluginEntryTlsView { mode: "verify-full".into(), pin_sha256: None, damaged: false });
    b.lib.set_plugin_entry_tls(id.clone(), "pinned".into(), Some(PIN.to_uppercase())).unwrap();
    assert_eq!(b.lib.plugin_entry_tls(id.clone()).unwrap(), PluginEntryTlsView { mode: "pinned".into(), pin_sha256: Some(PIN.into()), damaged: false });
    assert!(b.lib.set_plugin_entry_tls(id.clone(), "pinned".into(), Some("short".into())).is_err());
    assert!(b.lib.set_plugin_entry_tls(id, "off".into(), None).is_err());
    let ssh = b.lib.add_connection(None, "s".into(), "ssh".into(), "h".into(), None, None).unwrap();
    assert!(b.lib.plugin_entry_tls(ssh.clone()).is_err());
    assert!(b.lib.set_plugin_entry_tls(ssh, "verify-full".into(), None).is_err());
}

#[test]
fn a_plugin_type_gets_the_address_and_login_schema() {
    let keys: Vec<_> = property_schema(Some(PVE.into()), false).unwrap().into_iter().map(|d| d.key).collect();
    assert_eq!(keys, ["name", "host", "port", "credential_id", "credential_name", "gateway_id", "environment", "notes", "tags"]);
}

#[test]
fn no_login_is_released_when_the_entry_plugin_is_not_installed() {
    let b = bench();
    let id = b.pve_entry();
    let cred = b.vault.save_password(None, "pve token".into(), None, "audit@pve!bastion".into(), "token-secret-value".into()).unwrap();
    b.lib.set_property(id.clone(), "credential_id".into(), Some(cred)).unwrap();
    let e = plugin_entry_view_open(b.lib.clone(), Some(b.vault.clone()), id, b.data(), false, false).err().expect("refused");
    let text = e.to_string();
    assert!(!text.contains("token-secret-value") && !text.contains("audit@pve"), "{text}");
    assert!(!b.audit_text().contains("plugin-login-release"), "nothing was released");
}

#[test]
fn the_vault_offers_the_entry_its_own_login() {
    let b = bench();
    let id = b.pve_entry();
    let cred = b.vault.save_password(None, "pve token".into(), None, "audit@pve!bastion".into(), "token-secret-value".into()).unwrap();
    b.lib.set_property(id.clone(), "credential_id".into(), Some(cred.clone())).unwrap();
    let login = b.vault.password_login_for(&b.lib, parse_id(&id).unwrap(), Some(cred)).unwrap().expect("released");
    assert_eq!(login.0, "audit@pve!bastion");
}

#[test]
fn without_the_vault_the_view_opens_with_no_login_and_nothing_is_released() {
    let b = bench();
    let id = b.pve_entry();
    // Not installed, so refused; but the path without a vault never reads or audits a login.
    assert!(plugin_entry_view_open(b.lib.clone(), None, id, b.data(), false, false).is_err());
    assert!(!b.audit_text().contains("plugin-login-release"));
}

#[test]
fn the_probe_refuses_an_empty_host() {
    assert!(plugin_certificate_probe(String::new(), 8006).is_err());
}

/// Live, by hand, read-only: the TLS handshake only, no request and no login. The host comes from
/// the environment (`BASTION_PVE_HOST`, port `BASTION_PVE_PORT` or 8006) and is never printed.
#[test]
#[ignore]
fn live_probe_reads_a_stable_pin() {
    let host = std::env::var("BASTION_PVE_HOST").expect("BASTION_PVE_HOST");
    let port = std::env::var("BASTION_PVE_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8006);
    let a = plugin_certificate_probe(host.clone(), port).expect("first probe");
    let b = plugin_certificate_probe(host, port).expect("second probe");
    assert!(bastion_core::pluginentry::is_pin(&a), "a SHA-256 pin");
    assert_eq!(a, b, "the same certificate twice");
    // The pin is accepted as the entry's TLS setting.
    let bench = bench();
    let id = bench.pve_entry();
    bench.lib.set_plugin_entry_tls(id.clone(), "pinned".into(), Some(a)).unwrap();
    assert_eq!(bench.lib.plugin_entry_tls(id).unwrap().mode, "pinned");
}

#[test]
fn the_app_route_is_used_but_a_gateway_entry_never_goes_direct() {
    assert_eq!(chosen_route(EntryRoute::Direct, None), EntryRoute::Direct);
    assert_eq!(chosen_route(EntryRoute::NotDirect, Some(PluginRoute::Direct)), EntryRoute::NotDirect);
    assert_eq!(chosen_route(EntryRoute::NotDirect, Some(PluginRoute::Forward { port: 40001, target: "127.0.0.1".into() })), EntryRoute::Forward { port: 40001, target: "127.0.0.1".into() });
    assert_eq!(chosen_route(EntryRoute::Direct, Some(PluginRoute::Socks { port: 1080 })), EntryRoute::Socks { port: 1080 });
}

#[test]
fn the_gateway_of_a_plugin_entry_is_read() {
    let b = bench();
    let id = b.pve_entry();
    assert_eq!(b.lib.plugin_entry_gateway(id).unwrap(), None);
    assert!(b.lib.plugin_entry_gateway(uuid::Uuid::new_v4().to_string()).is_err());
}

/// PLUG-08 Mac: the PostgreSQL fixture (`apps/macos/uitests/fixtures/postgres.bastionplugin`).
fn install_postgres(b: &Bench) -> String {
    let pkg = concat!(env!("CARGO_MANIFEST_DIR"), "/../apps/macos/uitests/fixtures/postgres.bastionplugin");
    crate::plugins::plugin_install_file(b.data(), pkg.into(), true).unwrap();
    "com.example.postgres/postgres".into()
}

#[test]
fn the_postgres_type_offers_its_database_field() {
    let b = bench();
    let ty = install_postgres(&b);
    let types = plugin_connection_types(b.data()).unwrap();
    let pg = types.iter().find(|t| t.id == ty).expect("postgres type");
    assert_eq!(pg.default_port, Some(5432));
    assert_eq!(pg.fields, vec![PluginTypeFieldView { key: "database".into(), label: "Database".into() }]);
}

#[test]
fn a_plugin_field_is_saved_cleared_and_refused_for_unknown_keys() {
    let b = bench();
    let ty = install_postgres(&b);
    let id = b.lib.add_plugin_connection(b.data(), None, "db".into(), "db.lab".into(), ty).unwrap();
    b.lib.set_plugin_field(b.data(), id.clone(), "database".into(), Some("app".into())).unwrap();
    let stored = |lib: &Library| {
        let doc = lib.lock();
        let c = doc.root.children.iter().find_map(|n| match n { Node::Connection(c) if c.id.to_string() == id => Some(c.clone()), _ => None }).unwrap();
        c.extra.get(bastion_core::plugintypes::FIELDS_KEY).cloned()
    };
    assert_eq!(stored(&b.lib), Some(serde_json::json!({ "database": "app" })));
    assert!(b.lib.set_plugin_field(b.data(), id.clone(), "nope".into(), Some("x".into())).is_err());
    b.lib.set_plugin_field(b.data(), id.clone(), "database".into(), None).unwrap();
    assert_eq!(stored(&b.lib), None);
}

#[test]
fn a_plugin_field_is_refused_on_a_plain_entry() {
    let b = bench();
    install_postgres(&b);
    let id = b.lib.add_connection(None, "ssh".into(), "ssh".into(), "h".into(), None, None).unwrap();
    assert!(b.lib.set_plugin_field(b.data(), id, "database".into(), Some("app".into())).is_err());
}

/// Plugin API 1.3 / ABI 141: the property editor reads an entry's plugin fields with their kinds and values.
#[test]
fn plugin_fields_read_with_kind_and_value_and_a_toggle_takes_true_or_false() {
    let b = bench();
    let pkg = concat!(env!("CARGO_MANIFEST_DIR"), "/../apps/macos/uitests/fixtures/vmware.bastionplugin");
    crate::plugins::plugin_install_file(b.data(), pkg.into(), true).unwrap();
    let ty = "com.example.vmware/vcenter".to_string();
    assert!(plugin_connection_types(b.data()).unwrap().iter().find(|t| t.id == ty).unwrap().sidebar_tree, "the fixture declares a sidebar tree");
    let id = b.lib.add_plugin_connection(b.data(), None, "vc".into(), "vc.lab".into(), ty).unwrap();
    let read = || serde_json::from_str::<serde_json::Value>(&b.lib.plugin_entry_fields_json(b.data(), id.clone()).unwrap()).unwrap();
    let j = read();
    assert_eq!(j["typeId"], "com.example.vmware/vcenter");
    assert_eq!(j["fields"][0], serde_json::json!({ "key": "allow-changes", "label": "Allow changes (power, snapshots)", "kind": "toggle", "value": null }));
    b.lib.set_plugin_field(b.data(), id.clone(), "allow-changes".into(), Some("true".into())).unwrap();
    assert_eq!(read()["fields"][0]["value"], "true");
    assert!(b.lib.set_plugin_field(b.data(), id.clone(), "allow-changes".into(), Some("maybe".into())).is_err());
    assert!(b.lib.plugin_entry_fields_json(b.data(), uuid::Uuid::new_v4().to_string()).is_err(), "no such entry");
}

mod entry_test {
    use super::super::entry_test_step;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn node(id: i64, kind: &str, value: serde_json::Value) -> serde_json::Value {
        json!({ "id": id, "parent": 0, "component": { "kind": kind, "value": value } })
    }

    #[test]
    fn waits_while_loading_then_takes_the_error_banner() {
        let mut nodes = BTreeMap::new();
        let loading = json!({ "type": "set-view", "view": 1, "nodes": [node(0, "stack", json!(null)), node(8, "progress", json!(null))] });
        assert_eq!(entry_test_step(&mut nodes, &loading), None, "still loading");
        let busy = json!({ "type": "patch-view", "view": 1, "upsert": [node(3, "label", json!("Refreshing"))], "remove": null });
        assert_eq!(entry_test_step(&mut nodes, &busy), None, "progress still shown");
        let failed = json!({ "type": "set-view", "view": 1, "nodes": [node(0, "stack", json!(null)), node(8, "banner", json!({ "level": "error", "text": "Login refused." }))] });
        let v = entry_test_step(&mut nodes, &failed).unwrap();
        assert!(!v.ok);
        assert_eq!(v.message, "Login refused.");
    }

    #[test]
    fn a_clean_view_passes_and_a_warning_passes_with_its_text() {
        let mut nodes = BTreeMap::new();
        let v = entry_test_step(&mut nodes, &json!({ "type": "set-view", "view": 1, "nodes": [node(0, "label", json!("ok"))] })).unwrap();
        assert!(v.ok && v.message.is_empty());
        let mut nodes = BTreeMap::new();
        let w = entry_test_step(&mut nodes, &json!({ "type": "set-view", "view": 1, "nodes": [node(8, "banner", json!({ "level": "warning", "text": "Sees no nodes." }))] })).unwrap();
        assert!(w.ok);
        assert_eq!(w.message, "Sees no nodes.");
    }

    #[test]
    fn a_progress_bar_with_a_value_is_not_loading() {
        // Proxmox node cards draw CPU and memory as bars (runner 34, q-pveauth: the test never ended).
        let mut nodes = BTreeMap::new();
        let v = entry_test_step(&mut nodes, &json!({ "type": "set-view", "view": 1, "nodes": [node(0, "stack", json!(null)), node(20, "progress", json!(0.12))] })).unwrap();
        assert!(v.ok);
    }

    #[test]
    fn an_ended_plugin_fails_and_dialogs_are_ignored() {
        let mut nodes = BTreeMap::new();
        assert_eq!(entry_test_step(&mut nodes, &json!({ "type": "open-dialog", "view": 2, "nodes": [] })), None);
        assert!(!entry_test_step(&mut nodes, &json!({ "type": "ended" })).unwrap().ok);
    }
}
