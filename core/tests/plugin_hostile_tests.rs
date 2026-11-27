//! PLUG-09 (core part): hostile-plugin and host-API conformance suites.
//!
//! A real helper (`plugin-host/`, built once per run) runs a real component
//! (`tests/fixtures/hostile-plugin`, built for `wasm32-wasip2` once per run), installed as an
//! Official plugin signed by test keys, opened through `view::open` exactly as the apps open it.
//! The view name picks what the plugin does; a plugin that survives reports the core's answers
//! as one label, which these tests read from the view's updates.
//!
//! The app loads only Official plugins today, and the Official tier is re-derived from the app's
//! pinned keys (SEC-5), so test keys cannot make one. The suite therefore installs the plugin as
//! Unverified and runs with the `test-hooks` feature, whose `BASTION_TEST_PLUGIN_ROLLOUT=unverified`
//! opens that stage, as the UI proof runs do:
//! `cargo test --features test-hooks --test plugin_hostile_tests`. Without the feature the file
//! compiles to nothing. The install-time import check is the same code for every tier.
//!
//! Needs `rustup target add wasm32-wasip2` (docs/TESTING.md). Spec: docs/specs/plugins.md,
//! sections 5, 6 and 14; THREAT_MODEL T18.
#![cfg(feature = "test-hooks")]
#[path = "fixtures/plugin/support.rs"]
mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use bastion_core::plugin::host::view::{self, EntryBinding, ViewSession, ViewSpec};
use bastion_core::plugin::host::{Pool, Timing, HELPER_PROGRAM};
use bastion_core::plugin::{install, InstallRequest, PluginError, PluginFolders};
use bastion_core::policy::Policy;
use serde_json::json;
use support::*;

const ID: &str = "com.example.hostile";
const WAIT: Duration = Duration::from_secs(30);
const TIMING: Timing = Timing { hello: Duration::from_secs(20), ping_every: Duration::from_millis(200), hang_after: Duration::from_secs(3) };

// ---- building ----

fn cargo_build(dir: &Path, extra: &[&str]) {
    let out = Command::new(env!("CARGO"))
        .arg("build")
        .args(extra)
        .arg("--quiet")
        .current_dir(dir)
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTFLAGS")
        .output()
        .expect("run cargo");
    assert!(out.status.success(), "building {} failed:\n{}\n(the plugin target: `rustup target add wasm32-wasip2`)", dir.display(), String::from_utf8_lossy(&out.stderr));
}

fn program() -> &'static PathBuf {
    static P: OnceLock<PathBuf> = OnceLock::new();
    P.get_or_init(|| {
        if let Some(path) = std::env::var_os("BASTION_TEST_PLUGIN_HELPER") {
            return PathBuf::from(path);
        }
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../plugin-host");
        cargo_build(&dir, &[]);
        dir.join("target/debug").join(HELPER_PROGRAM)
    })
}

fn component() -> &'static Vec<u8> {
    static C: OnceLock<Vec<u8>> = OnceLock::new();
    C.get_or_init(|| {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hostile-plugin");
        cargo_build(&dir, &["--release", "--target", "wasm32-wasip2"]);
        std::fs::read(dir.join("target/wasm32-wasip2/release/bastion_hostile_plugin.wasm")).expect("hostile component")
    })
}

// ---- packaging and installing ----

fn hostile_manifest(permissions: &str) -> String {
    format!(
        r#"schema = 1
id = "{ID}"
name = "Hostile"
version = "1.0.0"
api = "1.2"
publisher = "Example Tools"
description = "A plugin that misbehaves on purpose, for the core's hostile suite."
license = "Apache-2.0"
repository = "https://github.com/example/hostile"

[permissions]
{permissions}
"#
    )
}

const ALL: &str = "network = \"entry\"\ncredentials = \"entry\"\nstorage = true\nopen = [\"ssh\", \"rdp\"]\n";

fn package(manifest: &str) -> Vec<u8> {
    zip(&[
        Entry::deflated("plugin.toml", manifest.as_bytes()),
        Entry::stored("plugin.wasm", component()),
        Entry::stored("icon.png", &png()),
        Entry::deflated("README.md", b"# Hostile\n"),
        Entry::stored("LICENSE", b"Apache License 2.0\n"),
        Entry::stored("THIRD_PARTY_NOTICES.txt", b"none\n"),
    ])
}

fn install_with(data: &Path, manifest: &str) -> Result<(), PluginError> {
    let bytes = package(manifest);
    install(&PluginFolders::new(data), InstallRequest { package: &bytes, record: None, record_bytes: None, allow_unverified: true }).map(|_| ())
}

struct Lab {
    _dir: tempfile::TempDir,
    data: PathBuf,
    pool: Pool,
}

fn lab() -> Lab {
    static ROLLOUT: std::sync::Once = std::sync::Once::new();
    // Read by `Rollout::current()` in a `test-hooks` build only. Set once, before any view opens.
    ROLLOUT.call_once(|| std::env::set_var("BASTION_TEST_PLUGIN_ROLLOUT", "unverified"));
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().to_path_buf();
    install_with(&data, &hostile_manifest(ALL)).expect("installs");
    Lab { pool: Pool::with_program(program().clone(), TIMING), data, _dir: dir }
}

fn entry() -> EntryBinding {
    EntryBinding {
        document_id: "doc-1".into(),
        entry_id: "entry-1".into(),
        name: "Lab box".into(),
        host: "127.0.0.1".into(),
        port: 1,
        fields: vec![],
        protected: false,
        environment: String::new(),
        tls: Default::default(),
        connection_type: String::new(),
    }
}

fn open(lab: &Lab, name: &str, entry: Option<EntryBinding>) -> ViewSession {
    view::open(&lab.pool, ViewSpec { data_dir: lab.data.clone(), plugin_id: ID.into(), view_name: name.into(), entry, policy: Policy::default(), allow_unverified: true, safe_mode: false, login: None })
        .unwrap_or_else(|f| panic!("view {name} opens: {f:?}"))
}

/// Updates until the plugin's report label, or until it ended (`Err(reason)`).
fn report(session: &ViewSession) -> Result<String, String> {
    report_within(session, WAIT)
}

fn report_within(session: &ViewSession, wait: Duration) -> Result<String, String> {
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        let Some(u) = session.next_update(Duration::from_millis(200)) else { continue };
        match u["type"].as_str() {
            Some("ended") => return Err(u["reason"].as_str().unwrap_or_default().to_string()),
            Some("set-view") => {
                let label = u["nodes"].as_array().and_then(|n| n.iter().find(|n| n["component"]["kind"] == "label")).and_then(|n| n["component"]["value"].as_str());
                return Ok(label.unwrap_or_else(|| panic!("no label in {u}")).to_string());
            }
            _ => {}
        }
    }
    panic!("no report and no end in {wait:?}");
}

/// Waits for `ended` and returns its reason, with how long it took.
fn ended(session: &ViewSession) -> (String, Duration) {
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if let Some(u) = session.next_update(Duration::from_millis(200)) {
            if u["type"] == "ended" {
                return (u["reason"].as_str().unwrap_or_default().to_string(), start.elapsed());
            }
        }
    }
    panic!("the view did not end in {WAIT:?}");
}

fn field<'a>(report: &'a str, key: &str) -> &'a str {
    report.split(' ').find_map(|kv| kv.strip_prefix(key).and_then(|r| r.strip_prefix('='))).unwrap_or_else(|| panic!("no {key} in {report}"))
}

// ---- conformance ----

#[test]
fn conformance_entry_storage_and_log_answer_as_the_api_says() {
    let lab = lab();
    let s = open(&lab, "conform", Some(entry()));
    let r = report(&s).expect("the conformance view reports");
    assert_eq!(field(&r, "entry"), "127.0.0.1:1", "{r}");
    assert_eq!(field(&r, "settings"), "0", "{r}");
    assert_eq!(field(&r, "set"), "ok", "{r}");
    assert_eq!(field(&r, "get"), "v1", "{r}");
    assert_eq!(field(&r, "keys"), "k", "{r}");
    assert_eq!(field(&r, "delete"), "ok", "{r}");
    assert_eq!(field(&r, "gone"), "true", "{r}");
    s.close();
    assert_eq!(ended(&s).0, "tab-closed");
}

#[test]
fn conformance_an_unknown_view_still_reports_and_closes_cleanly() {
    let lab = lab();
    let s = open(&lab, "no-such-view", None);
    assert!(report(&s).expect("reports").contains("unknown view"));
    s.close();
    assert_eq!(ended(&s).0, "tab-closed");
}

// ---- resource abuse ----

#[test]
fn a_plugin_that_loops_forever_is_stopped_by_the_compute_limit() {
    let lab = lab();
    let s = open(&lab, "spin", None);
    let (reason, took) = ended(&s);
    // COMPUTE_MS is 2 s of CPU per event; the helper traps and the core ends the view.
    assert_ne!(reason, "tab-closed", "the loop must be stopped, not close normally");
    assert!(matches!(reason.as_str(), "crash" | "limit" | "hang"), "{reason}");
    assert!(took < Duration::from_secs(15), "stopped after {took:?}");
}

#[test]
fn a_plugin_that_allocates_without_end_is_stopped_at_its_memory_limit() {
    let lab = lab();
    let s = open(&lab, "grow", None);
    let (reason, took) = ended(&s);
    assert!(matches!(reason.as_str(), "crash" | "limit"), "{reason}");
    assert!(took < Duration::from_secs(20), "stopped after {took:?}");
}

#[test]
fn a_plugin_that_traps_ends_as_a_crash_and_the_core_lives_on() {
    let lab = lab();
    let s = open(&lab, "trap", None);
    assert_eq!(ended(&s).0, "crash");
    // The pool gave the place back: another view opens and works.
    let again = open(&lab, "no-such-view", None);
    assert!(report(&again).is_ok());
    again.close();
}

#[test]
fn a_log_flood_is_absorbed_and_the_plugin_keeps_running() {
    let lab = lab();
    let s = open(&lab, "log-flood", None);
    assert_eq!(report(&s).as_deref(), Ok("flooded"));
    s.close();
    // The plugin's log file stays bounded (spec section 5: a capped log).
    let logs: u64 = walk(&lab.data).into_iter().filter(|p| p.extension().is_some_and(|e| e == "log")).map(|p| p.metadata().map(|m| m.len()).unwrap_or(0)).sum();
    assert!(logs < 20_000 * 1_000, "the log kept every line: {logs} bytes");
}

#[test]
fn an_update_flood_is_paced_and_never_lost_or_unbounded() {
    let lab = lab();
    let s = open(&lab, "update-flood", None);
    let start = Instant::now();
    let r = report(&s).expect("reports");
    assert_eq!(field(&r, "accepted"), "300", "every update is delivered, none dropped: {r}");
    // 300 patches at 30 a second take about 10 s: the core held them back.
    assert!(start.elapsed() >= Duration::from_secs(5), "not paced: {:?}", start.elapsed());
    s.close();
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

// ---- capabilities ----

#[test]
fn calls_a_view_has_no_grant_for_are_refused_and_the_plugin_lives_on() {
    let lab = lab();
    // No entry: storage, the network and the entry's login have nothing to act on.
    let s = open(&lab, "no-entry", None);
    let r = report(&s).expect("reports");
    assert_eq!(field(&r, "storage"), "denied", "{r}");
    assert_eq!(field(&r, "net"), "denied", "{r}");
    assert_eq!(field(&r, "credentials"), "denied", "{r}");
    s.close();
}

#[test]
fn a_connect_goes_only_to_the_entrys_host() {
    let lab = lab();
    let s = open(&lab, "net-other-host", Some(entry()));
    let r = report(&s).expect("reports");
    // Nothing listens on 127.0.0.1:1; the API has no way to name another host.
    assert_ne!(field(&r, "net"), "ok", "{r}");
    s.close();
}

#[test]
fn a_component_that_imports_more_than_its_permissions_is_refused_at_install() {
    let dir = tempfile::tempdir().unwrap();
    // The component imports storage, net and credentials; the manifest grants only the network.
    let err = install_with(dir.path(), &hostile_manifest("network = \"entry\"\n")).expect_err("refused");
    let text = format!("{err:?}");
    assert!(text.to_lowercase().contains("import") || text.to_lowercase().contains("permission"), "{text}");
}

// ---- malformed data ----

#[test]
fn malformed_views_are_refused_one_by_one_and_the_plugin_lives_on() {
    let lab = lab();
    let s = open(&lab, "malformed", None);
    let r = report(&s).expect("reports");
    for key in ["cycle", "orphan", "duplicate", "deep", "many", "huge"] {
        assert_eq!(field(&r, key), "invalid", "{key}: {r}");
    }
    s.close();
}

#[test]
fn storage_abuse_is_refused_and_nothing_escapes_the_plugins_folder() {
    let lab = lab();
    // A key is only a name inside the entry's one storage file, so "../../escape" is stored as
    // a name (checked below: no file of that name appears); the others must be refused. The
    // secret check refuses secrets the core released to this helper, not any key-shaped text;
    // no secret can be released until `credentials` lands, so that case waits for it.
    for (view, key) in [("storage-big", "big"), ("storage-long-key", "long-key"), ("storage-traversal", "")] {
        let s = open(&lab, view, Some(entry()));
        let start = Instant::now();
        // Filling 50 MiB rewrites the entry's file on every set: allow it longer.
        let got = report_within(&s, Duration::from_secs(180));
        eprintln!("{view}: {:?} in {:?}", got, start.elapsed());
        match got {
            // Refused: the plugin hears an error and keeps running.
            Ok(r) if key.is_empty() => assert!(r.starts_with("traversal="), "{r}"),
            Ok(r) => assert_ne!(field(&r, key), "ok", "{view}: {r}"),
            // Or the plugin ended: only its own helper stops.
            Err(reason) => panic!("{view}: the plugin ended ({reason}) instead of hearing a refusal"),
        }
        s.close();
        ended(&s);
    }
    // Whatever the traversal key did, no file named "escape" exists anywhere under the data folder.
    let escaped: Vec<_> = walk(&lab.data).into_iter().filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().contains("escape"))).collect();
    assert!(escaped.is_empty(), "{escaped:?}");
}

#[test]
fn malformed_app_events_are_refused_before_the_plugin_sees_them() {
    let lab = lab();
    let s = open(&lab, "no-such-view", None);
    report(&s).unwrap();
    for bad in [json!(null), json!({}), json!({"type": "ui"}), json!({"type": "ui", "view": "x", "node": 1}), json!({"type": "nope"}), json!([1, 2, 3])] {
        assert!(s.send_event(&bad).is_err(), "accepted {bad}");
    }
    s.close();
    assert_eq!(ended(&s).0, "tab-closed");
}

/// PLUG-09 finding, fixed (PLUG-STORAGE-CAP): a value over `MAX_STORAGE_VALUE_BYTES` is refused
/// with `invalid` before the helper frames it; the plugin hears the refusal and keeps running.
#[test]
fn a_four_mib_storage_value_is_refused_not_fatal() {
    let lab = lab();
    let s = open(&lab, "storage-size:4096", Some(entry()));
    let r = report(&s).expect("the plugin hears an answer and keeps running");
    assert!(r.starts_with("size=") && r != "size=ok", "{r}");
    s.close();
}

#[test]
fn a_two_mib_storage_value_is_stored() {
    let lab = lab();
    let s = open(&lab, "storage-size:2048", Some(entry()));
    assert_eq!(report(&s).as_deref(), Ok("size=ok"));
    s.close();
}

// ---- open.connection (plugin API 1.2; docs/specs/plugins-amendment-3.md, section 11) ----

/// The hostile plugin's manifest already grants `open = ["ssh", "rdp"]` (API 1.2).
fn open_lab() -> Lab {
    lab()
}

fn open_with(lab: &Lab, name: &str, entry: EntryBinding, policy: Policy) -> ViewSession {
    view::open(&lab.pool, ViewSpec { data_dir: lab.data.clone(), plugin_id: ID.into(), view_name: name.into(), entry: Some(entry), policy, allow_unverified: true, safe_mode: false, login: None })
        .unwrap_or_else(|f| panic!("view {name} opens: {f:?}"))
}

/// Updates until one of `kind`, collecting the report labels seen on the way.
fn until(session: &ViewSession, kind: &str) -> (serde_json::Value, Vec<String>) {
    let deadline = Instant::now() + WAIT;
    let mut labels = Vec::new();
    while Instant::now() < deadline {
        let Some(u) = session.next_update(Duration::from_millis(200)) else { continue };
        if u["type"] == "set-view" {
            if let Some(l) = u["nodes"].as_array().and_then(|n| n.iter().find(|n| n["component"]["kind"] == "label")).and_then(|n| n["component"]["value"].as_str()) {
                labels.push(l.to_string());
            }
        }
        if u["type"] == kind {
            return (u, labels);
        }
        assert_ne!(u["type"], "ended", "the view ended: {u}");
    }
    panic!("no {kind} update in {WAIT:?}; labels {labels:?}");
}

/// Runs a command (a user action) and returns the plugin's report, answering any sheet with
/// `answer` first. Returns every update type seen.
fn command(session: &ViewSession, id: &str, answer: Option<serde_json::Value>) -> (String, Vec<serde_json::Value>) {
    session.send_event(&json!({ "type": "command", "id": id, "view": 1 })).unwrap();
    let deadline = Instant::now() + WAIT;
    let mut seen = Vec::new();
    while Instant::now() < deadline {
        let Some(u) = session.next_update(Duration::from_millis(200)) else { continue };
        seen.push(u.clone());
        match u["type"].as_str() {
            Some("open-request") => {
                let mut a = answer.clone().expect("a sheet the test did not expect");
                a["type"] = json!("open");
                a["request"] = u["request"].clone();
                session.send_event(&a).unwrap();
            }
            Some("set-view") => {
                let label = u["nodes"].as_array().and_then(|n| n.iter().find(|n| n["component"]["kind"] == "label")).and_then(|n| n["component"]["value"].as_str()).unwrap_or_default();
                if label.starts_with("open=") {
                    return (label.to_string(), seen);
                }
            }
            Some("ended") => panic!("the view ended: {u}"),
            _ => {}
        }
    }
    panic!("no open report in {WAIT:?}: {seen:?}");
}

fn audits(lab: &Lab, action: &str) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(lab.data.join("audit.jsonl")).unwrap_or_default();
    text.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|v| v.to_string().contains(action)).collect()
}

fn guest_entry() -> EntryBinding {
    EntryBinding { host: "pve.lab.example".into(), port: 8006, ..entry() }
}

#[test]
fn open_without_a_user_action_is_refused_and_audited() {
    let lab = open_lab();
    let s = open_with(&lab, "open-unprompted", guest_entry(), Policy::default());
    let (_, labels) = until(&s, "set-view");
    assert_eq!(labels, vec!["open=denied(not-now)".to_string()]);
    let denied = audits(&lab, "plugin.open.denied");
    assert!(denied.iter().any(|a| a.to_string().contains("stamp")), "{denied:?}");
}

#[test]
fn a_confirmed_open_reaches_the_app_and_one_action_allows_one_request() {
    let lab = open_lab();
    let s = open_with(&lab, "conform", guest_entry(), Policy::default());
    let _ = report(&s);
    let (r, seen) = command(&s, "open|ssh|10.0.0.5|entry|web 01", Some(json!({ "accept": true, "route": "entry" })));
    assert_eq!(r, "open=opened");
    let sheet = seen.iter().find(|u| u["type"] == "open-request").expect("the sheet");
    assert_eq!((sheet["protocol"].as_str(), sheet["host"].as_str(), sheet["port"].as_u64(), sheet["reported"].as_bool()), (Some("ssh"), Some("10.0.0.5"), Some(22), Some(false)));
    assert_eq!(sheet["label"], "web 01");
    let go = seen.iter().find(|u| u["type"] == "open-go").expect("the go-ahead");
    assert_eq!((go["host"].as_str(), go["route"].as_str(), go["check_resolved"].as_bool()), (Some("10.0.0.5"), Some("entry"), Some(false)));
    assert_eq!(audits(&lab, "plugin.open.request").len(), 1);
    assert!(audits(&lab, "plugin.open.answer").iter().any(|a| a.to_string().contains("opened")));

    let (r, _) = command(&s, "open|rdp|10.0.0.6|entry|win", Some(json!({ "accept": false })));
    assert_eq!(r, "open=declined");

    let (r, seen) = command(&s, "open2|ssh|10.0.0.7|entry|x", Some(json!({ "accept": true })));
    assert_eq!(r, "open=opened second=denied(not-now)");
    assert_eq!(seen.iter().filter(|u| u["type"] == "open-request").count(), 1, "one sheet for one action");
}

#[test]
fn refused_targets_never_reach_the_sheet() {
    let lab = open_lab();
    let s = open_with(&lab, "conform", guest_entry(), Policy::default());
    let _ = report(&s);
    for (id, why) in [
        ("open|ssh|169.254.169.254|entry|m", "link-local"),
        ("open|ssh|127.0.0.1|entry|lo", "loopback"),
        ("open|ssh|::ffff:127.0.0.1|entry|lo", "loopback"),
        ("open|ssh|0x7f.1|entry|lo", "canonical"),
        ("open|ssh|metadata.google.internal|entry|m", "metadata"),
        ("open|vnc|10.0.0.5|entry|v", "may not open"),
        ("open|ssh|10.0.0.5|entry|two\nlines", "label"),
    ] {
        let (r, seen) = command(&s, id, None);
        assert!(r.starts_with("open=denied("), "{id}: {r}");
        assert!(r.contains(why) || why == "may not open" && r.contains("vnc") || why == "label", "{id}: {r}");
        assert!(!seen.iter().any(|u| u["type"] == "open-request"), "{id}");
    }
}

#[test]
fn loopback_only_for_a_loopback_entry_and_never_after_a_route_change() {
    let lab = open_lab();
    let direct = bastion_core::plugin::host::relay::EntryTls { route: bastion_core::plugin::host::relay::EntryRoute::Direct, ..Default::default() };
    let s = open_with(&lab, "conform", EntryBinding { tls: direct, ..entry() }, Policy::default()); // 127.0.0.1, direct
    let _ = report(&s);
    let (r, _) = command(&s, "open|ssh|127.0.0.1|entry|lo", Some(json!({ "accept": true, "route": "entry" })));
    assert_eq!(r, "open=opened");
    let (r, seen) = command(&s, "open|ssh|127.0.0.1|entry|lo", Some(json!({ "accept": true, "route": "direct" })));
    assert!(r.starts_with("open=denied("), "{r}");
    assert!(seen.iter().any(|u| u["type"] == "open-refused"));
    assert!(!seen.iter().any(|u| u["type"] == "open-go"));
    // The same loopback entry, but through a route that is not its own: refused at once.
    let s = open_with(&lab, "conform", entry(), Policy::default()); // 127.0.0.1, gateway without a tunnel
    let _ = report(&s);
    assert!(command(&s, "open|ssh|127.0.0.1|entry|lo", None).0.contains("loopback"));
}

#[test]
fn policy_off_and_reported_only_refuse_and_the_rate_holds() {
    let lab = open_lab();
    let off = Policy { plugin_open_disabled: true, ..Policy::default() };
    let s = open_with(&lab, "conform", guest_entry(), off);
    let _ = report(&s);
    assert!(command(&s, "open|ssh|10.0.0.5|entry|g", None).0.contains("policy"));
    s.close();

    let reported_only = Policy { plugin_open_reported_only: true, ..Policy::default() };
    let s = open_with(&lab, "conform", guest_entry(), reported_only);
    let _ = report(&s);
    assert_eq!(command(&s, "open|ssh|10.0.0.5|entry|g", None).0, "open=denied(not-reported)", "nothing was reported");
    s.close();

    let s = open_with(&lab, "conform", guest_entry(), Policy::default());
    let _ = report(&s);
    for i in 0..10 {
        let (r, _) = command(&s, "open|ssh|169.254.1.1|entry|g", None);
        assert!(!r.contains("rate-limited"), "request {i}: {r}");
    }
    assert_eq!(command(&s, "open|ssh|10.0.0.5|entry|g", None).0, "open=denied(rate-limited)", "the eleventh in a minute");
}
