//! The activity store over the C ABI (ABI 103, LOG-CORE-01-WIRING): the seven calls Native Mac
//! has through UniFFI, with the same JSON.
use std::ffi::{c_char, CStr, CString};
use std::path::Path;
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use bastion_core::activity::{ActivityLog, Filter, Page};
use bastion_core::settings::SettingsStore;
use serde_json::Value;

const CONNECTION: &str = "6f1d2c9e-3b1a-4c55-9d1e-0a4d2f3b7c11";
const FOLDER: &str = "0b9a8f7e-6d5c-4b3a-9f1e-2d3c4b5a6f70";
/// Must never be found in the store or in an error message.
const SECRET: &str = "cabi-secret-value-58";

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    Some(s)
}

unsafe fn code() -> String {
    CStr::from_ptr(bastion_last_error_code()).to_str().unwrap().to_string()
}

fn start_json(host: &str) -> String {
    format!(
        r#"{{"connectionId":"{CONNECTION}","connectionName":"web-01","folderPath":[{{"id":"{FOLDER}","name":"Customers"}}],"protocol":"rdp","host":"{host}","port":3389,"username":"deploy","route":[],"loginSource":"inherited","app":"native-windows","appVersion":"1.0.0","deviceName":"test-pc"}}"#
    )
}

fn set(data_dir: &Path, id: &str, value: &str) {
    let store = SettingsStore::new(data_dir.join("settings.json"));
    let mut settings = store.load().unwrap();
    settings.set(id, value).unwrap();
    store.save(&settings).unwrap();
}

fn stored_text(data_dir: &Path) -> String {
    let Ok(entries) = std::fs::read_dir(data_dir.join("activity")) else { return String::new() };
    entries.map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "jsonl")).map(|p| std::fs::read_to_string(p).unwrap()).collect()
}

unsafe fn begin(dir: &CString, json: &str) -> String {
    let mut err = null_mut();
    let id = take(bastion_activity_begin(dir.as_ptr(), c(json).as_ptr(), &mut err));
    assert!(err.is_null(), "{:?}", take(err));
    id.unwrap()
}

unsafe fn query(dir: &CString, filter: &str) -> Vec<Value> {
    let mut err = null_mut();
    let json = take(bastion_activity_query_json(dir.as_ptr(), c(filter).as_ptr(), 0, 50, &mut err));
    assert!(err.is_null(), "{:?}", take(err));
    serde_json::from_str(&json.unwrap()).unwrap()
}

#[test]
fn begin_event_end_query_and_events_round_trip() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        let id = begin(&dir, &start_json("web-01.example.test"));
        let cid = c(&id);
        let details = format!(r#"{{"direction":"to-remote","bytes":12,"password":"{SECRET}"}}"#);
        assert_eq!(bastion_activity_event(dir.as_ptr(), cid.as_ptr(), c("clipboard").as_ptr(), c(&details).as_ptr(), &mut err), 0);
        assert_eq!(bastion_activity_event(dir.as_ptr(), cid.as_ptr(), c("reconnect").as_ptr(), c("{}").as_ptr(), &mut err), 0);
        assert!(err.is_null());

        let open = query(&dir, &format!(r#"{{"folder":"{FOLDER}","result":"open"}}"#));
        assert_eq!(open.len(), 1);
        assert_eq!((open[0]["sessionId"].as_str(), open[0]["open"].as_bool(), open[0]["app"].as_str()), (Some(id.as_str()), Some(true), Some("native-windows")));
        assert!(open[0]["startedAt"].as_u64().unwrap() > 1_700_000_000_000, "startedAt defaults to now");

        // What a second instance of the app sees while the session is open: the same session,
        // open, and not an orphan.
        let other = ActivityLog::in_dir(d.path());
        let seen = other.query(&Filter::default(), Page { offset: 0, limit: 10 }).unwrap();
        assert_eq!((seen.len(), seen[0].open, seen[0].session_id.to_string()), (1, true, id.clone()));
        assert_eq!(other.close_orphans(bastion_core::activity::now_ms()).unwrap(), 0, "another instance closed a live session");

        assert_eq!(bastion_activity_end(dir.as_ptr(), cid.as_ptr(), c(r#"{"endReason":"remote_closed","connectedAt":1}"#).as_ptr(), &mut err), 0);
        let done = query(&dir, &format!(r#"{{"connection":"{CONNECTION}","protocol":"rdp","user":"DEPLOY","result":"ok"}}"#));
        assert_eq!(done.len(), 1);
        assert_eq!((done[0]["open"].as_bool(), done[0]["endReason"].as_str(), done[0]["reconnects"].as_u64()), (Some(false), Some("remote_closed"), Some(1)));
        assert!(done[0]["durationMs"].is_u64() && done[0]["endedAt"].is_u64());
        assert!(query(&dir, r#"{"result":"failed"}"#).is_empty());

        let events: Vec<Value> = serde_json::from_str(&take(bastion_activity_events_json(dir.as_ptr(), cid.as_ptr(), &mut err)).unwrap()).unwrap();
        assert_eq!(events.iter().map(|e| e["kind"].as_str().unwrap()).collect::<Vec<_>>(), ["clipboard", "reconnect"]);
        assert_eq!((events[0]["details"]["password"].as_str(), events[0]["details"]["bytes"].as_str()), (Some("***"), Some("12")));
        assert!(!stored_text(d.path()).contains(SECRET), "a secret reached the store");

        // An end is written once.
        assert_eq!(bastion_activity_end(dir.as_ptr(), cid.as_ptr(), c(r#"{"endReason":"failed"}"#).as_ptr(), &mut err), -1);
        assert!(take(err).is_some());
        assert_eq!(code(), "not_found");
    }
}

#[test]
fn a_disabled_log_records_nothing() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    set(d.path(), "logging.activity-enabled", "false");
    unsafe {
        let mut err = null_mut();
        let id = begin(&dir, &start_json("web-01.example.test"));
        let cid = c(&id);
        assert_eq!(bastion_activity_event(dir.as_ptr(), cid.as_ptr(), c("resize").as_ptr(), c("{}").as_ptr(), &mut err), 0);
        assert_eq!(bastion_activity_end(dir.as_ptr(), cid.as_ptr(), c(r#"{"endReason":"closed_by_user"}"#).as_ptr(), &mut err), 0);
        assert!(!d.path().join("activity").exists(), "the store was created while history is off");
        assert!(query(&dir, "{}").is_empty());

        set(d.path(), "logging.activity-enabled", "true");
        begin(&dir, &start_json("web-01.example.test"));
        assert_eq!(query(&dir, "{}").len(), 1);
    }
}

#[test]
fn bad_input_gives_an_error_with_a_code_that_does_not_repeat_the_input() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let id = begin(&dir, &start_json("web-01.example.test"));
        let cid = c(&id);
        let secret = c(SECRET);
        let refused = |what: &str, err: *mut c_char| {
            let message = take(err).unwrap_or_else(|| panic!("{what}: no error"));
            assert!(!message.contains(SECRET), "{what}: the error repeats its input: {message}");
            assert_eq!(code(), "invalid", "{what}: {message}");
        };

        let mut err = null_mut();
        assert!(bastion_activity_begin(dir.as_ptr(), c(&format!("{SECRET} is not json")).as_ptr(), &mut err).is_null());
        refused("begin, not JSON", err);
        assert!(bastion_activity_begin(dir.as_ptr(), c(&start_json("h").replace("native-windows", SECRET)).as_ptr(), &mut err).is_null());
        refused("begin, unknown app", err);
        assert!(bastion_activity_begin(dir.as_ptr(), c(&start_json("h").replace("3389", &format!("\"{SECRET}\""))).as_ptr(), &mut err).is_null());
        refused("begin, wrong type", err);
        assert!(bastion_activity_query_json(dir.as_ptr(), c(&format!(r#"{{"result":"{SECRET}"}}"#)).as_ptr(), 0, 10, &mut err).is_null());
        refused("query", err);
        assert!(bastion_activity_events_json(dir.as_ptr(), secret.as_ptr(), &mut err).is_null());
        refused("events, bad id", err);
        assert_eq!(bastion_activity_event(dir.as_ptr(), cid.as_ptr(), secret.as_ptr(), c("{}").as_ptr(), &mut err), -1);
        refused("event, unknown kind", err);
        assert_eq!(bastion_activity_event(dir.as_ptr(), cid.as_ptr(), c("resize").as_ptr(), c(&format!(r#"{{"{SECRET}":{{"a":1}}}}"#)).as_ptr(), &mut err), -1);
        refused("event, nested detail", err);
        assert_eq!(bastion_activity_end(dir.as_ptr(), cid.as_ptr(), c(&format!(r#"{{"endReason":"{SECRET}"}}"#)).as_ptr(), &mut err), -1);
        refused("end, unknown reason", err);
        assert_eq!(bastion_activity_end(dir.as_ptr(), secret.as_ptr(), c(r#"{"endReason":"failed"}"#).as_ptr(), &mut err), -1);
        refused("end, bad id", err);

        // A missing argument is an error, never a crash; a NULL `err` is allowed.
        assert!(bastion_activity_begin(null(), c("{}").as_ptr(), &mut err).is_null());
        assert!(take(err).unwrap().contains("data_dir is required"));
        assert!(bastion_activity_begin(dir.as_ptr(), null(), null_mut()).is_null());
        assert_eq!(bastion_activity_event(dir.as_ptr(), cid.as_ptr(), null(), c("{}").as_ptr(), null_mut()), -1);
        assert_eq!(bastion_activity_end(dir.as_ptr(), null(), c("{}").as_ptr(), null_mut()), -1);
        assert_eq!(bastion_activity_purge(null(), null_mut()), -1);
        assert_eq!(bastion_activity_close_orphans(null(), null_mut()), -1);
        assert!(bastion_activity_query_json(dir.as_ptr(), null(), 0, 10, null_mut()).is_null());
        assert!(bastion_activity_events_json(dir.as_ptr(), null(), null_mut()).is_null());

        assert_eq!(query(&dir, "{}").len(), 1, "nothing was written by the refused calls");
        assert!(!stored_text(d.path()).contains(SECRET));
    }
}

#[test]
fn a_bare_user_and_password_given_as_host_is_not_stored() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        begin(&dir, &start_json(&format!("deploy:{SECRET}")));
        begin(&dir, &start_json(&format!("https://deploy:{SECRET}@web-01.example.test:8443/path?token={SECRET}")));
        begin(&dir, &start_json("web-01.example.test:2222"));
        let hosts: Vec<String> = query(&dir, "{}").iter().map(|s| s["host"].as_str().unwrap().to_string()).collect();
        assert_eq!(hosts, ["web-01.example.test:2222", "web-01.example.test:8443", "(hidden)"]);
        assert!(!stored_text(d.path()).contains(SECRET), "a password given in the host reached the store");
    }
}

#[test]
fn purge_follows_the_retention_setting_and_orphans_are_closed_at_the_next_start() {
    let d = tempfile::tempdir().unwrap();
    let dir = c(d.path().to_str().unwrap());
    unsafe {
        let mut err = null_mut();
        assert_eq!(bastion_activity_purge(dir.as_ptr(), &mut err), 0, "no store yet");
        assert_eq!(bastion_activity_close_orphans(dir.as_ptr(), &mut err), 0);

        // An earlier run began a session and went away (quit or crash) without ending it.
        let earlier = ActivityLog::in_dir(d.path());
        let start = serde_json::from_str::<Value>(&start_json("web-01.example.test")).unwrap();
        let mut start = start.as_object().unwrap().clone();
        start.insert("startedAt".into(), bastion_core::activity::now_ms().into());
        let orphan = earlier.begin(serde_json::from_value(Value::Object(start)).unwrap()).unwrap();
        drop(earlier);
        // This run has a session of its own, which is not an orphan.
        let mine = begin(&dir, &start_json("web-01.example.test"));

        assert_eq!(bastion_activity_close_orphans(dir.as_ptr(), &mut err), 1);
        let all = query(&dir, "{}");
        let by_id = |id: &str| all.iter().find(|s| s["sessionId"] == id).unwrap().clone();
        assert_eq!((by_id(&orphan.to_string())["open"].as_bool(), by_id(&orphan.to_string())["endReason"].as_str()), (Some(false), Some("app_crashed")));
        assert_eq!(by_id(&mine)["open"], true);
        assert_eq!(bastion_activity_close_orphans(dir.as_ptr(), &mut err), 0, "closed once");

        let old = d.path().join("activity").join("2020-01.jsonl");
        std::fs::write(&old, "").unwrap();
        set(d.path(), "logging.activity-retention-days", "0");
        assert_eq!(bastion_activity_purge(dir.as_ptr(), &mut err), 0, "forever");
        assert!(old.exists());
        set(d.path(), "logging.activity-retention-days", "365");
        assert_eq!(bastion_activity_purge(dir.as_ptr(), &mut err), 1);
        assert!(!old.exists() && err.is_null());
        assert_eq!(query(&dir, "{}").len(), 2, "this month's history is kept");
    }
}
