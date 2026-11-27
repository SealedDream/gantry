//! Session history (`bastion_core::activity`): a record of every session of every protocol,
//! for the History lists. Metadata only: no secrets, no keystrokes, no session content.
//!
//! Records cross as JSON with camelCase keys. Times are Unix milliseconds.
//!
//! Lifecycle: at launch, off the main thread, call `activity_purge` and `activity_close_orphans`.
//! For each session call `activity_begin` when the connect starts, `activity_event` for what
//! happens inside it, and `activity_end` once when it ends (also when the connect failed).
//! With the setting `logging.activity-enabled` off, `activity_begin` still returns an id and
//! the other calls do nothing for it.
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use bastion_core::activity::{self, ActivityLog, EventKind, Filter, Page, SessionEnd, SessionStart};
use bastion_core::settings::SettingsStore;
use serde_json::Value;

use crate::{FfiError, FfiResult};

const ENABLED_SETTING: &str = "logging.activity-enabled";
const RETENTION_SETTING: &str = "logging.activity-retention-days";

/// One handle per data directory for the life of the process: it knows which sessions are open
/// and holds the lock that tells other instances this run is alive.
pub(crate) fn log(data_dir: impl AsRef<Path>) -> Arc<ActivityLog> {
    static LOGS: OnceLock<Mutex<HashMap<PathBuf, Arc<ActivityLog>>>> = OnceLock::new();
    let data_dir = data_dir.as_ref();
    let mut logs = LOGS.get_or_init(Default::default).lock().unwrap_or_else(|e| e.into_inner());
    logs.entry(data_dir.to_path_buf()).or_insert_with(|| Arc::new(ActivityLog::in_dir(data_dir))).clone()
}

fn setting(data_dir: impl AsRef<Path>, id: &str) -> FfiResult<String> {
    Ok(SettingsStore::new(data_dir.as_ref().join("settings.json")).load()?.get(id)?)
}

/// The setting `logging.activity-enabled`. A settings file that cannot be read leaves the
/// default, which is on.
pub(crate) fn is_enabled(data_dir: impl AsRef<Path>) -> bool {
    setting(data_dir, ENABLED_SETTING).map_or(true, |v| v == "true")
}

fn to_json<T: serde::Serialize>(v: &T) -> FfiResult<String> {
    serde_json::to_string(v).map_err(|e| FfiError::failed(e.to_string()))
}

/// Bad input from the caller. The message says what kind of fault it is and where, and never
/// repeats the input: serde's own text quotes the value it met, which may be a secret a caller
/// passed in the wrong place, and error messages end up in logs.
fn invalid(what: &str, e: serde_json::Error) -> FfiError {
    use serde_json::error::Category;
    let fault = match e.classify() {
        Category::Syntax | Category::Eof => "not valid JSON",
        Category::Data => "a field is missing, unknown or of the wrong type",
        Category::Io => "could not be read",
    };
    let place = if e.line() > 0 { format!(" (line {}, column {})", e.line(), e.column()) } else { String::new() };
    FfiError::Failed { message: format!("invalid {what}: {fault}{place}"), code: "invalid".into() }
}

/// A session id from the caller; the error does not repeat what was passed.
fn session(id: &str) -> FfiResult<activity::SessionId> {
    id.parse().map_err(|_| FfiError::Failed { message: "invalid session id".into(), code: "invalid".into() })
}

/// Parse a JSON object, filling `time_key` with now when the caller left it out.
fn parse_with_time<T: serde::de::DeserializeOwned>(json: &str, time_key: &str, what: &str) -> FfiResult<T> {
    let mut value: Value = serde_json::from_str(json).map_err(|e| invalid(what, e))?;
    if let Some(object) = value.as_object_mut() {
        object.entry(time_key).or_insert_with(|| activity::now_ms().into());
    }
    serde_json::from_value(value).map_err(|e| invalid(what, e))
}

/// Record the start of a session; returns its session id. `start_json`:
/// `{"connectionId","connectionName","folderPath":[{"id","name"}],"protocol","host","port"?,
/// "username"?,"route":[names],"loginSource":"own|inherited|same-host|typed|agent|key",
/// "startedAt"?,"app":"native-mac|native-windows|tauri","appVersion","deviceName"}`.
/// `folderPath` is root first; `startedAt` defaults to now. Never pass a secret: there is no
/// field for one, and a URL given as `host` is cut down to its host name. **Never pass a bare
/// `user:password` as `host`**: it is not stored where it can be told from a host and a port
/// (`name:word`), but a password of digits only cannot be told from a port.
///
/// Call off the main thread: the first write of a run can wait up to two seconds for another
/// instance and can fail (the error is returned; show it or log it, the core does not).
/// Sessions the bridge opens itself (`SessionManager::connect_ssh`, `connect_sftp`,
/// `connect_ftps`) are recorded by the bridge: do not begin them here as well.
#[uniffi::export]
pub fn activity_begin(data_dir: String, start_json: String) -> FfiResult<String> {
    let start: SessionStart = parse_with_time(&start_json, "startedAt", "session start")?;
    let log = log(&data_dir);
    log.set_enabled(is_enabled(&data_dir));
    Ok(log.begin(start)?.to_string())
}

/// Record an event of an open session, now. `kind`: `reconnect`, `host_key`, `certificate`,
/// `resize`, `clipboard`, `shared_folder`, `file_transfer`, `tunnel`, `task`, `snippet`,
/// `broadcast`, `session_log` or `trigger`. `details_json`: a flat object of short strings,
/// numbers or booleans, metadata only (direction, size, name, exit code): never clipboard, file
/// or terminal content. Each kind has its own list of keys (`EventKind::detail_keys` in the
/// core); a key that is not on it is dropped.
#[uniffi::export]
pub fn activity_event(data_dir: String, session_id: String, kind: String, details_json: String) -> FfiResult<()> {
    let kind: EventKind = serde_json::from_value(Value::String(kind)).map_err(|e| invalid("event kind", e))?;
    let given: BTreeMap<String, Value> = serde_json::from_str(&details_json).map_err(|e| invalid("event details", e))?;
    let mut details = BTreeMap::new();
    for (key, value) in given {
        let text = match value {
            Value::String(s) => s,
            Value::Number(n) => n.to_string(),
            Value::Bool(b) => b.to_string(),
            _ => return Err(FfiError::Failed { message: "invalid event details: a value is not a string, number or boolean".into(), code: "invalid".into() }),
        };
        details.insert(key, text);
    }
    Ok(log(&data_dir).event(session(&session_id)?, kind, details)?)
}

/// Record the end of a session, once. `end_json`: `{"connectedAt"?,"endedAt"?,
/// "endReason":"closed_by_user|remote_closed|network_lost|auth_failed|host_key|timeout|app_quit|failed",
/// "reconnects"?,"transcriptPath"?,"transcriptSha256"?}`. `endedAt` defaults to now; leave
/// `connectedAt` out when the session never connected.
#[uniffi::export]
pub fn activity_end(data_dir: String, session_id: String, end_json: String) -> FfiResult<()> {
    let end: SessionEnd = parse_with_time(&end_json, "endedAt", "session end")?;
    Ok(log(&data_dir).end(session(&session_id)?, end)?)
}

/// One page of sessions, newest first, as a JSON array. `filter_json`: `{"connection"?,
/// "folder"?,"from"?,"to"?,"protocol"?,"user"?,"result"?:"ok|failed|open"}`; `folder` includes
/// subfolders. `limit` is capped at 500. Each item: the fields of the start, `open`, and once
/// ended `connectedAt`, `endedAt`, `durationMs`, `endReason`, `reconnects`, `transcriptPath`,
/// `transcriptSha256`.
#[uniffi::export]
pub fn activity_query_json(data_dir: String, filter_json: String, offset: u32, limit: u32) -> FfiResult<String> {
    let filter: Filter = serde_json::from_str(&filter_json).map_err(|e| invalid("filter", e))?;
    to_json(&log(&data_dir).query(&filter, Page { offset: offset as usize, limit: limit as usize })?)
}

/// The events of one session, oldest first: `[{"at","kind","details":{…}}]`.
#[uniffi::export]
pub fn activity_events_json(data_dir: String, session_id: String) -> FfiResult<String> {
    to_json(&log(&data_dir).events(session(&session_id)?)?)
}

/// Delete history older than the "Keep session history for" setting; returns the number of
/// monthly files deleted. Call at launch, off the main thread.
#[uniffi::export]
pub fn activity_purge(data_dir: String) -> FfiResult<u32> {
    let days: u32 = setting(&data_dir, RETENTION_SETTING)?.parse().map_err(|_| FfiError::failed("retention setting is not a number".into()))?;
    Ok(log(&data_dir).purge(days, activity::now_ms())? as u32)
}

/// Close sessions an earlier run left open (crash, power loss) as `app_crashed`; returns how
/// many. Call once at launch, off the main thread: it can wait up to two seconds for another
/// instance. When that instance is stopped or hung the sweep is skipped (0, a line on stderr)
/// and the next start does it; that is not a failure to show the user.
#[uniffi::export]
pub fn activity_close_orphans(data_dir: String) -> FfiResult<u32> {
    match log(&data_dir).close_orphans(activity::now_ms()) {
        Ok(closed) => Ok(closed as u32),
        // Another instance is stopped or hung while holding the store's gate. Nothing was
        // closed and nothing is wrong with this run: the sweep of the next start does it.
        Err(bastion_core::CoreError::Io(e)) if e.kind() == std::io::ErrorKind::TimedOut => {
            eprintln!("bastion: activity sweep skipped, another instance holds the gate: {e}");
            Ok(0)
        }
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONNECTION: &str = "6f1d2c9e-3b1a-4c55-9d1e-0a4d2f3b7c11";
    const FOLDER: &str = "0b9a8f7e-6d5c-4b3a-9f1e-2d3c4b5a6f70";

    fn dir() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_string_lossy().into_owned();
        (dir, path)
    }

    fn start_json() -> String {
        format!(
            r#"{{"connectionId":"{CONNECTION}","connectionName":"web-01","folderPath":[{{"id":"{FOLDER}","name":"Customers"}}],"protocol":"rdp","host":"web-01.example.test","port":3389,"username":"deploy","route":[],"loginSource":"inherited","app":"native-mac","appVersion":"1.0.0","deviceName":"test-mac"}}"#
        )
    }

    fn set(data_dir: &str, id: &str, value: &str) {
        let store = SettingsStore::new(Path::new(data_dir).join("settings.json"));
        let mut settings = store.load().unwrap();
        settings.set(id, value).unwrap();
        store.save(&settings).unwrap();
    }

    fn query(data_dir: &str, filter: &str) -> Vec<Value> {
        serde_json::from_str(&activity_query_json(data_dir.into(), filter.into(), 0, 50).unwrap()).unwrap()
    }

    fn stored_text(data_dir: &str) -> String {
        let Ok(entries) = std::fs::read_dir(Path::new(data_dir).join("activity")) else { return String::new() };
        entries.map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "jsonl")).map(|p| std::fs::read_to_string(p).unwrap()).collect()
    }

    #[test]
    fn a_session_crosses_the_bridge_as_json_and_comes_back_in_the_folder_history() {
        let (_keep, data_dir) = dir();
        let id = activity_begin(data_dir.clone(), start_json()).unwrap();
        activity_event(data_dir.clone(), id.clone(), "clipboard".into(), r#"{"direction":"to-remote","bytes":12,"password":"bridge-secret-value"}"#.into()).unwrap();
        activity_event(data_dir.clone(), id.clone(), "reconnect".into(), "{}".into()).unwrap();

        let open = query(&data_dir, &format!(r#"{{"folder":"{FOLDER}","result":"open"}}"#));
        assert_eq!(open.len(), 1);
        assert_eq!(open[0]["sessionId"], id.as_str());
        assert_eq!(open[0]["open"], true);
        assert!(open[0]["startedAt"].as_u64().unwrap() > 1_700_000_000_000, "startedAt defaults to now");

        activity_end(data_dir.clone(), id.clone(), r#"{"endReason":"remote_closed","connectedAt":1}"#.into()).unwrap();
        let done = query(&data_dir, &format!(r#"{{"connection":"{CONNECTION}","protocol":"rdp","user":"DEPLOY","result":"ok"}}"#));
        assert_eq!(done.len(), 1);
        let s = &done[0];
        assert_eq!((s["connectionName"].as_str(), s["loginSource"].as_str(), s["app"].as_str()), (Some("web-01"), Some("inherited"), Some("native-mac")));
        assert_eq!(s["folderPath"][0]["name"], "Customers");
        assert_eq!((s["open"].as_bool(), s["endReason"].as_str(), s["reconnects"].as_u64()), (Some(false), Some("remote_closed"), Some(1)));
        // `connectedAt` before the start is clamped to the start.
        assert_eq!(s["connectedAt"], s["startedAt"]);
        assert!(s["durationMs"].is_u64() && s["endedAt"].is_u64());

        let events: Vec<Value> = serde_json::from_str(&activity_events_json(data_dir.clone(), id).unwrap()).unwrap();
        assert_eq!(events.iter().map(|e| e["kind"].as_str().unwrap()).collect::<Vec<_>>(), ["clipboard", "reconnect"]);
        assert_eq!(events[0]["details"]["password"], "***");
        assert_eq!(events[0]["details"]["bytes"], "12");
        assert!(!stored_text(&data_dir).contains("bridge-secret"), "a secret reached the store");
        assert!(query(&data_dir, r#"{"result":"failed"}"#).is_empty());
    }

    #[test]
    fn bad_input_is_refused_with_a_stable_code() {
        let (_keep, data_dir) = dir();
        let code = |r: FfiResult<String>| r.unwrap_err().code().to_string();
        assert_eq!(code(activity_begin(data_dir.clone(), "not json".into())), "invalid");
        assert_eq!(code(activity_begin(data_dir.clone(), start_json().replace("native-mac", "some-other-app"))), "invalid");
        assert_eq!(code(activity_query_json(data_dir.clone(), r#"{"result":"maybe"}"#.into(), 0, 10)), "invalid");
        assert!(activity_events_json(data_dir.clone(), "not-an-id".into()).is_err());

        let id = activity_begin(data_dir.clone(), start_json()).unwrap();
        let unit = |r: FfiResult<()>| r.unwrap_err().code().to_string();
        assert_eq!(unit(activity_event(data_dir.clone(), id.clone(), "keystrokes".into(), "{}".into())), "invalid");
        assert_eq!(unit(activity_event(data_dir.clone(), id.clone(), "resize".into(), r#"{"size":{"w":1}}"#.into())), "invalid");
        assert_eq!(unit(activity_end(data_dir.clone(), id.clone(), r#"{"endReason":"went_away"}"#.into())), "invalid");
        assert_eq!(unit(activity_end(data_dir.clone(), id.clone(), r#"{"endReason":"failed","transcriptPath":"/logs/a.log","transcriptSha256":"abc"}"#.into())), "invalid");
        activity_end(data_dir.clone(), id.clone(), r#"{"endReason":"failed"}"#.into()).unwrap();
        assert_eq!(unit(activity_end(data_dir.clone(), id, r#"{"endReason":"failed"}"#.into())), "not_found");
        assert_eq!(query(&data_dir, "{}").len(), 1);
    }

    #[test]
    fn an_error_about_bad_input_never_repeats_the_input() {
        const SECRET: &str = "echo-secret-77";
        let (_keep, data_dir) = dir();
        let id = activity_begin(data_dir.clone(), start_json()).unwrap();
        let messages = [
            activity_begin(data_dir.clone(), format!("{SECRET} is not json")).unwrap_err().to_string(),
            activity_begin(data_dir.clone(), start_json().replace("native-mac", SECRET)).unwrap_err().to_string(),
            activity_begin(data_dir.clone(), start_json().replace("3389", &format!("\"{SECRET}\""))).unwrap_err().to_string(),
            activity_query_json(data_dir.clone(), format!(r#"{{"result":"{SECRET}"}}"#), 0, 10).unwrap_err().to_string(),
            activity_events_json(data_dir.clone(), SECRET.into()).unwrap_err().to_string(),
            activity_event(data_dir.clone(), SECRET.into(), "resize".into(), "{}".into()).unwrap_err().to_string(),
            activity_event(data_dir.clone(), id.clone(), SECRET.into(), "{}".into()).unwrap_err().to_string(),
            activity_event(data_dir.clone(), id.clone(), "resize".into(), format!(r#"{{"{SECRET}":{{"a":1}}}}"#)).unwrap_err().to_string(),
            activity_event(data_dir.clone(), id.clone(), "resize".into(), format!("[{SECRET}")).unwrap_err().to_string(),
            activity_end(data_dir.clone(), SECRET.into(), r#"{"endReason":"failed"}"#.into()).unwrap_err().to_string(),
            activity_end(data_dir.clone(), id.clone(), format!(r#"{{"endReason":"{SECRET}"}}"#)).unwrap_err().to_string(),
        ];
        for message in messages {
            assert!(message.starts_with("invalid "), "{message}");
            assert!(!message.contains(SECRET), "the error repeats its input: {message}");
        }
    }

    #[test]
    fn nothing_is_written_while_the_setting_is_off() {
        let (_keep, data_dir) = dir();
        set(&data_dir, ENABLED_SETTING, "false");
        let id = activity_begin(data_dir.clone(), start_json()).unwrap();
        activity_event(data_dir.clone(), id.clone(), "resize".into(), "{}".into()).unwrap();
        activity_end(data_dir.clone(), id, r#"{"endReason":"closed_by_user"}"#.into()).unwrap();
        assert!(!Path::new(&data_dir).join("activity").exists());
        assert!(query(&data_dir, "{}").is_empty());

        set(&data_dir, ENABLED_SETTING, "true");
        activity_begin(data_dir.clone(), start_json()).unwrap();
        assert_eq!(query(&data_dir, "{}").len(), 1);
    }

    #[test]
    fn purge_follows_the_retention_setting_and_a_clean_store_has_no_orphans() {
        let (_keep, data_dir) = dir();
        assert_eq!(activity_purge(data_dir.clone()).unwrap(), 0, "no store yet");
        assert_eq!(activity_close_orphans(data_dir.clone()).unwrap(), 0);
        let id = activity_begin(data_dir.clone(), start_json()).unwrap();
        activity_end(data_dir.clone(), id, r#"{"endReason":"closed_by_user"}"#.into()).unwrap();
        let old = Path::new(&data_dir).join("activity").join("2020-01.jsonl");
        std::fs::write(&old, "").unwrap();

        set(&data_dir, RETENTION_SETTING, "0");
        assert_eq!(activity_purge(data_dir.clone()).unwrap(), 0, "forever");
        assert!(old.exists());
        set(&data_dir, RETENTION_SETTING, "365");
        assert_eq!(activity_purge(data_dir.clone()).unwrap(), 1);
        assert!(!old.exists());
        assert_eq!(query(&data_dir, "{}").len(), 1, "this month's history is kept");
        // A session of this run is not an orphan.
        activity_begin(data_dir.clone(), start_json()).unwrap();
        assert_eq!(activity_close_orphans(data_dir).unwrap(), 0);
    }
}
