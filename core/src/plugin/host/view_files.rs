//! `clipboard.write-text` and `files.save` (PG-LIVE): the plugin asks, the app does the visible part,
//! the core keeps the rules. Both need their grant and a user action in the view within the last
//! [`STAMP_WINDOW`] (one call per action), so a plugin cannot copy or save on its own.
//!
//! Updates to the app:
//! - `{"type":"clipboard","text"}`: the app puts the text on the clipboard.
//! - `{"type":"save-request","request":n,"name","bytes"}`: the app shows its save panel with `name`
//!   suggested (a file name, never a path).
//!
//! The app answers a save with `{"type":"save","request":n,"path":"/absolute/path"}`, or with
//! `"path":null` when the user closed the panel. The core writes the file; one save at a time.

use std::path::Path;
use std::time::Instant;

use serde_json::{json, Value as Json};

use super::{as_str, record, variant, AppEvent, Dispatch};
use crate::plugin::broker::grants::Call;
use crate::plugin::broker::open::STAMP_WINDOW;
use crate::plugin::broker::Failure;
use crate::plugin::host::proto::Value;

/// The most text one copy puts on the clipboard.
pub(super) const MAX_CLIPBOARD_BYTES: usize = 8 * 1024 * 1024;
/// The most bytes one save writes.
pub(super) const MAX_SAVE_BYTES: usize = 256 * 1024 * 1024;
/// The longest suggested file name.
const MAX_NAME_CHARS: usize = 120;

/// A save waiting for the user's panel.
pub(super) struct PendingSave {
    request: u32,
    data: Vec<u8>,
}

fn none() -> Value {
    Value::Variant("none".into(), None)
}

fn not_asked() -> Failure {
    Failure::Denied(format!("only right after the user asks (within {} s)", STAMP_WINDOW.as_secs()))
}

/// The suggested name as a plain file name: no folders, no control characters, not empty.
pub(super) fn file_name(suggested: &str) -> String {
    let last = suggested.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = last.chars().filter(|c| !c.is_control() && *c != ':').take(MAX_NAME_CHARS).collect();
    let clean = clean.trim().trim_start_matches('.').to_string();
    if clean.is_empty() { "export".into() } else { clean }
}

impl Dispatch {
    pub(super) fn clipboard_write(&mut self, args: &[Value]) -> Result<Value, Failure> {
        self.grants.check(Call::ClipboardWrite)?;
        if self.sidebar {
            return Err(Failure::Denied("no clipboard from the library sidebar".into()));
        }
        let text = as_str(args.first()).ok_or_else(|| Failure::Invalid("the text is missing".into()))?;
        if text.len() > MAX_CLIPBOARD_BYTES {
            return Err(Failure::Invalid("too much text to copy".into()));
        }
        if !self.open.stamp.take(Instant::now()) {
            return Err(not_asked());
        }
        self.push("clipboard", json!({ "text": text }));
        Ok(none())
    }

    /// Shows the app's save panel. An error is the reply; on success the reply waits for the panel.
    pub(super) fn file_save(&mut self, request: u32, args: &[Value]) -> Result<(), Failure> {
        self.grants.check(Call::FileSave)?;
        if self.sidebar {
            return Err(Failure::Denied("no save panel from the library sidebar".into()));
        }
        let name = file_name(as_str(args.first()).unwrap_or(""));
        let Some(Value::Bytes(data)) = args.get(1) else { return Err(Failure::Invalid("the data is missing".into())) };
        if data.len() > MAX_SAVE_BYTES {
            return Err(Failure::Invalid("too much data to save".into()));
        }
        if self.pending_save.is_some() {
            return Err(Failure::Denied("a save panel is already open".into()));
        }
        if !self.open.stamp.take(Instant::now()) {
            return Err(not_asked());
        }
        let bytes = data.len();
        self.pending_save = Some(PendingSave { request, data: data.clone() });
        self.push("save-request", json!({ "request": request, "name": name, "bytes": bytes }));
        Ok(())
    }

    /// The user's answer to the save panel. An answer to a request the core did not ask is ignored.
    pub(super) fn save_answer(&mut self, request: u32, path: Option<String>) {
        let Some(pending) = self.pending_save.take_if(|p| p.request == request) else { return };
        let Some(path) = path else {
            // The WIT `failure.cancelled`: the broker's `Failure` has no such case (it is never a refusal).
            let cancelled = Value::Result(Err(Some(Box::new(Value::Variant("cancelled".into(), None)))));
            self.replies.push_back((variant("reply", record(vec![("request", Value::U32(request)), ("outcome", cancelled)])), None));
            return;
        };
        let outcome = if Path::new(&path).is_absolute() {
            std::fs::write(&path, &pending.data).map(|_| none()).map_err(|e| Failure::Io(format!("The file was not saved ({}).", e.kind())))
        } else {
            Err(Failure::Invalid("the save path is not absolute".into()))
        };
        self.reply_later(request, outcome);
    }
}

/// `{"type":"save","request":n,"path":…|null}`.
pub(super) fn answer_from_json(j: &Json) -> Result<AppEvent, Failure> {
    let request = j.get("request").and_then(Json::as_u64).and_then(|n| u32::try_from(n).ok()).ok_or_else(|| Failure::Invalid("`request` is missing".into()))?;
    let path = match j.get("path") {
        None | Some(Json::Null) => None,
        Some(Json::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => return Err(Failure::Invalid("`path` must be text or null".into())),
    };
    Ok(AppEvent::SaveAnswer { request, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suggested_names_become_plain_file_names() {
        assert_eq!(file_name("results.csv"), "results.csv");
        assert_eq!(file_name("../../etc/passwd"), "passwd");
        assert_eq!(file_name("C:\\Windows\\x.csv"), "x.csv");
        assert_eq!(file_name(".hidden"), "hidden");
        assert_eq!(file_name(""), "export");
        assert_eq!(file_name("a\u{0}b:c.csv"), "abc.csv");
        assert_eq!(file_name(&"x".repeat(500)).len(), MAX_NAME_CHARS);
    }

    #[test]
    fn save_answers_parse() {
        assert!(matches!(answer_from_json(&json!({"type":"save","request":4,"path":"/tmp/a.csv"})).unwrap(), AppEvent::SaveAnswer { request: 4, path: Some(_) }));
        assert!(matches!(answer_from_json(&json!({"type":"save","request":4,"path":null})).unwrap(), AppEvent::SaveAnswer { request: 4, path: None }));
        assert!(answer_from_json(&json!({"type":"save","request":4,"path":3})).is_err());
        assert!(answer_from_json(&json!({"type":"save"})).is_err());
    }
}
