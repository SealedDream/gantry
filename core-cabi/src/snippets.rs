//! Command snippets over the C ABI (`bastion_core::snippets`): the same `snippets.json` the Mac
//! and Tauri apps use. Text that looks like a secret is refused by the core. Sending goes
//! through the core so the safety rule lives in one place: a multi-line snippet, or any snippet
//! sent to more than one tab, needs `confirmed` = 1 (the host asks the user first), and each send
//! is written to the audit log with the snippet name and tab count only.
use std::collections::BTreeMap;
use std::ffi::c_char;
use std::path::Path;
use std::ptr::null_mut;

use bastion_core::audit::{Category, Outcome};
use bastion_core::snippets::{Snippet, SnippetStore};
use serde_json::{json, Value};

use crate::session::manager;
use crate::terminal::term;
use crate::{guarded, optional, required, set_ok, to_c, BastionSessionManager, BastionTerminal};

/// Tabs one send may reach (same limit as the Tauri app).
pub const SNIPPET_MAX_TARGETS: usize = 64;
/// [`bastion_snippet_send`]: the snippet is multi-line or goes to several tabs; ask the user,
/// then call again with `confirmed` = 1. Nothing was sent.
pub const SNIPPET_NEEDS_CONFIRM: i32 = -2;

fn store(data_dir: &str) -> Result<SnippetStore, String> {
    SnippetStore::open(SnippetStore::file(Path::new(data_dir))).map_err(|e| e.to_string())
}

fn view(s: &Snippet) -> Value {
    json!({ "id": s.id, "name": s.name, "text": s.text, "multiline": s.is_multiline(), "lines": s.text.trim_end().lines().count() })
}

/// Snippets whose name or text holds every word of `query` (NULL or empty lists all), sorted by
/// name: `[{"id","name","text","multiline","lines"}]`.
///
/// # Safety
/// `data_dir` valid NUL-terminated; `query` NULL or NUL-terminated; `err` NULL or writable.
/// Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_snippets_json(data_dir: *const c_char, query: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let s = store(&required(data_dir, "data_dir")?)?;
        let q = optional(query, "query")?.unwrap_or_default();
        Ok(to_c(Value::Array(s.search(&q).iter().map(view).collect()).to_string()))
    })
}

/// Add (`id` NULL or empty) or replace a snippet. Returns its id; NULL with `*err` when the name
/// is taken, the text is empty, too long or looks like a secret.
///
/// # Safety
/// `data_dir`, `name`, `text` valid NUL-terminated; `id` NULL or NUL-terminated; `err` NULL or
/// writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_snippet_put(data_dir: *const c_char, name: *const c_char, text: *const c_char, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let mut s = store(&required(data_dir, "data_dir")?)?;
        let id = optional(id, "id")?.filter(|i| !i.is_empty());
        let new_id = s.put(&required(name, "name")?, &required(text, "text")?, id.as_deref()).map_err(|e| e.to_string())?;
        Ok(to_c(new_id))
    })
}

/// Delete a snippet. 0 / -1.
///
/// # Safety
/// Strings valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_snippet_remove(data_dir: *const c_char, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        store(&required(data_dir, "data_dir")?)?.remove(&required(id, "id")?).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Type snippet `id` into each of the `count` terminals like a paste (bracketed when the
/// program asked for it). Returns how many tabs received it, [`SNIPPET_NEEDS_CONFIRM`] when a
/// confirmation is needed and `confirmed` is 0, or -1 with `*err`. `m` (NULL allowed) is the
/// session manager whose audit log records the send.
///
/// # Safety
/// `data_dir`, `id` valid NUL-terminated; `terminals` points to `count` live handles; `m` NULL
/// or live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_snippet_send(
    data_dir: *const c_char,
    id: *const c_char,
    terminals: *const *const BastionTerminal,
    count: usize,
    confirmed: i32,
    m: *const BastionSessionManager,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, -1, || {
        if terminals.is_null() || count == 0 || count > SNIPPET_MAX_TARGETS {
            return Err(format!("Send to 1 to {SNIPPET_MAX_TARGETS} tabs."));
        }
        let id = required(id, "id")?;
        let snippet = store(&required(data_dir, "data_dir")?)?.list().into_iter().find(|s| s.id == id).ok_or_else(|| "unknown snippet".to_string())?;
        if (snippet.is_multiline() || count > 1) && confirmed == 0 {
            return Ok(SNIPPET_NEEDS_CONFIRM);
        }
        let targets = std::slice::from_raw_parts(terminals, count).iter().map(|t| term(*t)).collect::<Result<Vec<_>, _>>()?;
        let sent = targets.iter().filter(|t| t.paste(snippet.text.clone()).is_ok()).count();
        if !m.is_null() {
            let details = BTreeMap::from([("tabs".to_string(), sent.to_string()), ("lines".to_string(), snippet.text.lines().count().to_string())]);
            manager(m)?.record_audit(Category::BulkOperation, "snippet.send", Some(&snippet.name), Outcome::Success, details);
        }
        Ok(sent as i32)
    })
}
