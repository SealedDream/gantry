//! PLUG-06c: the code editor's tokenizer and completions for Native Windows, over
//! `bastion_ffi::highlight`. Token offsets are UTF-16 units, as WinUI counts. An editor keeps
//! each line's `endState` and passes it with the line below (null or `""` for the first line).
use std::os::raw::c_char;

use bastion_ffi::{completion_context, completions_rank, highlight_line, highlight_text, CompletionContextView, CompletionItem, HighlightSpans, HighlightToken};
use serde_json::{json, Value};

use crate::{guarded, optional, required, to_c};

fn spans_json(s: HighlightSpans) -> Value {
    let HighlightSpans { tokens, end_state } = s;
    let tokens: Vec<Value> = tokens
        .into_iter()
        .map(|t| {
            let HighlightToken { kind, utf16_start, utf16_len, start, len } = t;
            json!({ "kind": kind, "utf16Start": utf16_start, "utf16Len": utf16_len, "start": start, "len": len })
        })
        .collect();
    json!({ "tokens": tokens, "endState": end_state })
}

/// One line (no line break) of `language` (`postgresql`, `sql`; any other is plain text), after the
/// line whose `endState` is `state`: `{tokens:[{kind,utf16Start,utf16Len,start,len}], endState}`. Kinds:
/// keyword, identifier, quoted-identifier, string, number, comment, operator, punctuation, parameter,
/// type, function, text, error. On a bad argument returns null and sets `err`. Free the result.
///
/// # Safety
/// `language` and `line` are NUL-terminated UTF-8; `state` is null or NUL-terminated UTF-8; `err`
/// is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_highlight_line_json(language: *const c_char, line: *const c_char, state: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let language = required(language, "language")?;
        let line = required(line, "line")?;
        let state = optional(state, "state")?.unwrap_or_default();
        Ok(to_c(spans_json(highlight_line(language, line, state)).to_string()))
    })
}

/// A whole text, as [`bastion_highlight_line_json`] with offsets from the text's start. For small texts.
///
/// # Safety
/// `language` and `text` are NUL-terminated UTF-8; `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_highlight_text_json(language: *const c_char, text: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let language = required(language, "language")?;
        let text = required(text, "text")?;
        Ok(to_c(spans_json(highlight_text(language, text)).to_string()))
    })
}

/// At cursor `cursor_utf16` in `text`: `{ask, prefix, replaceUtf16Start, replaceUtf16Len, charOffset}`.
/// Send the plugin a `completions` event with `offset` = `charOffset` only when `ask` is true. Free it.
///
/// # Safety
/// `language` and `text` are NUL-terminated UTF-8; `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_completion_context_json(language: *const c_char, text: *const c_char, cursor_utf16: u64, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let language = required(language, "language")?;
        let text = required(text, "text")?;
        let CompletionContextView { ask, prefix, replace_utf16_start, replace_utf16_len, char_offset } = completion_context(language, text, cursor_utf16);
        Ok(to_c(json!({ "ask": ask, "prefix": prefix, "replaceUtf16Start": replace_utf16_start, "replaceUtf16Len": replace_utf16_len, "charOffset": char_offset }).to_string()))
    })
}

/// `items_json` (the `[{label, insert, detail}]` of a `provide-completions` update) filtered and ordered
/// against `prefix`, at most 200, as the same JSON array. On a bad argument returns null and sets `err`.
///
/// # Safety
/// `items_json` and `prefix` are NUL-terminated UTF-8; `err` is null or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_completions_rank_json(items_json: *const c_char, prefix: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let items: Value = serde_json::from_str(&required(items_json, "items_json")?).map_err(|e| format!("items_json: {e}"))?;
        let items = items.as_array().ok_or("items_json: not an array")?;
        let field = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        let items = items.iter().map(|v| CompletionItem { label: field(v, "label"), insert: field(v, "insert"), detail: field(v, "detail") }).collect();
        let ranked: Vec<Value> = completions_rank(items, required(prefix, "prefix")?).into_iter().map(|c| json!({ "label": c.label, "insert": c.insert, "detail": c.detail })).collect();
        Ok(to_c(Value::Array(ranked).to_string()))
    })
}
