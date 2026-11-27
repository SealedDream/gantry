//! Terminal themes over the C ABI (ABI 88): the bundled set plus the user's own themes in
//! `<data dir>/terminal-themes.json`, and applying any of them to a terminal by id. A thin JSON
//! layer over core-ffi's `ThemeLibrary`, so Windows gets the same rules as macOS: bundled themes
//! are read-only, colours are 24-bit, names are unique, a damaged file is an error.
//!
//! Theme JSON: `{"id","name","bundled","source","license","foreground","background","ansi":[16],
//! "contrast"}` with colours as `"#rrggbb"`. `contrast` is WCAG foreground-on-background; under 4.5
//! is hard to read.
use std::ffi::c_char;

use bastion_ffi::{TerminalThemeView, ThemeLibrary};
use serde_json::{json, Value};

use crate::terminal::BastionTerminal;
use crate::{guarded, required, set_ok, to_c};

/// Contrast under which a saved theme gets a readability warning (WCAG AA for body text).
const MIN_CONTRAST: f64 = 4.5;

fn library(dir: *const c_char) -> Result<std::sync::Arc<ThemeLibrary>, String> {
    // SAFETY: callers pass the C argument through unchanged; `required` checks NULL and UTF-8.
    let dir = unsafe { required(dir, "data_dir")? };
    ThemeLibrary::open(dir).map_err(|e| e.to_string())
}

fn hex(c: u32) -> String {
    format!("#{c:06x}")
}

fn parse_hex(v: &Value, what: &str) -> Result<u32, String> {
    let s = v.as_str().ok_or_else(|| format!("{what} must be a \"#rrggbb\" string"))?;
    let digits = s.strip_prefix('#').filter(|d| d.len() == 6 && d.chars().all(|c| c.is_ascii_hexdigit()));
    digits.and_then(|d| u32::from_str_radix(d, 16).ok()).ok_or_else(|| format!("{what} `{s}` is not a \"#rrggbb\" colour"))
}

fn to_json(v: &TerminalThemeView) -> Value {
    json!({
        "id": v.id, "name": v.name, "bundled": v.bundled, "source": v.source, "license": v.license,
        "foreground": hex(v.foreground), "background": hex(v.background),
        "ansi": v.ansi.iter().map(|c| hex(*c)).collect::<Vec<_>>(),
        "contrast": (v.contrast * 100.0).round() / 100.0,
    })
}

fn from_json(text: &str) -> Result<TerminalThemeView, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("theme JSON: {e}"))?;
    let field = |k: &str| v.get(k).ok_or_else(|| format!("theme JSON needs `{k}`"));
    let ansi = field("ansi")?.as_array().filter(|a| a.len() == 16).ok_or("`ansi` must hold exactly 16 colours")?;
    Ok(TerminalThemeView {
        id: field("id")?.as_str().ok_or("`id` must be a string")?.to_string(),
        name: field("name")?.as_str().ok_or("`name` must be a string")?.to_string(),
        bundled: false,
        source: String::new(),
        license: String::new(),
        foreground: parse_hex(field("foreground")?, "foreground")?,
        background: parse_hex(field("background")?, "background")?,
        ansi: ansi.iter().enumerate().map(|(i, c)| parse_hex(c, &format!("ansi[{i}]"))).collect::<Result<_, _>>()?,
        contrast: 0.0,
    })
}

/// Every theme as a JSON array: bundled first (display order), then the user's by name.
/// Free with `bastion_string_free`; NULL on error.
///
/// # Safety
/// `data_dir` NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_termthemes_list_json(data_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let all: Vec<Value> = library(data_dir)?.list().iter().map(to_json).collect();
        Ok(to_c(Value::Array(all).to_string()))
    })
}

/// Copy theme `source_id` (bundled or the user's) into a new editable theme named "<name> copy"
/// and save it. Returns the new theme's JSON; NULL on error (unknown id, 200 themes already).
///
/// # Safety
/// Strings NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_termthemes_duplicate(data_dir: *const c_char, source_id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let id = required(source_id, "source_id")?;
        let t = library(data_dir)?.duplicate(id).map_err(|e| e.to_string())?;
        Ok(to_c(to_json(&t).to_string()))
    })
}

/// Save an edited user theme (`id` from duplicate; bundled ids are refused, as are bad colours,
/// empty or taken names). Returns `{"warning": null | "<text>"}`, a warning when the text is
/// hard to read on the background. NULL on error.
///
/// # Safety
/// Strings NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_termthemes_put(data_dir: *const c_char, theme_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let theme = from_json(&required(theme_json, "theme_json")?)?;
        let ratio = bastion_core::termthemes::contrast(theme.foreground, theme.background);
        library(data_dir)?.save(theme).map_err(|e| e.to_string())?;
        let warning = (ratio < MIN_CONTRAST).then(|| format!("Text contrast is {ratio:.1}:1; at least {MIN_CONTRAST}:1 is easier to read."));
        Ok(to_c(json!({ "warning": warning }).to_string()))
    })
}

/// Delete a user theme. 0 / -1 (bundled or unknown id).
///
/// # Safety
/// Strings NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_termthemes_remove(data_dir: *const c_char, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let id = required(id, "id")?;
        library(data_dir)?.remove(id).map_err(|e| e.to_string())?;
        set_ok()
    })
}

/// Apply theme `id` (bundled or the user's, e.g. a connection's `terminal_theme`) to terminal `t`.
/// An id that no longer exists (a deleted theme) falls back to Bastion Dark, as on macOS. 0 / -1.
///
/// # Safety
/// `t` live; strings NUL-terminated UTF-8; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_terminal_set_theme_in(t: *const BastionTerminal, data_dir: *const c_char, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let id = required(id, "id")?;
        let terminal = t.as_ref().ok_or("terminal handle is NULL")?.arc();
        library(data_dir)?.apply(id, terminal);
        set_ok()
    })
}

/// Window colours for a terminal theme (UI-06, ABI 143) as JSON: `{"activeTab","tabStrip","toolbar","sidebar",
/// "separator","text","secondaryText"}` as `"#rrggbb"`, plus `"isDark"` and `"accentUsable"` (accent reaches 3:1 on
/// every surface). Colours in are `0xRRGGBB`; `increased_contrast` != 0 uses the 7:1 floor. Free with
/// `bastion_string_free`. Never fails. Windows apps skip the feature entirely in high-contrast mode.
#[no_mangle]
pub extern "C" fn bastion_termtheme_window_tones(background: u32, foreground: u32, accent: u32, increased_contrast: i32) -> *mut c_char {
    to_c(window_tones_json(background, foreground, accent, increased_contrast != 0).to_string())
}

pub(crate) fn window_tones_json(background: u32, foreground: u32, accent: u32, increased_contrast: bool) -> Value {
    let t = bastion_core::windowtones::window_tones(background, foreground, increased_contrast);
    json!({
        "activeTab": hex(t.active_tab), "tabStrip": hex(t.tab_strip), "toolbar": hex(t.toolbar),
        "sidebar": hex(t.sidebar), "separator": hex(t.separator), "text": hex(t.text),
        "secondaryText": hex(t.secondary_text), "isDark": t.is_dark,
        "accentUsable": bastion_core::windowtones::accent_usable(accent, &t),
    })
}

#[cfg(test)]
mod window_tones_tests {
    #[test]
    fn json_has_every_field_as_hex() {
        let v = super::window_tones_json(0x1E1E2E, 0xCDD6F4, 0x2E6BFF, false);
        for k in ["activeTab", "tabStrip", "toolbar", "sidebar", "separator", "text", "secondaryText"] {
            let s = v[k].as_str().unwrap();
            assert!(s.len() == 7 && s.starts_with('#'), "{k} = {s}");
        }
        assert_eq!(v["isDark"], true);
        assert_eq!(v["text"], "#cdd6f4");
        assert!(v["accentUsable"].is_boolean());
    }
}
