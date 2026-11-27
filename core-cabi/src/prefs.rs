//! Settings, keyboard shortcuts and command-palette ranking over the C ABI (ABI 16), forwarding to
//! `core-ffi` (`settings.rs`, `shortcuts.rs`, `palette.rs`) so the WinUI app reads the same registry,
//! files and ranking as the macOS app. Same conventions as the rest of this crate: JSON out,
//! `char **err`, nothing unwinds. Nothing here touches a secret.
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::{PaletteEntryInput, PaletteIndex, SettingsFile, ShortcutsFile};
use serde_json::{json, Value};

use crate::{guarded, optional, required, to_c};

fn links(handled_links: *const c_char) -> Result<Vec<String>, String> {
    // SAFETY: forwarded from the caller's contract (NULL or a valid string).
    match unsafe { optional(handled_links, "handled_links")? } {
        Some(s) => serde_json::from_str(&s).map_err(|e| format!("handled_links: {e}")),
        None => Ok(vec![]),
    }
}

/// Settings categories with at least one visible setting, in sidebar order: `[{id,label,icon}]`.
/// `handled_links` is a JSON array of the `link` targets the host can open (NULL = none); settings
/// that link anywhere else are hidden, and so is a category left empty.
///
/// # Safety
/// `handled_links` NULL or valid NUL-terminated; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_setting_categories_json(handled_links: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out: Vec<Value> = bastion_ffi::setting_categories(links(handled_links)?).into_iter().map(|c| json!({"id": c.id, "label": c.label, "icon": c.icon})).collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Every visible setting: `[{id,category,label,help,kind,options:[{id,label}],min,max,unit,default,link}]`,
/// `kind` = `choice` | `toggle` | `integer` | `link`.
///
/// # Safety
/// As [`bastion_setting_categories_json`].
#[no_mangle]
pub unsafe extern "C" fn bastion_setting_definitions_json(handled_links: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out: Vec<Value> = bastion_ffi::setting_definitions(links(handled_links)?)
            .into_iter()
            .map(|d| {
                json!({"id": d.id, "category": d.category, "label": d.label, "help": d.help, "kind": d.kind,
                       "options": d.options.iter().map(|o| json!({"id": o.id, "label": o.label})).collect::<Vec<_>>(),
                       "min": d.min, "max": d.max, "unit": d.unit, "default": d.default_value, "link": d.link})
            })
            .collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Ids of the settings matching `query` (label, help, keywords, category), best first, as a JSON array.
///
/// # Safety
/// `query` valid NUL-terminated; `handled_links` as above; `err` NULL or writable. Free the result.
#[no_mangle]
pub unsafe extern "C" fn bastion_settings_search_json(query: *const c_char, handled_links: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(json!(bastion_ffi::search_settings(required(query, "query")?, links(handled_links)?)).to_string())))
}

/// Whether the credentials should lock: `value` is the `security.auto-lock` setting, `idle_secs`
/// the time since the last keyboard or mouse input. 1 = lock now.
///
/// # Safety
/// `value` NULL or valid NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn bastion_settings_auto_lock_due(value: *const c_char, idle_secs: u64) -> i32 {
    guarded(null_mut(), 0, || Ok(i32::from(bastion_ffi::auto_lock_due(optional(value, "value")?.unwrap_or_default(), idle_secs))))
}

/// Opaque handle for `settings.json` (values only; definitions come from the registry).
pub struct BastionSettings(SettingsFile);

/// # Safety
/// `s` NULL or a live handle.
pub(crate) unsafe fn settings<'a>(s: *const BastionSettings) -> Result<&'a SettingsFile, String> {
    s.as_ref().map(|s| &s.0).ok_or_else(|| "settings handle is NULL".to_string())
}

/// Open `path` (missing = defaults). A file that does not parse is an error, never silently reset.
///
/// # Safety
/// `path` valid NUL-terminated; `err` NULL or writable. Free with [`bastion_settings_free`].
#[no_mangle]
pub unsafe extern "C" fn bastion_settings_open(path: *const c_char, err: *mut *mut c_char) -> *mut BastionSettings {
    guarded(err, null_mut(), || {
        let f = SettingsFile::open(required(path, "path")?).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionSettings(f))))
    })
}

/// # Safety
/// `s` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_settings_free(s: *mut BastionSettings) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

/// The current value of setting `id` (its default when unset). Free the result.
///
/// # Safety
/// `id` valid NUL-terminated; `s` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_settings_get(s: *const BastionSettings, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(settings(s)?.get(required(id, "id")?).map_err(|e| e.to_string())?)))
}

/// Validate and save one value; an invalid value is refused and nothing is written. 0 / -1.
///
/// # Safety
/// Strings valid NUL-terminated; `s` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_settings_set(s: *const BastionSettings, id: *const c_char, value: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        settings(s)?.set(required(id, "id")?, required(value, "value")?).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Opaque handle for `shortcuts.json` (only the user's changes are stored).
pub struct BastionShortcuts(ShortcutsFile);

/// # Safety
/// `s` NULL or a live handle.
unsafe fn shortcuts<'a>(s: *const BastionShortcuts) -> Result<&'a ShortcutsFile, String> {
    s.as_ref().map(|s| &s.0).ok_or_else(|| "shortcuts handle is NULL".to_string())
}

/// Open `path` (missing = the defaults). Free with [`bastion_shortcuts_free`].
///
/// # Safety
/// `path` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_shortcuts_open(path: *const c_char, err: *mut *mut c_char) -> *mut BastionShortcuts {
    guarded(err, null_mut(), || {
        let f = ShortcutsFile::open(required(path, "path")?).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(BastionShortcuts(f))))
    })
}

/// # Safety
/// `s` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_shortcuts_free(s: *mut BastionShortcuts) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

/// Every command with its chord on `platform` (`macos` | `windows`):
/// `[{id,label,group,groupLabel,chord,defaultChord,isDefault}]`; chords are neutral (`primary+shift+p`),
/// `chord` null = no shortcut. Free the result.
///
/// # Safety
/// `platform` valid NUL-terminated; `s` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_shortcuts_list_json(s: *const BastionShortcuts, platform: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let out: Vec<Value> = shortcuts(s)?
            .list(required(platform, "platform")?)
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|v| json!({"id": v.id, "label": v.label, "group": v.group, "groupLabel": v.group_label, "chord": v.chord, "defaultChord": v.default_chord, "isDefault": v.is_default}))
            .collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// What `chord` would collide with if given to command `id`: `null` (free), `{"commandId":…,"label":…}`
/// (another command, which Replace takes it from) or `{"commandId":null,"label":…}` (reserved by the
/// system; refused). A chord that does not parse is an error. Free the result.
///
/// # Safety
/// Strings valid NUL-terminated; `s` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_shortcuts_conflict_json(s: *const BastionShortcuts, id: *const c_char, chord: *const c_char, platform: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let c = shortcuts(s)?.conflict(required(id, "id")?, required(chord, "chord")?, required(platform, "platform")?).map_err(|e| e.to_string())?;
        Ok(to_c(c.map_or(Value::Null, |c| json!({"commandId": c.command_id, "label": c.label})).to_string()))
    })
}

/// Give command `id` the `chord` (NULL = no shortcut) and save. A chord another command holds is
/// refused unless `replace` != 0, which takes it from that command; a reserved chord is always refused.
/// 0 / -1.
///
/// # Safety
/// Strings valid NUL-terminated (`chord` may be NULL); `s` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_shortcuts_set(s: *const BastionShortcuts, id: *const c_char, chord: *const c_char, platform: *const c_char, replace: i32, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let (id, chord, platform) = (required(id, "id")?, optional(chord, "chord")?, required(platform, "platform")?);
        shortcuts(s)?.set(id, chord, platform, replace != 0).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Restore command `id`'s default (`id` NULL = every command) and save. 0 / -1.
///
/// # Safety
/// `id` NULL or valid NUL-terminated; `s` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_shortcuts_reset(s: *const BastionShortcuts, id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let f = shortcuts(s)?;
        match optional(id, "id")? {
            Some(id) => f.reset(id),
            None => f.reset_all(),
        }
        .map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Commands whose chord a hand-edited file gave to an earlier command too (those chords do nothing),
/// as a JSON array of ids. Free the result.
///
/// # Safety
/// `platform` valid NUL-terminated; `s` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_shortcuts_shadowed_json(s: *const BastionShortcuts, platform: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(json!(shortcuts(s)?.shadowed(required(platform, "platform")?).map_err(|e| e.to_string())?).to_string())))
}

/// Command ids matching `query` by label or group, as a JSON array (the Keyboard page's filter by name;
/// filtering by keys is the host's, on the displayed chords). Free the result.
///
/// # Safety
/// `query` valid NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn bastion_shortcuts_search_json(query: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || Ok(to_c(json!(bastion_ffi::search_shortcuts(required(query, "query")?)).to_string())))
}

/// Opaque command-palette index, built once per opening of the palette.
pub struct BastionPalette(PaletteIndex);

/// Index `entries_json` = `[{kind,title,detail,keywords}]`, `kind` as core/src/palette.rs `EntryKind::parse`.
/// An unknown kind is refused. Free with [`bastion_palette_free`].
///
/// # Safety
/// `entries_json` valid NUL-terminated; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_palette_new(entries_json: *const c_char, err: *mut *mut c_char) -> *mut BastionPalette {
    guarded(err, null_mut(), || {
        let v: Vec<Value> = serde_json::from_str(&required(entries_json, "entries_json")?).map_err(|e| format!("entries_json: {e}"))?;
        let field = |e: &Value, k: &str| e.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
        let entries = v.iter().map(|e| PaletteEntryInput { kind: field(e, "kind"), title: field(e, "title"), detail: field(e, "detail"), keywords: field(e, "keywords") }).collect();
        Ok(Box::into_raw(Box::new(BastionPalette(PaletteIndex::new(entries).map_err(|e| e.to_string())?))))
    })
}

/// # Safety
/// `p` NULL or a live handle, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_palette_free(p: *mut BastionPalette) {
    if !p.is_null() {
        drop(Box::from_raw(p));
    }
}

/// Indexes of the entries matching `query`, best first, at most `limit`, as a JSON array. Free the result.
///
/// # Safety
/// `query` valid NUL-terminated; `p` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_palette_rank_json(p: *const BastionPalette, query: *const c_char, limit: u32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let p = p.as_ref().ok_or_else(|| "palette handle is NULL".to_string())?;
        Ok(to_c(json!(p.0.rank(required(query, "query")?, limit)).to_string()))
    })
}

/// Every library connection as a palette entry (ABI 57), in library order:
/// `[{id,protocol,kind:"connection",title,detail,keywords}]`. Pass the entries to [`bastion_palette_new`]
/// beside the app's own, and connect by `id`. Free the result.
///
/// # Safety
/// `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_palette_connections_json(lib: *const crate::BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        let rows: Vec<Value> = lib
            .palette_connections()
            .map_err(|e| e.to_string())?
            .into_iter()
            .map(|r| json!({ "id": r.id, "protocol": r.protocol, "kind": "connection", "title": r.title, "detail": r.detail, "keywords": r.keywords }))
            .collect();
        Ok(to_c(Value::Array(rows).to_string()))
    })
}
