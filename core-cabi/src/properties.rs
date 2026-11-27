//! Property editor over the C ABI: the core's schema (only settings the core honours), values with
//! where each comes from (own, folder, type default, built-in), and folder/type Default Settings.
//! Same calls as the macOS editor (`core-ffi/src/properties.rs`).
use std::ffi::c_char;
use std::ptr::null_mut;

use bastion_ffi::{PropertyValueView, Library};
use serde_json::{json, Value};

use crate::{guarded, optional, required, to_c, BastionLibrary};

/// # Safety
/// `lib` NULL or a live handle.
unsafe fn library<'a>(lib: *const BastionLibrary) -> Result<&'a Library, String> {
    lib.as_ref().map(|l| &*l.0).ok_or_else(|| "library handle is NULL".to_string())
}

fn values_json(v: Vec<PropertyValueView>) -> String {
    Value::Array(v.into_iter().map(|v| json!({ "key": v.key, "own": v.own, "effective": v.effective, "source": v.source, "from": v.from })).collect()).to_string()
}

/// The editor schema as JSON `[{key,label,category,kind,help,inheritable,options}]`, `kind` = `text` |
/// `port` | `seconds` | `multiline` | `tags` | `choice` | `toggle` (v16; `options` = `[{id,label}]` for `choice`). `protocol` NULL with `defaults_only` 1 gives the folder
/// Default Settings set; a protocol with `defaults_only` 1 that type's Default Settings.
///
/// # Safety
/// `protocol` NULL or valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_property_schema_json(protocol: *const c_char, defaults_only: i32, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let defs = bastion_ffi::property_schema(optional(protocol, "protocol")?, defaults_only != 0).map_err(|e| e.to_string())?;
        let out: Vec<_> = defs
            .into_iter()
            .map(|d| json!({ "key": d.key, "label": d.label, "category": d.category, "kind": d.kind, "help": d.help, "inheritable": d.inheritable,
                "options": d.options.iter().map(|o| json!({ "id": o.id, "label": o.label })).collect::<Vec<_>>() }))
            .collect();
        Ok(to_c(Value::Array(out).to_string()))
    })
}

/// Values for a connection, or a folder's Default Settings, as JSON `[{key,own,effective,source,from}]`;
/// `source` = `own` | `inherited` | `typedefault` | `builtin` | `unset`, `from` names the folder or type.
///
/// # Safety
/// `id` valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_property_values_json(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v = library(lib)?.property_values(required(id, "id")?).map_err(|e| e.to_string())?;
        Ok(to_c(values_json(v)))
    })
}

/// A connection type's Default Settings, same JSON as [`bastion_library_property_values_json`].
///
/// # Safety
/// `protocol` valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_type_default_values_json(lib: *const BastionLibrary, protocol: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v = library(lib)?.type_default_values(required(protocol, "protocol")?).map_err(|e| e.to_string())?;
        Ok(to_c(values_json(v)))
    })
}

/// Set a property on a connection or folder; `value` NULL or blank resets it to inherited.
/// Invalid values (port 0, keep-alive out of range, empty name) are refused with a message.
/// Returns 0 or -1. Call `bastion_library_save` afterwards.
///
/// # Safety
/// Strings valid NUL-terminated (`value` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_property(lib: *const BastionLibrary, id: *const c_char, key: *const c_char, value: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let (id, key, value) = (required(id, "id")?, required(key, "key")?, optional(value, "value")?);
        library(lib)?.set_property(id, key, value).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// "Allow for this host" after `CONNECT_NO_COMMON_ALGORITHM`: `kind` and `names_json` (a JSON
/// string array) exactly as that outcome's JSON gave them (`kind`, `weakAllowable`). Only weak
/// algorithms Bastion implements are accepted; policy is still checked on connect. Returns 0 or -1.
///
/// # Safety
/// Strings valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_allow_weak_algorithms(lib: *const BastionLibrary, id: *const c_char, kind: *const c_char, names_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let (id, kind, names) = (required(id, "id")?, required(kind, "kind")?, required(names_json, "names_json")?);
        let names: Vec<String> = serde_json::from_str(&names).map_err(|e| format!("names_json: {e}"))?;
        library(lib)?.allow_weak_algorithms(id, kind, names).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Preview for Properties → Advanced → Algorithms. `settings_json` is the `ssh_algorithms`
/// property value (NULL or blank for the defaults). Returns JSON `{kex, ciphers, macs, hostKeys,
/// compression, weakEnabled, warnings, error, forbidWeak, catalogue: {kind: [{name, weak}]},
/// unsupported: [{kind, name}]}`; `error` is set (lists empty) when the settings are unusable.
///
/// # Safety
/// `settings_json` NULL or valid NUL-terminated; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_algorithms_preview_json(settings_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    use bastion_core::algorithms::{self as algo, AlgoKind, AlgorithmSettings};
    guarded(err, null_mut(), || {
        let settings: AlgorithmSettings = match optional(settings_json, "settings_json")?.filter(|s| !s.trim().is_empty()) {
            Some(s) => serde_json::from_str(&s).map_err(|e| format!("settings_json: {e}"))?,
            None => AlgorithmSettings::default(),
        };
        let forbid = bastion_ffi::policy_state().forbid_weak_ssh_algorithms;
        let (resolved, error) = match settings.resolve(forbid) {
            Ok(r) => (Some(r), None),
            Err(e) => (None, Some(e.to_string())),
        };
        let kinds = [AlgoKind::Kex, AlgoKind::Cipher, AlgoKind::Mac, AlgoKind::HostKey];
        let catalogue: serde_json::Map<String, Value> = kinds
            .iter()
            .map(|k| (serde_json::to_value(k).unwrap().as_str().unwrap().to_string(), Value::Array(algo::catalogue(*k).into_iter().map(|n| json!({ "weak": algo::is_weak(*k, &n), "name": n })).collect())))
            .collect();
        let r = resolved.unwrap_or_else(|| algo::ResolvedAlgorithms { kex: vec![], ciphers: vec![], macs: vec![], host_keys: vec![], compression: vec![], weak_enabled: vec![], warnings: vec![] });
        Ok(to_c(
            json!({
                "kex": r.kex, "ciphers": r.ciphers, "macs": r.macs, "hostKeys": r.host_keys, "compression": r.compression,
                "weakEnabled": r.weak_enabled, "warnings": r.warnings, "error": error, "forbidWeak": forbid,
                "catalogue": catalogue,
                "unsupported": algo::UNSUPPORTED.iter().map(|(k, n)| json!({ "kind": k, "name": n })).collect::<Vec<_>>(),
            })
            .to_string(),
        ))
    })
}

/// Set one of a connection type's Default Settings; `value` NULL or blank clears it. Returns 0 or -1.
///
/// # Safety
/// As [`bastion_library_set_property`].
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_type_default(lib: *const BastionLibrary, protocol: *const c_char, key: *const c_char, value: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let (p, key, value) = (required(protocol, "protocol")?, required(key, "key")?, optional(value, "value")?);
        library(lib)?.set_type_default(p, key, value).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Connections a change to a default would affect, as a JSON string array: a folder's default
/// (`folder_id`) or a type's (`folder_id` NULL, `protocol` set).
///
/// # Safety
/// Strings valid NUL-terminated (`folder_id`, `protocol` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_affected_by_default_json(lib: *const BastionLibrary, folder_id: *const c_char, protocol: *const c_char, key: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v = library(lib)?
            .affected_by_default(optional(folder_id, "folder id")?, optional(protocol, "protocol")?, required(key, "key")?)
            .map_err(|e| e.to_string())?;
        Ok(to_c(json!(v).to_string()))
    })
}

/// Effective per-host colour of a connection as JSON `{accent,text,tint,named,privileged,fgLight,bgLight,fgDark,bgDark}` (`#rrggbb`, `#000000` or
/// `#ffffff` for text on the accent, `#rrggbbaa` background tint), or `null` when none is set on the
/// connection or a parent folder. Set it with `bastion_library_set_property(.., "host_color", ..)`
/// (a preset name or `#rgb`/`#rrggbb`). Additive in ABI 66.
///
/// # Safety
/// `id` valid NUL-terminated; `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_host_color_json(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let c = library(lib)?.host_color(required(id, "id")?).map_err(|e| e.to_string())?;
        let v = c.map_or(Value::Null, |c| host_color_json(&c));
        Ok(to_c(v.to_string()))
    })
}

/// Every coloured connection's effective colour in one pass, as JSON `{"<id>": {accent,text,tint}}`
/// (connections without a colour are left out). `bastion_library_host_color_json` resolves one
/// connection with a walk of the whole tree, so asking it for each row of a 5,000-connection tree is
/// quadratic. Additive in ABI 125.
///
/// # Safety
/// `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_host_colors_json(lib: *const BastionLibrary, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let all = library(lib)?.host_colors().map_err(|e| e.to_string())?;
        let map: serde_json::Map<String, Value> =
            all.into_iter().map(|e| (e.id, host_color_json(&e.color))).collect();
        Ok(to_c(Value::Object(map).to_string()))
    })
}

/// Whether "Log session output" (`session_log`) is on for a connection, after folder and type
/// inheritance: 1 on, 0 off, -1 on failure (unknown id, NULL handle). Hosts start a session log
/// when a terminal tab for the connection opens or reconnects (LOG-01).
///
/// # Safety
/// `connection_id` valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_session_log(lib: *const BastionLibrary, connection_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let id = required(connection_id, "connection_id")?;
        let on = library(lib)?.session_log(id).map_err(|e| e.to_string())?;
        Ok(i32::from(on))
    })
}

/// Whether "Hide tab preview" (`no_preview`) is on for a connection, after folder and type
/// inheritance: 1 hide, 0 show, -1 on failure (unknown id, NULL handle). Hosts ask before drawing a
/// tab preview or an Overview tile image (B11).
///
/// # Safety
/// `connection_id` valid NUL-terminated; `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_no_preview(lib: *const BastionLibrary, connection_id: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let id = required(connection_id, "connection_id")?;
        let on = library(lib)?.no_preview(id).map_err(|e| e.to_string())?;
        Ok(i32::from(on))
    })
}

/// A connection's custom properties as JSON `[{name,value}]` (`user.*` metadata; 121).
///
/// # Safety
/// `id` valid NUL-terminated; `lib` live; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_custom_properties_json(lib: *const BastionLibrary, id: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let v = library(lib)?.custom_properties(required(id, "id")?).map_err(|e| e.to_string())?;
        Ok(to_c(Value::Array(v.into_iter().map(|p| json!({ "name": p.name, "value": p.value })).collect()).to_string()))
    })
}

/// Set (`value` non-NULL) or remove (`value` NULL) one custom property. Names that look secret,
/// bad names and oversize values are refused with a message. Returns 0 or -1. Call
/// `bastion_library_save` afterwards (121).
///
/// # Safety
/// Strings valid NUL-terminated (`value` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_custom_property(lib: *const BastionLibrary, id: *const c_char, name: *const c_char, value: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let (id, name, value) = (required(id, "id")?, required(name, "name")?, optional(value, "value")?);
        library(lib)?.set_custom_property(id, name, value).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// The icon names an item may carry, as a JSON string array (122).
///
/// # Safety
/// Always safe; free with `bastion_string_free`.
#[no_mangle]
pub extern "C" fn bastion_connection_icon_names_json() -> *mut c_char {
    to_c(Value::from(bastion_core::model::ICONS.to_vec()).to_string())
}

/// Set (`icon` non-NULL) or clear (`icon` NULL or blank) a connection's icon; unknown names are
/// refused. Returns 0 or -1. Call `bastion_library_save` afterwards (122).
///
/// # Safety
/// Strings valid NUL-terminated (`icon` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_set_icon(lib: *const BastionLibrary, id: *const c_char, icon: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let (id, icon) = (required(id, "id")?, optional(icon, "icon")?);
        let icon = icon.map(|i| i.trim().to_string()).filter(|i| !i.is_empty());
        library(lib)?.set_icon(id, icon).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// `{accent,text,tint,named,privileged,fgLight,bgLight,fgDark,bgDark}` (the last six added by UI-01).
fn host_color_json(c: &bastion_ffi::HostColorView) -> Value {
    json!({ "accent": c.accent, "text": c.text, "tint": c.tint, "named": c.named, "privileged": c.privileged,
            "fgLight": c.fg_light, "bgLight": c.bg_light, "fgDark": c.fg_dark, "bgDark": c.bg_dark })
}
