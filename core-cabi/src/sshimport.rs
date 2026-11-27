//! OpenSSH config import over the C ABI: the same read-only scan and deduplicating import the
//! macOS app uses (`core::sshconfig` / `core::sshworkflow`). Nothing in a config is executed.
use std::ffi::c_char;
use std::ptr::null_mut;

use serde_json::json;

use crate::{guarded, library, optional, required, to_c, BastionLibrary};

/// # Safety
/// `p` NULL or a valid NUL-terminated string.
unsafe fn extra(p: *const c_char) -> Result<Vec<String>, String> {
    Ok(optional(p, "extra file")?.into_iter().collect())
}

/// Scan `root` (normally `%USERPROFILE%\.ssh`: `config`, its `Include`s and `config.d\`) plus an
/// optional extra file such as `C:\ProgramData\ssh\ssh_config` (NULL to skip; a missing file is
/// ignored). Returns JSON `{hosts:[{alias,hostname,user,port,group,sourceFile,identity,proxyJump,
/// flags,placeholders}],files:[…],warnings:[…]}`.
///
/// # Safety
/// Strings valid NUL-terminated (`extra_file` may be NULL); `err` NULL or writable. Free the
/// result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_ssh_scan_json(root: *const c_char, extra_file: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let scan = bastion_ffi::scan_ssh_config_with(required(root, "root")?, extra(extra_file)?);
        let hosts: Vec<_> = scan
            .hosts
            .iter()
            .map(|h| {
                json!({
                    "alias": h.alias, "hostname": h.hostname, "user": h.user, "port": h.port, "group": h.group,
                    "sourceFile": h.source_file, "identity": h.identity, "proxyJump": h.proxy_jump,
                    "flags": h.flags, "placeholders": h.placeholders,
                })
            })
            .collect();
        Ok(to_c(json!({ "hosts": hosts, "files": scan.files, "warnings": scan.warnings }).to_string()))
    })
}

/// Import the hosts whose `identity` is in `identities_json` (a JSON string array) from the same
/// sources as [`bastion_ssh_scan_json`], one folder per group. Hosts already in the library are
/// skipped. Returns the number imported, or -1 with `*err` set. Call `bastion_library_save` after.
///
/// # Safety
/// Strings valid NUL-terminated (`extra_file` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_import_ssh_hosts(
    lib: *const BastionLibrary,
    root: *const c_char,
    extra_file: *const c_char,
    identities_json: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, -1, || {
        let ids: Vec<String> = serde_json::from_str(&required(identities_json, "identities")?).map_err(|_| "identities must be a JSON array of strings".to_string())?;
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        let n = lib.import_ssh_hosts_with(required(root, "root")?, extra(extra_file)?, ids).map_err(|e| e.to_string())?;
        Ok(n as i32)
    })
}

/// Import-preview rows for every `LocalForward`/`RemoteForward`/`DynamicForward` of the hosts in
/// the same sources as [`bastion_ssh_scan_json`]. `chosen_json` (NULL = none) is the JSON array of
/// ticked row keys in tick order. Returns JSON `[{key,hostIdentity,hostAlias,kind,line,
/// description,explain,warning,blocked}]`; `blocked` non-empty = cannot be imported. Creates nothing.
///
/// # Safety
/// Strings valid NUL-terminated (`extra_file`, `chosen_json` may be NULL); `lib` live; `err` NULL
/// or writable. Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_ssh_forwards_json(
    lib: *const BastionLibrary,
    root: *const c_char,
    extra_file: *const c_char,
    chosen_json: *const c_char,
    err: *mut *mut c_char,
) -> *mut c_char {
    guarded(err, null_mut(), || {
        let chosen = keys(optional(chosen_json, "chosen")?)?;
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        let rows: Vec<_> = lib
            .ssh_forward_preview_with(required(root, "root")?, extra(extra_file)?, chosen)
            .into_iter()
            .map(|r| {
                json!({ "key": r.key, "hostIdentity": r.host_identity, "hostAlias": r.host_alias, "kind": r.kind,
                        "line": r.line, "description": r.description, "explain": r.explain, "warning": r.warning, "blocked": r.blocked })
            })
            .collect();
        Ok(to_c(serde_json::Value::from(rows).to_string()))
    })
}

/// Create auto-starting tunnels for the ticked forward rows (`keys_json`, a JSON string array).
/// Import the hosts first; rows that are blocked now are skipped. Returns the number created, or
/// -1 with `*err` set. Call `bastion_library_save` after.
///
/// # Safety
/// Strings valid NUL-terminated (`extra_file` may be NULL); `lib` live; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_import_ssh_forwards(
    lib: *const BastionLibrary,
    root: *const c_char,
    extra_file: *const c_char,
    keys_json: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    guarded(err, -1, || {
        let ks = keys(Some(required(keys_json, "keys")?))?;
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        let n = lib.import_ssh_forwards_with(required(root, "root")?, extra(extra_file)?, ks).map_err(|e| e.to_string())?;
        Ok(n as i32)
    })
}

fn keys(s: Option<String>) -> Result<Vec<String>, String> {
    s.map(|s| serde_json::from_str(&s).map_err(|_| "keys must be a JSON array of strings".to_string())).transpose().map(Option::unwrap_or_default)
}

/// Write the library's SSH connections (`ids_json` NULL = all, else a JSON array of connection or
/// folder ids) to `path` as an OpenSSH `ssh_config` (owner-only, atomic). Returns JSON
/// `{exported, skipped:["name: reason", …]}`; values that could inject directives are skipped.
///
/// # Safety
/// `lib` live; strings valid NUL-terminated (`ids_json` may be NULL); `err` NULL or writable.
/// Free the result with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_export_ssh_config_json(lib: *const BastionLibrary, path: *const c_char, ids_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let ids = optional(ids_json, "ids")?
            .map(|s| serde_json::from_str::<Vec<String>>(&s).map_err(|_| "ids must be a JSON array of strings".to_string()))
            .transpose()?;
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        let v = lib.export_ssh_config(required(path, "path")?, ids).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "exported": v.exported, "skipped": v.skipped }).to_string()))
    })
}

/// Parse an optional JSON array of folder/connection ids (NULL = everything).
///
/// # Safety
/// `ids_json` NULL or a valid NUL-terminated string.
unsafe fn selection(ids_json: *const c_char) -> Result<Option<Vec<String>>, String> {
    optional(ids_json, "ids")?
        .map(|s| serde_json::from_str::<Vec<String>>(&s).map_err(|_| "ids must be a JSON array of strings".to_string()))
        .transpose()
}

/// What a portable `bastion-export` v1 of `ids_json` (NULL = everything) would contain; nothing is
/// written. Returns JSON `{folders, connections, credentialRefs, strippedFields:[…]}`. ABI 86.
///
/// # Safety
/// `lib` live; `ids_json` NULL or valid; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_export_preview_json(lib: *const BastionLibrary, ids_json: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, null_mut(), || {
        let ids = selection(ids_json)?;
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        let p = lib.export_preview(ids).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "folders": p.folders, "connections": p.connections, "credentialRefs": p.credential_refs, "strippedFields": p.stripped_fields }).to_string()))
    })
}

/// Write the confirmed, secret-free `bastion-export` v1 of `ids_json` (NULL = everything) to
/// `path` (atomic, owner-only). Returns 0, or -1 with `*err` set. ABI 86.
///
/// # Safety
/// `lib` live; strings valid (`ids_json` may be NULL); `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_export_portable(lib: *const BastionLibrary, path: *const c_char, ids_json: *const c_char, err: *mut *mut c_char) -> i32 {
    guarded(err, -1, || {
        let ids = selection(ids_json)?;
        let lib = lib.as_ref().map(|l| &l.0).ok_or_else(|| "library handle is NULL".to_string())?;
        lib.export_to(required(path, "path")?, ids).map_err(|e| e.to_string())?;
        Ok(0)
    })
}

/// Import a connection file into a new top-level folder `Imported <file name>`: CSV, `.rdp`,
/// PuTTY `.reg`, Royal TS `.json` (or a Bastion export), RDCMan `.rdg` or mRemoteNG `.xml` (ABI 119), chosen by extension,
/// at most 64 MB. Passwords in the file are never read; what was left out is listed in
/// `skipped`. Returns JSON `{folder, format, connections, skipped}`, or NULL with `*err` set
/// (unknown type, no connections found, unreadable file). Call `bastion_library_save` after.
/// Additive in ABI 76.
///
/// # Safety
/// `lib` live; `path` valid NUL-terminated UTF-8; `err` NULL or writable. Free with `bastion_string_free`.
#[no_mangle]
pub unsafe extern "C" fn bastion_library_import_file_json(lib: *const BastionLibrary, path: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    guarded(err, std::ptr::null_mut(), || {
        let r = library(lib)?.import_file(required(path, "path")?).map_err(|e| e.to_string())?;
        Ok(to_c(json!({ "folder": r.folder, "format": r.format, "connections": r.connections, "skipped": r.skipped }).to_string()))
    })
}
