//! The import-list check on `plugin.wasm` (section 6, "Checks at install"): the component may
//! import only the interfaces its permissions allow.
//!
//! Only the top-level import section of the component is read: those are the imports the host
//! must satisfy. Imports of nested components and core modules are satisfied inside the
//! component and never reach the host. The reader walks the component binary format's section
//! list (an id byte and a LEB128 size per section) and decodes each top-level import's name and
//! extern descriptor, enough to find where the next import starts. Anything it does not
//! understand is refused, never skipped. The helper checks the imports again at load
//! (wasmtime), so this check is the early, readable refusal, not the only one.
//!
//! Allowed imports (`plugins/wit/plugin.wit`):
//! - `bastion:plugin/{types,host,log,ui,events}@1.*`: always;
//! - `bastion:plugin/net@1.*`: `network = "entry"`; `credentials`: `credentials = "entry"`;
//!   `storage`: `storage = true`; `clipboard`: `clipboard = "write"`; `files`: `files` not empty;
//!   `http` (API 1.1): `http = "entry"`;
//!   `open` (API 1.2): `open = ["ssh", ...]`;
//! - `wasi:*`: allowed (only `wasi:clocks` and `wasi:random` work; the rest are stubs that end
//!   the plugin when called).
use super::error::{Excerpt, PluginError};
use super::manifest::Permissions;

const MAGIC: &[u8; 4] = b"\0asm";
/// Component binary: version 0x0d, layer 1.
const COMPONENT_HEADER: [u8; 4] = [0x0d, 0x00, 0x01, 0x00];
const IMPORT_SECTION: u8 = 0x0a;
/// More imports than this is not a plugin (the world has 9 interfaces plus a few WASI ones).
const MAX_IMPORTS: u32 = 256;
const MAX_NAME_BYTES: u32 = 256;

fn bad(reason: &'static str) -> PluginError {
    PluginError::WasmMalformed(reason)
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, PluginError> {
        let b = *self.bytes.get(self.at).ok_or(bad("cut short"))?;
        self.at += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], PluginError> {
        let end = self.at.checked_add(n).filter(|end| *end <= self.bytes.len()).ok_or(bad("cut short"))?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    /// Unsigned LEB128, at most 32 bits.
    fn u32(&mut self) -> Result<u32, PluginError> {
        let mut value: u64 = 0;
        for shift in (0..35).step_by(7) {
            let b = self.byte()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return u32::try_from(value).map_err(|_| bad("a number is too large"));
            }
        }
        Err(bad("a number is too long"))
    }

    /// Signed LEB128 (s33), only to tell a primitive value type (negative) from a type index.
    fn s33(&mut self) -> Result<i64, PluginError> {
        let mut value: i64 = 0;
        let mut shift = 0;
        loop {
            let b = self.byte()?;
            value |= i64::from(b & 0x7f) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    value |= -1i64 << shift;
                }
                return Ok(value);
            }
            if shift >= 35 {
                return Err(bad("a number is too long"));
            }
        }
    }

    fn name(&mut self) -> Result<&'a str, PluginError> {
        let len = self.u32()?;
        if len == 0 || len > MAX_NAME_BYTES {
            return Err(bad("an import name is empty or too long"));
        }
        std::str::from_utf8(self.take(len as usize)?).map_err(|_| bad("an import name is not UTF-8"))
    }
}

/// Skip one extern descriptor.
fn extern_desc(r: &mut Reader) -> Result<(), PluginError> {
    match r.byte()? {
        // core module: 0x00 0x11 typeidx
        0x00 => {
            if r.byte()? != 0x11 {
                return Err(bad("an import has an unknown core sort"));
            }
            r.u32()?;
        }
        // func, component, instance: typeidx
        0x01 | 0x04 | 0x05 => {
            r.u32()?;
        }
        // value: valuebound
        0x02 => match r.byte()? {
            0x00 => {
                r.u32()?;
            }
            0x01 => {
                r.s33()?;
            }
            _ => return Err(bad("an import has an unknown value bound")),
        },
        // type: typebound
        0x03 => match r.byte()? {
            0x00 => {
                r.u32()?;
            }
            0x01 => {}
            _ => return Err(bad("an import has an unknown type bound")),
        },
        _ => return Err(bad("an import has an unknown kind")),
    }
    Ok(())
}

/// The names of the component's top-level imports, in order.
pub fn component_imports(wasm: &[u8]) -> Result<Vec<String>, PluginError> {
    let mut r = Reader { bytes: wasm, at: 0 };
    if r.take(4)? != MAGIC {
        return Err(bad("not a WebAssembly file"));
    }
    if r.take(4)? != COMPONENT_HEADER {
        return Err(bad("not a WebAssembly component (a core module or an unknown version)"));
    }
    let mut names = Vec::new();
    while r.at < wasm.len() {
        let id = r.byte()?;
        let size = r.u32()? as usize;
        let body = r.take(size)?;
        if id != IMPORT_SECTION {
            continue;
        }
        let mut s = Reader { bytes: body, at: 0 };
        let count = s.u32()?;
        if count > MAX_IMPORTS || (names.len() as u32).saturating_add(count) > MAX_IMPORTS {
            return Err(bad("too many imports"));
        }
        for _ in 0..count {
            let name = match s.byte()? {
                0x00 => s.name()?,
                // A name with a version suffix: 0x01 name versionsuffix (a name of its own).
                0x01 => {
                    let name = s.name()?;
                    s.name()?;
                    name
                }
                _ => return Err(bad("an import name has an unknown form")),
            };
            extern_desc(&mut s)?;
            names.push(name.to_string());
        }
        if s.at != body.len() {
            return Err(bad("an import section has bytes after its last import"));
        }
    }
    Ok(names)
}

/// The permission an interface of `bastion:plugin` needs; `Some(None)` for one that needs
/// none, `None` for a name that is not part of API 1.
fn needs(interface: &str) -> Option<Option<&'static str>> {
    Some(match interface {
        "types" | "host" | "log" | "ui" | "events" => None,
        "net" => Some("network"),
        "credentials" => Some("credentials"),
        "storage" => Some("storage"),
        "clipboard" => Some("clipboard"),
        "files" => Some("files"),
        "http" => Some("http"),
        "open" => Some("open"),
        "exec" => Some("exec"),
        "library" => Some("library"),
        _ => return None,
    })
}

fn granted(permission: &str, p: &Permissions) -> bool {
    match permission {
        "network" => p.network_entry,
        "credentials" => p.credentials_entry,
        "storage" => p.storage,
        "clipboard" => p.clipboard_write,
        "files" => p.files_save || p.files_open,
        "http" => p.http_entry,
        "open" => p.opens_any(),
        "exec" => p.exec_entry,
        "library" => p.library_propose,
        _ => false,
    }
}

/// Check every top-level import of `wasm` against `permissions`.
pub fn check_imports(wasm: &[u8], permissions: &Permissions) -> Result<(), PluginError> {
    for name in component_imports(wasm)? {
        let refuse = |why: &'static str| PluginError::WasmImportNotAllowed { import: Excerpt::new(name.as_bytes()), why };
        if name.starts_with("wasi:") {
            continue;
        }
        let Some(rest) = name.strip_prefix("bastion:plugin/") else {
            return Err(refuse("not part of the Gantry plugin API"));
        };
        let (interface, version) = rest.split_once('@').ok_or_else(|| refuse("no API version"))?;
        if !version.starts_with("1.") {
            return Err(refuse("not API version 1"));
        }
        match needs(interface) {
            None => return Err(refuse("not an interface of API 1")),
            Some(Some(permission)) if !granted(permission, permissions) => return Err(refuse("its permission is not in the manifest")),
            Some(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leb(mut n: u32, out: &mut Vec<u8>) {
        loop {
            let b = (n & 0x7f) as u8;
            n >>= 7;
            if n == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }

    /// A component whose import section holds `names` as instance imports.
    pub(crate) fn component(names: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        leb(names.len() as u32, &mut body);
        for name in names {
            body.push(0x00);
            leb(name.len() as u32, &mut body);
            body.extend_from_slice(name.as_bytes());
            body.extend_from_slice(&[0x05, 0x00]);
        }
        let mut out = b"\0asm".to_vec();
        out.extend_from_slice(&COMPONENT_HEADER);
        // A custom section first, skipped by size.
        out.extend_from_slice(&[0x00, 0x03, 0x01, b'x', 0x00]);
        out.push(IMPORT_SECTION);
        leb(body.len() as u32, &mut out);
        out.extend_from_slice(&body);
        out
    }

    fn all() -> Permissions {
        Permissions { network_entry: true, credentials_entry: true, storage: true, clipboard_write: true, files_save: true, files_open: false, http_entry: false, open_ssh: false, open_rdp: false, open_vnc: false, exec_entry: false, library_propose: false }
    }

    #[test]
    fn imports_are_read_and_checked_against_permissions() {
        let wasm = component(&["bastion:plugin/types@1.0.0", "bastion:plugin/net@1.0.0", "wasi:clocks/monotonic-clock@0.2.0"]);
        assert_eq!(component_imports(&wasm).unwrap().len(), 3);
        check_imports(&wasm, &all()).unwrap();
        let none = Permissions::default();
        assert!(matches!(check_imports(&wasm, &none).unwrap_err(), PluginError::WasmImportNotAllowed { .. }));
        check_imports(&component(&["bastion:plugin/ui@1.0.0", "bastion:plugin/events@1.2.0"]), &none).unwrap();
    }

    #[test]
    fn unknown_names_and_versions_are_refused() {
        for name in ["bastion:plugin/net", "bastion:plugin/net@2.0.0", "bastion:plugin/shell@1.0.0", "evil:x/y@1.0.0", "bastion:other/net@1.0.0"] {
            assert!(matches!(check_imports(&component(&[name]), &all()).unwrap_err(), PluginError::WasmImportNotAllowed { .. }), "{name}");
        }
    }

    #[test]
    fn a_core_module_or_damaged_component_is_refused() {
        let mut core_module = b"\0asm".to_vec();
        core_module.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]);
        assert!(matches!(component_imports(&core_module).unwrap_err(), PluginError::WasmMalformed(_)));
        let good = component(&["bastion:plugin/types@1.0.0"]);
        for cut in 0..good.len() {
            let _ = component_imports(&good[..cut]);
        }
        assert!(component_imports(&good[..good.len() - 1]).is_err());
        let mut odd = good.clone();
        *odd.last_mut().unwrap() = 0x07; // an unknown extern kind's index byte stays; make the kind unknown instead
        let kind_at = odd.len() - 2;
        odd[kind_at] = 0x09;
        assert!(matches!(component_imports(&odd).unwrap_err(), PluginError::WasmMalformed(_)));
    }
}
