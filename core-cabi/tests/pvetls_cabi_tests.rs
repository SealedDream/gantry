//! PVE-TLS (ABI 142): the plugin-entry exports refuse bad input with the core's text and never crash.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::pluginentries::*;
use bastion_cabi::properties::*;
use bastion_cabi::*;

const LIBRARY: &str = include_str!("../../core/tests/fixtures/plug03a/library-unknown.json");
const UNKNOWN_ID: &str = "0a000000-0000-4000-8000-000000000004";

unsafe fn take_err(err: *mut c_char) -> String {
    assert!(!err.is_null(), "expected an error");
    let s = CStr::from_ptr(err).to_str().unwrap().to_string();
    bastion_string_free(err);
    s
}

#[test]
fn certificate_check_refuses_an_empty_host_and_a_closed_port() {
    unsafe {
        let mut err: *mut c_char = null_mut();
        assert_eq!(bastion_plugin_certificate_check(CString::new("").unwrap().as_ptr(), 443, null_mut(), &mut err), -1);
        assert!(take_err(err).contains("no host"));
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let mut err: *mut c_char = null_mut();
        let pin = CString::new("0".repeat(64)).unwrap();
        assert_eq!(bastion_plugin_certificate_check(CString::new("127.0.0.1").unwrap().as_ptr(), port, pin.as_ptr(), &mut err), -1);
        take_err(err);
    }
}

#[test]
fn fields_and_set_field_need_an_installed_plugin_type() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, LIBRARY).unwrap();
    unsafe {
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(CString::new(path.to_str().unwrap()).unwrap().as_ptr(), &mut err);
        assert!(!lib.is_null());
        let data = CString::new(dir.path().to_str().unwrap()).unwrap();
        let id = CString::new(UNKNOWN_ID).unwrap();
        let mut err: *mut c_char = null_mut();
        assert!(bastion_library_plugin_entry_fields_json(lib, data.as_ptr(), id.as_ptr(), &mut err).is_null());
        take_err(err);
        let mut err: *mut c_char = null_mut();
        let key = CString::new("node").unwrap();
        assert_eq!(bastion_library_set_plugin_field(lib, data.as_ptr(), id.as_ptr(), key.as_ptr(), null_mut(), &mut err), -1);
        take_err(err);
        bastion_library_free(lib);
    }
}

#[test]
fn properties_open_on_a_plugin_entry() {
    // Windows Properties… (PropertyEditorForm) reads the schema by the entry's type name, its
    // values and its custom properties. None may refuse a plugin entry (q-pvetls-w1).
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, LIBRARY.replace("\"postgresql\",\n            \"host\"", "\"dev.bastion.proxmox/pve\",\n            \"host\"")).unwrap();
    unsafe {
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(CString::new(path.to_str().unwrap()).unwrap().as_ptr(), &mut err);
        assert!(!lib.is_null());
        let id = CString::new(UNKNOWN_ID).unwrap();
        let proto = CString::new("dev.bastion.proxmox/pve").unwrap();
        for (what, p) in [
            ("schema", bastion_property_schema_json(proto.as_ptr(), 0, &mut err)),
            ("values", bastion_library_property_values_json(lib, id.as_ptr(), &mut err)),
            ("custom", bastion_library_custom_properties_json(lib, id.as_ptr(), &mut err)),
        ] {
            let e = if err.is_null() { String::new() } else { take_err(err) };
            err = null_mut();
            assert!(!p.is_null(), "{what}: {e}");
            bastion_string_free(p);
        }
        bastion_library_free(lib);
    }
}
