//! The ABI v54 library palette entries, ranked by the ABI v16 palette.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null());
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    s
}

#[test]
fn library_connections_rank_by_folder_and_host() {
    let d = tempfile::tempdir().unwrap();
    unsafe {
        assert!(bastion_abi_version() >= 57, "palette connections need ABI 57+");
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        let folder = take(bastion_library_add_folder(lib, null(), c("Customers").as_ptr(), &mut err));
        let db = take(bastion_library_add_connection(lib, c(&folder).as_ptr(), c("db-01").as_ptr(), c("ssh").as_ptr(), c("10.0.0.5").as_ptr(), -1, null(), &mut err));
        take(bastion_library_add_connection(lib, null(), c("lab").as_ptr(), c("rdp").as_ptr(), c("lab.local").as_ptr(), -1, null(), &mut err));
        let json = take(bastion_library_palette_connections_json(lib, &mut err));
        let rows: Vec<Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["id"], db.as_str());
        assert_eq!((rows[0]["protocol"].as_str(), rows[0]["kind"].as_str()), (Some("ssh"), Some("connection")));

        let p = bastion_palette_new(c(&json).as_ptr(), &mut err);
        assert_eq!(take(bastion_palette_rank_json(p, c("customers").as_ptr(), 10, &mut err)), "[0]");
        assert_eq!(take(bastion_palette_rank_json(p, c("lab.local").as_ptr(), 10, &mut err)), "[1]");
        bastion_palette_free(p);

        assert!(bastion_library_palette_connections_json(null(), &mut err).is_null());
        assert!(take(err).contains("NULL"));
        bastion_library_free(lib);
    }
}
