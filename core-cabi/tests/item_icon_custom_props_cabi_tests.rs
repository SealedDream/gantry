//! Per-item icon and custom properties over the C ABI, as the Windows property editor drives them.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::{json, Value};

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

unsafe fn json_of(p: *mut c_char) -> Value {
    serde_json::from_str(&take(p)).unwrap()
}

/// The tree row of the first connection at the root.
unsafe fn row(lib: *const BastionLibrary) -> Value {
    let mut err: *mut c_char = null_mut();
    let tree = json_of(bastion_library_tree_json(lib, &mut err));
    tree["connections"][0].clone()
}

#[test]
fn icon_names_are_the_core_list() {
    let names = unsafe { json_of(bastion_connection_icon_names_json()) };
    assert_eq!(names, json!(["server", "desktop", "terminal", "database", "network", "cloud", "container", "globe", "shield", "storage"]));
}

#[test]
fn item_icon_is_set_shown_in_the_tree_cleared_and_unknown_names_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lib.json");
    unsafe {
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(c(path.to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let conn = take(bastion_library_add_connection(lib, null(), c("A").as_ptr(), c("ssh").as_ptr(), c("a.lab").as_ptr(), -1, null(), &mut err));
        assert_eq!(row(lib)["ownIcon"], Value::Null);

        assert_eq!(bastion_library_set_icon(lib, c(&conn).as_ptr(), c("database").as_ptr(), &mut err), 0);
        assert_eq!(row(lib)["ownIcon"], "database");
        // The protocol glyph is unchanged; the app draws `ownIcon` when it is set.
        assert_eq!(row(lib)["icon"], "ssh");

        assert_eq!(bastion_library_set_icon(lib, c(&conn).as_ptr(), c("../evil").as_ptr(), &mut err), -1);
        assert!(take(err).contains("unknown icon"));
        err = null_mut();
        assert_eq!(row(lib)["ownIcon"], "database");

        assert_eq!(bastion_library_save(lib, &mut err), 0);
        bastion_library_free(lib);
        let lib = bastion_library_open(c(path.to_str().unwrap()).as_ptr(), &mut err);
        assert_eq!(row(lib)["ownIcon"], "database", "the icon survives a save and reopen");

        assert_eq!(bastion_library_set_icon(lib, c(&conn).as_ptr(), null(), &mut err), 0);
        assert_eq!(row(lib)["ownIcon"], Value::Null);
        assert_eq!(bastion_library_set_icon(lib, c(&conn).as_ptr(), c("database").as_ptr(), &mut err), 0);
        assert_eq!(bastion_library_set_icon(lib, c(&conn).as_ptr(), c("  ").as_ptr(), &mut err), 0);
        assert_eq!(row(lib)["ownIcon"], Value::Null, "a blank name clears");
        bastion_library_free(lib);
    }
}

#[test]
fn custom_properties_round_trip_and_bad_input_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lib.json");
    unsafe {
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(c(path.to_str().unwrap()).as_ptr(), &mut err);
        let conn = take(bastion_library_add_connection(lib, null(), c("A").as_ptr(), c("rdp").as_ptr(), c("a.lab").as_ptr(), -1, null(), &mut err));
        assert_eq!(json_of(bastion_library_custom_properties_json(lib, c(&conn).as_ptr(), &mut err)), json!([]));

        assert_eq!(bastion_library_set_custom_property(lib, c(&conn).as_ptr(), c("Asset tag").as_ptr(), c("A-1042").as_ptr(), &mut err), 0);
        assert_eq!(bastion_library_set_custom_property(lib, c(&conn).as_ptr(), c("Rack").as_ptr(), c("R3").as_ptr(), &mut err), 0);
        assert_eq!(bastion_library_save(lib, &mut err), 0);
        bastion_library_free(lib);

        let lib = bastion_library_open(c(path.to_str().unwrap()).as_ptr(), &mut err);
        assert_eq!(
            json_of(bastion_library_custom_properties_json(lib, c(&conn).as_ptr(), &mut err)),
            json!([{ "name": "Asset tag", "value": "A-1042" }, { "name": "Rack", "value": "R3" }])
        );

        // Removing one leaves the other.
        assert_eq!(bastion_library_set_custom_property(lib, c(&conn).as_ptr(), c("Rack").as_ptr(), null(), &mut err), 0);
        assert_eq!(json_of(bastion_library_custom_properties_json(lib, c(&conn).as_ptr(), &mut err)), json!([{ "name": "Asset tag", "value": "A-1042" }]));

        // A bad name is refused with a message, and nothing is stored.
        assert_eq!(bastion_library_set_custom_property(lib, c(&conn).as_ptr(), c("a/b").as_ptr(), c("x").as_ptr(), &mut err), -1);
        assert!(!take(err).is_empty());
        err = null_mut();
        assert_eq!(json_of(bastion_library_custom_properties_json(lib, c(&conn).as_ptr(), &mut err)).as_array().unwrap().len(), 1);

        // An unknown connection id is an error, not an empty list.
        let other = "00000000-0000-4000-8000-000000000000";
        assert!(bastion_library_custom_properties_json(lib, c(other).as_ptr(), &mut err).is_null());
        assert!(!take(err).is_empty());
        bastion_library_free(lib);
    }
}
