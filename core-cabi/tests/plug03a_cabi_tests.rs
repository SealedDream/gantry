//! PLUG-03a through the C ABI: the tree JSON an existing call returns carries the core's fixed
//! text on an entry of an unknown type. No new export and no ABI version change.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::*;
use serde_json::Value;

const LIBRARY: &str = include_str!("../../core/tests/fixtures/plug03a/library-unknown.json");
const UNKNOWN_ID: &str = "0a000000-0000-4000-8000-000000000004";
const SSH_ID: &str = "0a000000-0000-4000-8000-000000000005";

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

#[test]
fn tree_json_marks_an_unknown_entry_and_the_abi_version_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("library.json");
    std::fs::write(&path, LIBRARY).unwrap();
    unsafe {
        assert_eq!(bastion_abi_version(), 149, "PLUG-03a added a JSON field only; 96 is A1-CORE-01, 97 is CABI-97, 101 is SEC-07, 103 is LOG-CORE-01-WIRING, 104 is A1-CORE-01-FU3, 105 is A1-CORE-02, 106 is LOG-01, 107 is LIB-01, 108 is A1-CORE-01-FU5, 109 is B4-FOLDER-CONNECT-ALL-FU1, 111 is PLUG-02c, 112 is SSH-IMPORT-FORWARDS, 114 is B10, 115 is W11-TERM-SEARCH, 116 is B7-CORE, 117 is B9, 118 is B11, 119 is B14, 120 is PLUG-04b part 2, 121 is custom properties, 122 is item icon, 123 is audit log, 124 is TERMINAL-WAKE, 125 is WIN-LIB-FIRST-SCREEN, 126 is B3-BULK-EDIT, 127 is B8-KEEPASS-IMPORT, 128 is B5-TASK-HOOKS-WIN, 129 is RDP-VNC-FIT, 130 is B15-NATIVE core, 131 is TAGS, 132 is TERM-MARKS, 133 is PAR-WIN-D close check, 134 is PAR-WIN-D carry-over, 135 is PAR-WIN-D task ask, 136 is PLUG-06c, 137 is PLUG-VIEW-CABI, 138 is LOG-CORE-02, 139 is PLUG-08-WIN, 140 is PLUG-OPEN-WIN, 141 is PLUG API 1.3, 142 is PVE-TLS, 143 is UI-06, 144 is PVE-AUTH, 145 is START-WINDOW, 146 is LOG-ERRCODES, 147 is PLUG-EXEC-01, 149 is PLUG-SAVE-CONN");
        let mut err: *mut c_char = null_mut();
        let lib = bastion_library_open(CString::new(path.to_str().unwrap()).unwrap().as_ptr(), &mut err);
        assert!(!lib.is_null() && err.is_null(), "an unknown connection type is not corruption");

        let tree: Value = serde_json::from_str(&take(bastion_library_tree_json(lib, &mut err))).unwrap();
        let rows = tree["folders"][0]["connections"].as_array().unwrap();
        let unknown = rows.iter().find(|c| c["id"] == UNKNOWN_ID).expect("the entry is listed");
        assert_eq!(unknown["unavailable"], "Needs a newer Gantry or a plugin");
        assert_eq!(unknown["iconLabel"], "Needs a newer Gantry or a plugin");
        assert_eq!((unknown["protocol"].as_str(), unknown["icon"].as_str(), unknown["hasTools"].as_bool()), (Some("postgresql"), Some("network"), Some(false)));
        let known = rows.iter().find(|c| c["id"] == SSH_ID).unwrap();
        assert!(known["unavailable"].is_null());
        assert_eq!((known["protocol"].as_str(), known["icon"].as_str()), (Some("ssh"), Some("ssh")));

        bastion_library_free(lib);
    }
}

#[test]
fn test_connection_on_an_unknown_type_gets_the_fixed_text() {
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        let mut err: *mut c_char = null_mut();
        let m = bastion_session_manager_new(CString::new(dir.path().to_str().unwrap()).unwrap().as_ptr(), &mut err);
        assert!(!m.is_null() && err.is_null());
        // What Native Windows sends for the row of an entry of an unknown type.
        let input = CString::new(r#"{"protocol":"postgresql","host":"db.lab.example","port":5432,"username":"app"}"#).unwrap();
        assert!(bastion_probe_start(m, std::ptr::null(), input.as_ptr(), &mut err).is_null());
        let message = take(err);
        assert!(message.contains("Needs a newer Gantry or a plugin"), "{message}");
        bastion_session_manager_free(m);
    }
}
