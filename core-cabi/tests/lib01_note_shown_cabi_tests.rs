//! LIB-01: the library shown by hand becomes the head of Recents, which the next launch opens.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::personal::*;
use bastion_cabi::*;

unsafe fn recent_head(data: &CString) -> String {
    let mut err: *mut c_char = null_mut();
    let json = bastion_documents_recent_json(data.as_ptr(), &mut err);
    assert!(!json.is_null());
    let list: Vec<String> = serde_json::from_str(&CStr::from_ptr(json).to_string_lossy()).unwrap();
    bastion_string_free(json);
    list.first().cloned().unwrap_or_default()
}

#[test]
fn show_personal_then_show_document_moves_the_head_of_recents() {
    // A synthetic test device key; the real one comes from DPAPI.
    std::env::set_var("BASTION_DEVICE_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    let d = tempfile::tempdir().unwrap();
    let data = CString::new(d.path().to_str().unwrap()).unwrap();
    let personal_path = d.path().join("Personal.bastion");
    let doc_path = d.path().join("Testing-New.bastion");
    let pp = CString::new(personal_path.to_str().unwrap()).unwrap();
    let dp = CString::new(doc_path.to_str().unwrap()).unwrap();
    let name = CString::new("Testing-New").unwrap();
    let mut err: *mut c_char = null_mut();
    unsafe {
        let p = bastion_personal_open(data.as_ptr(), pp.as_ptr(), &mut err);
        assert!(!p.is_null());
        let h = bastion_document_create(name.as_ptr(), data.as_ptr(), &mut err);
        assert!(!h.is_null());
        assert_eq!(bastion_document_save(h, dp.as_ptr(), &mut err), 0);
        assert!(recent_head(&data).ends_with("Testing-New.bastion"));

        assert_eq!(bastion_personal_note_shown(p, &mut err), 0);
        assert!(recent_head(&data).ends_with("Personal.bastion"));

        assert_eq!(bastion_document_note_opened(h, &mut err), 0);
        assert!(recent_head(&data).ends_with("Testing-New.bastion"));

        // NULL handles fail cleanly.
        assert_eq!(bastion_personal_note_shown(std::ptr::null(), &mut err), -1);
        bastion_string_free(err);
        bastion_document_free(h);
        bastion_personal_free(p);
    }
}
