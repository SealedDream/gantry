//! PLUG-06c through the C ABI: highlighting and completions as JSON.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::*;
use serde_json::{json, Value};

unsafe fn take(p: *mut c_char) -> Value {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    serde_json::from_str(&s).unwrap()
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn lines_carry_their_state() {
    unsafe {
        let mut err = null_mut();
        let first = take(bastion_highlight_line_json(c("postgresql").as_ptr(), c("SELECT /* a").as_ptr(), std::ptr::null(), &mut err));
        assert!(err.is_null());
        assert_eq!(first["tokens"][0]["kind"], "keyword");
        assert_eq!(first["endState"], "c1");
        let state = c(first["endState"].as_str().unwrap());
        let second = take(bastion_highlight_line_json(c("postgresql").as_ptr(), c("b */ x").as_ptr(), state.as_ptr(), &mut err));
        assert_eq!(second["tokens"][0]["kind"], "comment");
        assert_eq!(second["endState"], "");
        let text = take(bastion_highlight_text_json(c("sql").as_ptr(), c("SELECT 'é'\nFROM").as_ptr(), &mut err));
        let from = text["tokens"].as_array().unwrap().last().unwrap();
        assert_eq!((from["utf16Start"].as_u64(), from["start"].as_u64()), (Some(11), Some(12)));
    }
}

#[test]
fn completion_context_and_rank() {
    unsafe {
        let mut err = null_mut();
        let ctx = take(bastion_completion_context_json(c("postgresql").as_ptr(), c("SELECT na").as_ptr(), 9, &mut err));
        assert_eq!(ctx, json!({"ask": true, "prefix": "na", "replaceUtf16Start": 7, "replaceUtf16Len": 2, "charOffset": 9}));
        let quiet = take(bastion_completion_context_json(c("postgresql").as_ptr(), c("SELECT 'na").as_ptr(), 10, &mut err));
        assert_eq!(quiet["ask"], false);
        let items = c(r#"[{"label":"orders"},{"label":"name","insert":"name","detail":"text"},{"label":"Namespace"}]"#);
        let ranked = take(bastion_completions_rank_json(items.as_ptr(), c("na").as_ptr(), &mut err));
        assert!(err.is_null());
        assert_eq!(ranked, json!([{"label":"name","insert":"name","detail":"text"},{"label":"Namespace","insert":"","detail":""}]));
    }
}

#[test]
fn bad_arguments_set_err() {
    unsafe {
        let mut err = null_mut();
        assert!(bastion_highlight_line_json(std::ptr::null(), c("x").as_ptr(), std::ptr::null(), &mut err).is_null());
        assert!(!err.is_null());
        bastion_string_free(err);
        let mut err = null_mut();
        assert!(bastion_completions_rank_json(c("{}").as_ptr(), c("").as_ptr(), &mut err).is_null());
        assert!(!err.is_null());
        bastion_string_free(err);
    }
}
