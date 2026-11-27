//! The ABI v53 split-pane and broadcast surface.
use std::ffi::{c_char, CStr, CString};
use std::ptr::null_mut;

use bastion_cabi::*;
use serde_json::{json, Value};

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    let s = CStr::from_ptr(p).to_string_lossy().into_owned();
    bastion_string_free(p);
    Some(s)
}

const P: [&str; 3] = ["6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0c01", "6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0c02", "6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0c03"];

unsafe fn apply(tree: &Value, op: Value) -> Result<Value, String> {
    let mut err = null_mut();
    let out = bastion_panes_apply_json(c(&tree.to_string()).as_ptr(), c(&op.to_string()).as_ptr(), &mut err);
    match take(out) {
        Some(s) => Ok(serde_json::from_str(&s).unwrap()),
        None => Err(take(err).unwrap()),
    }
}

#[test]
fn split_focus_resize_close_and_layout() {
    unsafe {
        let leaf = json!({"kind":"leaf","id":P[0]});
        let a = apply(&leaf, json!({"op":"split","pane":P[0],"axis":"right","newPane":P[1]})).unwrap();
        assert_eq!(a["focus"], P[1]);
        let b = apply(&a["tree"], json!({"op":"split","pane":P[1],"axis":"down","newPane":P[2]})).unwrap();
        let f = apply(&b["tree"], json!({"op":"focus","pane":P[2],"direction":"left"})).unwrap();
        assert_eq!(f["focus"], P[0]);
        let r = apply(&b["tree"], json!({"op":"resize","pane":P[0],"axis":"right","delta":0.25})).unwrap();
        assert_eq!(r["tree"]["ratio"], 0.75);
        assert!(apply(&b["tree"], json!({"op":"close","pane":"6f1c3c58-3d7c-4f43-9d0e-2b6a4f1f0cff"})).unwrap_err().contains("pane"));
        let gone = apply(&leaf, json!({"op":"close","pane":P[0]})).unwrap();
        assert!(gone["tree"].is_null());

        let mut err = null_mut();
        let layout = take(bastion_panes_to_layout_json(c(&b["tree"].to_string()).as_ptr(), &mut err)).unwrap();
        assert!(!layout.contains(P[0]), "saved layouts hold no pane ids");
        let live: Value = serde_json::from_str(&take(bastion_panes_from_layout_json(c(&layout).as_ptr(), &mut err)).unwrap()).unwrap();
        assert_eq!(live["second"]["kind"], "split");
        assert!(live["first"]["id"].is_string());
    }
}

#[test]
fn broadcast_review_over_the_abi() {
    unsafe {
        let targets = json!([
            {"pane":P[0],"name":"web1","connected":true,"sensitive":true},
            {"pane":P[1],"name":"web2","connected":false},
        ]);
        let mut err = null_mut();
        let out = take(bastion_broadcast_review_json(c("keys").as_ptr(), c("l").as_ptr(), c(&targets.to_string()).as_ptr(), 0, &mut err)).unwrap();
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["sendTo"], json!([P[0]]));
        assert_eq!(v["skipped"], json!([P[1]]));
        assert_eq!(v["needsConfirm"], true);
        let refused = bastion_broadcast_review_json(c("paste").as_ptr(), c("x\u{1b}[201~y").as_ptr(), c(&targets.to_string()).as_ptr(), 1, &mut err);
        assert!(refused.is_null());
        assert!(take(err).unwrap().contains("bracketed"));
        let mut err = null_mut();
        assert!(bastion_broadcast_review_json(c("shout").as_ptr(), c("x").as_ptr(), c("[]").as_ptr(), 0, &mut err).is_null());
        take(err);
    }
}
