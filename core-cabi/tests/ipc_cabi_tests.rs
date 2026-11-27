//! The ABI v9 IPC listener, driven as the WinUI host drives it, with requests sent the way the
//! `bastion` CLI sends them (`core::ipc::request` on the same endpoint).
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use bastion_core::ipc::{self, Request, Response, PROTOCOL_VERSION};

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

fn ask(dir: &std::path::Path, req: Request) -> Response {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(ipc::request(&ipc::socket_path(dir), &ipc::read_token(dir).unwrap(), &req)).unwrap()
}

#[test]
fn ping_list_and_open_by_name_or_id() {
    unsafe {
        let dir = tempfile::tempdir().unwrap();
        let mut err = null_mut();
        let lib = bastion_library_open(c(&dir.path().join("lib.json").to_string_lossy()).as_ptr(), &mut err);
        assert!(!lib.is_null(), "{:?}", take(err));
        let add = |name: &str| take(bastion_library_add_connection(lib, null(), c(name).as_ptr(), c("ssh").as_ptr(), c("10.0.0.1").as_ptr(), 22, c("ops").as_ptr(), null_mut())).unwrap();
        let web = add("web-1");
        add("twin");
        add("twin");

        let l = bastion_ipc_listen(lib, c(&dir.path().to_string_lossy()).as_ptr(), &mut err);
        assert!(!l.is_null(), "{:?}", take(err));
        assert!(take(bastion_ipc_error(l)).is_none());

        assert_eq!(ask(dir.path(), Request::Ping), Response::Pong { version: PROTOCOL_VERSION });
        match ask(dir.path(), Request::List) {
            Response::Names { mut names } => {
                names.sort();
                assert_eq!(names, ["twin", "twin", "web-1"], "names only");
            }
            other => panic!("{other:?}"),
        }
        assert!(bastion_ipc_next_open(l).is_null(), "nothing asked yet");

        assert_eq!(ask(dir.path(), Request::Open { name: "web-1".into(), files: false, protocol: None }), Response::Ok);
        assert_eq!(take(bastion_ipc_next_open(l)).as_deref(), Some(web.as_str()), "the host gets the id");
        assert_eq!(ask(dir.path(), Request::Open { name: web.clone(), files: false, protocol: None }), Response::Ok);
        assert_eq!(take(bastion_ipc_next_open(l)).as_deref(), Some(web.as_str()), "an id works too");
        assert!(bastion_ipc_next_open(l).is_null());

        // Only saved connections: an unknown name, a host, an ambiguous name and --files are refused.
        for name in ["nope", "10.0.0.1", "twin"] {
            assert!(matches!(ask(dir.path(), Request::Open { name: name.into(), files: false, protocol: None }), Response::Error { .. }), "{name}");
        }
        assert!(matches!(ask(dir.path(), Request::Open { name: "web-1".into(), files: true, protocol: None }), Response::Error { .. }));
        assert!(bastion_ipc_next_open(l).is_null(), "refused requests queue nothing");

        // One listener per data dir; after free the endpoint is free again.
        let second = bastion_ipc_listen(lib, c(&dir.path().to_string_lossy()).as_ptr(), &mut err);
        assert!(second.is_null());
        assert!(take(err).unwrap().contains("already listening"));
        // WR-01: the refused listener left the running one's token alone; a client that
        // re-reads the token from disk still reaches the first listener.
        assert_eq!(ask(dir.path(), Request::Ping), Response::Pong { version: PROTOCOL_VERSION });
        bastion_ipc_free(l);
        std::thread::sleep(std::time::Duration::from_millis(300));
        let again = bastion_ipc_listen(lib, c(&dir.path().to_string_lossy()).as_ptr(), &mut err);
        assert!(!again.is_null(), "{:?}", take(err));
        assert_eq!(ask(dir.path(), Request::Ping), Response::Pong { version: PROTOCOL_VERSION }, "a restart publishes its own token");
        bastion_ipc_free(again);
        bastion_library_free(lib);
    }
}

#[test]
fn the_queue_is_bounded() {
    unsafe {
        let dir = tempfile::tempdir().unwrap();
        let lib = bastion_library_open(c(&dir.path().join("lib.json").to_string_lossy()).as_ptr(), null_mut());
        take(bastion_library_add_connection(lib, null(), c("a").as_ptr(), c("ssh").as_ptr(), c("h").as_ptr(), 22, null(), null_mut()));
        let l = bastion_ipc_listen(lib, c(&dir.path().to_string_lossy()).as_ptr(), null_mut());
        assert!(!l.is_null());
        for _ in 0..40 {
            assert_eq!(ask(dir.path(), Request::Open { name: "a".into(), files: false, protocol: None }), Response::Ok);
        }
        let mut n = 0;
        while take(bastion_ipc_next_open(l)).is_some() {
            n += 1;
        }
        assert_eq!(n, 16, "a script cannot pile up more than 16 pending tabs");
        bastion_ipc_free(l);
        bastion_library_free(lib);
    }
}

#[test]
fn null_handles_are_harmless() {
    unsafe {
        let mut err = null_mut();
        assert!(bastion_ipc_listen(null(), c("x").as_ptr(), &mut err).is_null());
        assert!(take(err).is_some());
        assert!(bastion_ipc_next_open(null()).is_null());
        assert!(bastion_ipc_error(null()).is_null());
        bastion_ipc_free(null_mut());
    }
}
