//! Tunnel definitions and web tabs through a tunnel over the C ABI, as the Windows app uses them:
//! WebView2 gets `--proxy-server` and its own user-data folder per tunnel.
use std::ffi::{c_char, CStr, CString};
use std::ptr::{null, null_mut};

use bastion_cabi::*;
use serde_json::Value;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

unsafe fn take(p: *mut c_char) -> String {
    assert!(!p.is_null(), "expected a string");
    let s = CStr::from_ptr(p).to_str().unwrap().to_string();
    bastion_string_free(p);
    s
}

unsafe fn err_text(err: *mut c_char) -> String {
    take(err)
}

#[test]
fn web_connection_through_a_socks_tunnel_gets_proxy_and_own_data_folder() {
    let d = tempfile::tempdir().unwrap();
    let data = d.path().join("data");
    unsafe {
        let mut err = null_mut();
        let lib = bastion_library_open(c(d.path().join("library.json").to_str().unwrap()).as_ptr(), &mut err);
        assert!(!lib.is_null());
        let ssh = take(bastion_library_add_connection(lib, null(), c("jump").as_ptr(), c("ssh").as_ptr(), c("127.0.0.1").as_ptr(), 22, null(), &mut err));
        let web = take(bastion_library_add_connection(lib, null(), c("intranet").as_ptr(), c("web").as_ptr(), c("https://intranet.corp").as_ptr(), -1, null(), &mut err));

        let socks = take(bastion_library_put_tunnel_json(lib, c(&format!(r#"{{"name":"Corp","viaId":"{ssh}","kind":"dynamic","localPort":18080}}"#)).as_ptr(), &mut err));
        let fwd = take(bastion_library_put_tunnel_json(lib, c(&format!(r#"{{"name":"Fwd","viaId":"{ssh}","kind":"local","localPort":18443,"host":"intranet.corp","port":443}}"#)).as_ptr(), &mut err));
        let list: Value = serde_json::from_str(&take(bastion_library_tunnels_json(lib, &mut err))).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 2);
        assert_eq!(list[0]["viaName"], "jump");
        assert!(bastion_library_put_tunnel_json(lib, c(r#"{"name":"x","kind":"dynamic","localPort":70000}"#).as_ptr(), &mut err).is_null());
        assert!(err_text(err).contains("65535"));
        err = null_mut();

        let plan = |id: &str| -> Value {
            let mut e = null_mut();
            serde_json::from_str(&take(bastion_library_web_tunnel_plan_json(lib, c(id).as_ptr(), c(data.to_str().unwrap()).as_ptr(), &mut e))).unwrap()
        };
        assert_eq!(plan(&web), Value::Null, "direct by default");
        assert_eq!(bastion_library_set_web_tunnel(lib, c(&web).as_ptr(), c(&socks).as_ptr(), &mut err), 0);
        let p = plan(&web);
        assert_eq!(p["proxyUrl"], "socks5://127.0.0.1:18080");
        assert_eq!(p["forwardAddress"], Value::Null);
        assert_eq!(p["viaId"], ssh.as_str());
        let socks_dir = p["dataDir"].as_str().unwrap().to_string();
        assert!(std::path::Path::new(&socks_dir).is_dir(), "created for WebView2");

        assert_eq!(bastion_library_set_web_tunnel(lib, c(&web).as_ptr(), c(&fwd).as_ptr(), &mut err), 0);
        let p = plan(&web);
        assert_eq!(p["forwardAddress"], "127.0.0.1:18443");
        assert_ne!(p["dataDir"].as_str().unwrap(), socks_dir, "cookies never mix between tunnels");

        let s: Value = serde_json::from_str(&take(bastion_library_tunnel_proxy_settings_json(lib, c(&socks).as_ptr(), &mut err))).unwrap();
        assert_eq!(s["url"], "socks5h://127.0.0.1:18080");
        assert_eq!(take(bastion_library_tunnel_proxy_settings_json(lib, c(&fwd).as_ptr(), &mut err)), "null");

        // Not a web connection; deleted tunnel is an error, never direct.
        assert_eq!(bastion_library_set_web_tunnel(lib, c(&ssh).as_ptr(), c(&socks).as_ptr(), &mut err), -1);
        bastion_string_free(err);
        err = null_mut();
        assert_eq!(bastion_library_remove_tunnel(lib, c(&fwd).as_ptr(), &mut err), 0);
        assert!(bastion_library_web_tunnel_plan_json(lib, c(&web).as_ptr(), c(data.to_str().unwrap()).as_ptr(), &mut err).is_null());
        assert!(err_text(err).contains("deleted"));
        err = null_mut();

        // The deleted tunnel's folder is pruned; the SOCKS one stays until cleared.
        assert_eq!(bastion_library_prune_web_tunnel_data(lib, c(data.to_str().unwrap()).as_ptr(), &mut err), 1);
        assert!(std::path::Path::new(&socks_dir).is_dir());
        assert_eq!(bastion_web_tunnel_clear_data(c(data.to_str().unwrap()).as_ptr(), c(&socks).as_ptr(), &mut err), 0);
        assert!(!std::path::Path::new(&socks_dir).exists());
        bastion_library_free(lib);
    }
}

#[test]
fn port_check_and_browser_fallback() {
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let p = taken.local_addr().unwrap().port();
    let next = bastion_local_port_next_free(p);
    assert!(next > i32::from(p));
    unsafe {
        let mut err = null_mut();
        let a: Vec<String> = serde_json::from_str(&take(bastion_tunnel_browser_args_json(c("chromium").as_ptr(), 18080, c(r"C:\Temp\b p").as_ptr(), &mut err))).unwrap();
        assert!(a.contains(&r"--user-data-dir=C:\Temp\b p".to_string()) && a.contains(&"--proxy-server=socks5://127.0.0.1:18080".to_string()));
        assert!(bastion_tunnel_browser_args_json(c("ie").as_ptr(), 1, c("x").as_ptr(), &mut err).is_null());
        bastion_string_free(err);
        assert!(take(bastion_firefox_user_js(18080)).contains("socks_remote_dns\", true"));
    }
}
