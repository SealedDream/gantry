//! Plain `extern "C"` surface over [`RdpSession`] for the Windows shell (P/Invoke), next to the
//! UniFFI one the macOS app uses. Same conventions as `core-cabi`: strings are UTF-8 and
//! NUL-terminated, returned strings are freed with [`bastion_rdp_string_free`], handles with
//! [`bastion_rdp_free`]. The password is borrowed for one connect call and never kept.
use std::ffi::{c_char, CStr, CString};
use std::ptr;
use std::sync::Arc;

use crate::{RdpError, RdpPointerButton, RdpSession, RdpState, RdpTarget};

/// Bumped whenever a signature below changes.
///
/// 2: `bastion_rdp_connect_with_options` + [`BastionRdpOptions`] (additive).
/// 3: `bastion_rdp_type_text` + `bastion_rdp_release_all` (owner point 29, additive).
/// 4: `bastion_rdp_resize` (Display Control, RDP-VNC-FIT, additive).
pub const RDP_ABI_VERSION: u32 = 4;

/// Connect results.
pub const RDP_OK: i32 = 0;
pub const RDP_FAILED: i32 = -1;
/// `err` holds the certificate's SHA-256 fingerprint; retry with it as `trusted_fingerprint`.
pub const RDP_CERTIFICATE_UNKNOWN: i32 = -2;
pub const RDP_AUTH_FAILED: i32 = -3;

fn put(err: *mut *mut c_char, text: &str) {
    if !err.is_null() {
        let c = CString::new(text.replace('\0', " ")).unwrap_or_default();
        // SAFETY: the caller passes NULL or a writable pointer.
        unsafe { *err = c.into_raw() };
    }
}

/// # Safety
/// `s` NULL or a valid NUL-terminated string.
unsafe fn text(s: *const c_char) -> Option<String> {
    if s.is_null() {
        None
    } else {
        Some(CStr::from_ptr(s).to_string_lossy().into_owned())
    }
}

/// # Safety
/// `s` must be NULL or a live handle from [`bastion_rdp_new`].
unsafe fn session<'a>(s: *const RdpSession) -> Option<&'a RdpSession> {
    s.as_ref()
}

#[no_mangle]
pub extern "C" fn bastion_rdp_abi_version() -> u32 {
    RDP_ABI_VERSION
}

/// A new idle session, or NULL with `err` set.
///
/// # Safety
/// `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_new(err: *mut *mut c_char) -> *const RdpSession {
    match RdpSession::new() {
        Ok(s) => Arc::into_raw(s),
        Err(e) => {
            put(err, &e.to_string());
            ptr::null()
        }
    }
}

/// Session options for [`bastion_rdp_connect_with_options`]. Versioned by size: set
/// `struct_size = sizeof(BastionRdpOptions)`; later versions only append fields.
///
/// Layout (x64, 24 bytes): `struct_size` u32 @0, `nla_only` u8 @4, `clipboard` u8 @5, `audio` u8 @6,
/// reserved u8 @7, `gateway_port` u16 @8, reserved u16 @10, `color_depth` u32 @12,
/// `shared_folder` pointer @16.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BastionRdpOptions {
    pub struct_size: u32,
    /// 1: offer only NLA (CredSSP); 0: also allow TLS security with the server's login screen.
    pub nla_only: u8,
    /// 1: share Unicode text both ways (CLIPRDR).
    pub clipboard: u8,
    /// 1: play the server's sound locally.
    pub audio: u8,
    pub _reserved0: u8,
    /// Loopback port of a gateway forward to dial instead of `host:port`; 0 = direct TCP.
    /// `host` stays the name the certificate pin and CredSSP use.
    pub gateway_port: u16,
    pub _reserved1: u16,
    /// 15, 16, 24 or 32; anything else is refused.
    pub color_depth: u32,
    /// Absolute path of an existing local folder shared as drive "Gantry", or NULL for none.
    pub shared_folder: *const c_char,
}

/// Validated session options: `nla_only, via_loopback_port, clipboard, shared_folder, audio, color_depth`.
type Options = (bool, Option<u16>, bool, Option<String>, bool, u32);

/// The options the old [`bastion_rdp_connect`] always used.
const DEFAULT_OPTIONS: Options = (true, None, false, None, false, 32);

/// # Safety
/// `o` NULL or pointing at `o.struct_size` readable bytes; `shared_folder` NULL or valid.
unsafe fn options(o: *const BastionRdpOptions) -> Result<Options, String> {
    let Some(o) = o.as_ref() else { return Ok(DEFAULT_OPTIONS) };
    if (o.struct_size as usize) < std::mem::size_of::<BastionRdpOptions>() {
        return Err(format!("options struct_size {} is smaller than {}", o.struct_size, std::mem::size_of::<BastionRdpOptions>()));
    }
    let flag = |v: u8, what: &str| match v {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(format!("{what} must be 0 or 1, not {v}")),
    };
    if !matches!(o.color_depth, 15 | 16 | 24 | 32) {
        return Err(format!("color_depth must be 15, 16, 24 or 32, not {}", o.color_depth));
    }
    let folder = match text(o.shared_folder).filter(|f| !f.is_empty()) {
        None => None,
        Some(f) => {
            let p = std::path::Path::new(&f);
            if !p.is_absolute() || !p.is_dir() {
                return Err(format!("shared_folder must be an existing absolute folder: {f}"));
            }
            Some(f)
        }
    };
    let gateway = (o.gateway_port != 0).then_some(o.gateway_port);
    Ok((flag(o.nla_only, "nla_only")?, gateway, flag(o.clipboard, "clipboard")?, folder, flag(o.audio, "audio")?, o.color_depth))
}

/// Connects and logs in; blocks until the desktop is up. Returns one of the `RDP_*` codes.
/// NLA only, direct TCP, no redirection, 32-bit colour; see [`bastion_rdp_connect_with_options`].
///
/// # Safety
/// `s` live; `host`, `username`, `password` valid strings; `domain`, `trusted_fingerprint` NULL or
/// valid; `err` NULL or writable.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_rdp_connect(
    s: *const RdpSession,
    host: *const c_char,
    port: u16,
    username: *const c_char,
    domain: *const c_char,
    width: u16,
    height: u16,
    trusted_fingerprint: *const c_char,
    password: *const c_char,
    err: *mut *mut c_char,
) -> i32 {
    bastion_rdp_connect_with_options(s, host, port, username, domain, width, height, trusted_fingerprint, password, ptr::null(), err)
}

/// [`bastion_rdp_connect`] with [`BastionRdpOptions`] (NULL = the old defaults). Invalid options
/// return `RDP_FAILED` with `err` set before any network traffic.
///
/// # Safety
/// As [`bastion_rdp_connect`]; `opts` NULL or a valid [`BastionRdpOptions`] of `struct_size` bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn bastion_rdp_connect_with_options(
    s: *const RdpSession,
    host: *const c_char,
    port: u16,
    username: *const c_char,
    domain: *const c_char,
    width: u16,
    height: u16,
    trusted_fingerprint: *const c_char,
    password: *const c_char,
    opts: *const BastionRdpOptions,
    err: *mut *mut c_char,
) -> i32 {
    let (Some(s), Some(host), Some(username), Some(password)) =
        (session(s), text(host), text(username), text(password))
    else {
        put(err, "missing argument");
        return RDP_FAILED;
    };
    let (nla_only, via_loopback_port, clipboard, shared_folder, audio, color_depth) = match options(opts) {
        Ok(o) => o,
        Err(e) => {
            put(err, &e);
            return RDP_FAILED;
        }
    };
    let target = RdpTarget {
        host,
        port,
        username,
        domain: text(domain).filter(|d| !d.is_empty()),
        width,
        height,
        trusted_fingerprint: text(trusted_fingerprint).filter(|f| !f.is_empty()),
        nla_only,
        via_loopback_port,
        clipboard,
        shared_folder,
        audio,
        color_depth,
    };
    match s.connect(target, password) {
        Ok(()) => RDP_OK,
        Err(RdpError::CertificateUnknown { fingerprint }) => {
            put(err, &fingerprint);
            RDP_CERTIFICATE_UNKNOWN
        }
        Err(RdpError::AuthFailed) => {
            put(err, "authentication failed");
            RDP_AUTH_FAILED
        }
        Err(e) => {
            put(err, &e.to_string());
            RDP_FAILED
        }
    }
}

/// 0 idle, 1 connecting, 2 connected, 3 closed (-1 for a NULL handle).
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_state(s: *const RdpSession) -> i32 {
    match session(s).map(RdpSession::state) {
        Some(RdpState::Idle) => 0,
        Some(RdpState::Connecting) => 1,
        Some(RdpState::Connected) => 2,
        Some(RdpState::Closed) => 3,
        None => -1,
    }
}

/// Why the session closed, or NULL. Free with [`bastion_rdp_string_free`].
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_close_reason(s: *const RdpSession) -> *mut c_char {
    match session(s).and_then(RdpSession::close_reason) {
        Some(r) => CString::new(r.replace('\0', " ")).unwrap_or_default().into_raw(),
        None => ptr::null_mut(),
    }
}

/// Copies the current BGRA picture into `buf` when it changed since `after_serial`.
/// Returns 1 when copied, 0 when unchanged (or nothing yet), -1 when `buf_len` is too small
/// (`width`/`height` are still set so the caller can resize), -2 for a NULL handle.
///
/// # Safety
/// `s` NULL or live; `buf` writable for `buf_len` bytes (or NULL with 0); out pointers writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_frame(
    s: *const RdpSession,
    after_serial: u64,
    buf: *mut u8,
    buf_len: usize,
    width: *mut u16,
    height: *mut u16,
    serial: *mut u64,
) -> i32 {
    let Some(s) = session(s) else { return -2 };
    let Some(frame) = s.frame(after_serial) else { return 0 };
    *width = frame.width;
    *height = frame.height;
    if buf.is_null() || buf_len < frame.bgra.len() {
        return -1;
    }
    ptr::copy_nonoverlapping(frame.bgra.as_ptr(), buf, frame.bgra.len());
    *serial = frame.serial;
    1
}

/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_mouse_move(s: *const RdpSession, x: u16, y: u16) {
    if let Some(s) = session(s) {
        s.mouse_move(x, y);
    }
}

/// `button`: 0 left, 1 right, 2 middle.
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_mouse_button(s: *const RdpSession, button: u8, down: u8) {
    let b = match button {
        0 => RdpPointerButton::Left,
        1 => RdpPointerButton::Right,
        2 => RdpPointerButton::Middle,
        _ => return,
    };
    if let Some(s) = session(s) {
        s.mouse_button(b, down != 0);
    }
}

/// A PC/AT set-1 scancode (`extended` for the E0 prefix).
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_key(s: *const RdpSession, scancode: u8, extended: u8, down: u8) {
    if let Some(s) = session(s) {
        s.key(scancode, extended != 0, down != 0);
    }
}

/// Types UTF-8 `text` as Unicode keyboard events (owner point 29): layout- and modifier-independent, so "." is always ".".
///
/// # Safety
/// `s` NULL or live; `text` NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_type_text(s: *const RdpSession, text: *const c_char) {
    if text.is_null() {
        return;
    }
    let Ok(text) = CStr::from_ptr(text).to_str() else { return };
    if let Some(s) = session(s) {
        s.type_text(text.to_owned());
    }
}

/// Offers UTF-8 `text` copied on this computer to the server (CLIPRDR). Does nothing when the
/// connection does not share the clipboard (no clipboard channel was opened).
///
/// # Safety
/// `s` NULL or live; `text` NULL or a NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_set_local_clipboard(s: *const RdpSession, text: *const c_char) {
    if text.is_null() {
        return;
    }
    let Ok(text) = CStr::from_ptr(text).to_str() else { return };
    if let Some(s) = session(s) {
        s.set_local_clipboard(text.to_owned());
    }
}

/// Text copied on the server since the last call (taken once), or NULL. A NUL inside the text
/// becomes a space. Free with [`bastion_rdp_string_free`].
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_take_remote_clipboard(s: *const RdpSession) -> *mut c_char {
    match session(s).and_then(RdpSession::take_remote_clipboard) {
        Some(t) => CString::new(t.replace('\0', " ")).unwrap_or_default().into_raw(),
        None => ptr::null_mut(),
    }
}

/// Releases every key and modifier still down on the server (focus left the view).
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_release_all(s: *const RdpSession) {
    if let Some(s) = session(s) {
        s.release_all_keys();
    }
}

/// Asks the server to resize its desktop (MS-RDPEDISP Display Control). Sizes are clamped to
/// 200..=8192 with an even width. Sent before the channel opens, it is held and sent once it does;
/// after a reactivation the newest size is asked for again. A server without Display Control
/// keeps its size.
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_resize(s: *const RdpSession, width: u32, height: u32) {
    if let Some(s) = session(s) {
        s.resize(width, height);
    }
}

/// Ends the session gracefully; the handle stays valid until [`bastion_rdp_free`].
///
/// # Safety
/// `s` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_close(s: *const RdpSession) {
    if let Some(s) = session(s) {
        s.close();
    }
}

/// # Safety
/// `s` NULL or a handle from [`bastion_rdp_new`], not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_free(s: *const RdpSession) {
    if !s.is_null() {
        drop(Arc::from_raw(s));
    }
}

/// The OpenH264 library later sessions load (see `set_openh264_library_path`); NULL clears it.
///
/// # Safety
/// `path` NULL or a valid NUL-terminated string.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_set_openh264_library_path(path: *const c_char) {
    crate::set_openh264_library_path(text(path));
}

/// Downloads Cisco's OpenH264 into `codecs_dir` unless it is there, checks its SHA-256 and
/// returns its path (free with [`bastion_rdp_string_free`]), or NULL with `err` set. Blocking:
/// call it off the UI thread. It does not set the path; pass the result to the setter.
///
/// # Safety
/// `codecs_dir` a valid NUL-terminated string; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_install_openh264(codecs_dir: *const c_char, err: *mut *mut c_char) -> *mut c_char {
    let Some(dir) = text(codecs_dir) else {
        put(err, "no codecs folder");
        return ptr::null_mut();
    };
    match crate::openh264::install(std::path::Path::new(&dir)) {
        Ok(p) => CString::new(p.to_string_lossy().into_owned()).map_or(ptr::null_mut(), CString::into_raw),
        Err(e) => {
            put(err, &e);
            ptr::null_mut()
        }
    }
}

/// # Safety
/// `s` NULL or a string returned by this library, not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_rdp_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_without_server() {
        unsafe {
            let mut err = ptr::null_mut();
            let s = bastion_rdp_new(&mut err);
            assert!(!s.is_null());
            assert_eq!(bastion_rdp_state(s), 0);
            assert!(bastion_rdp_close_reason(s).is_null());
            let (mut w, mut h, mut serial) = (0, 0, 0);
            assert_eq!(bastion_rdp_frame(s, 0, ptr::null_mut(), 0, &mut w, &mut h, &mut serial), 0);
            bastion_rdp_mouse_move(s, 1, 1);
            bastion_rdp_key(s, 0x1e, 0, 1);
            bastion_rdp_resize(s, 1024, 768);
            bastion_rdp_resize(ptr::null(), 1024, 768);
            bastion_rdp_close(s);
            bastion_rdp_free(s);
            assert_eq!(bastion_rdp_state(ptr::null()), -1);
        }
    }

    #[test]
    fn refused_port_reports_failure_and_closes() {
        // Bind then drop to get a port with nothing listening.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let host = CString::new("127.0.0.1").unwrap();
        let user = CString::new("u").unwrap();
        let pw = CString::new("p").unwrap();
        unsafe {
            let s = bastion_rdp_new(ptr::null_mut());
            let mut err = ptr::null_mut();
            let rc = bastion_rdp_connect(
                s, host.as_ptr(), port, user.as_ptr(), ptr::null(), 800, 600, ptr::null(), pw.as_ptr(), &mut err,
            );
            assert_eq!(rc, RDP_FAILED);
            assert!(!err.is_null());
            bastion_rdp_string_free(err);
            assert_eq!(bastion_rdp_state(s), 3);
            let reason = bastion_rdp_close_reason(s);
            assert!(!reason.is_null());
            bastion_rdp_string_free(reason);
            bastion_rdp_free(s);
        }
    }

    /// Real server: `BASTION_RDP_TEST=host:port:user:password` (apps/windows/tests/rdp-test-setup.sh starts one).
    /// Unknown certificate first, then a pinned connect, a frame, a wrong password, input and close.
    #[ignore = "live: needs BASTION_RDP_TEST (docs/TESTING.md); run with --ignored"]
    #[test]
    fn real_server_round_trip() {
        // Ignored by default so a run without the lab reports it as ignored, never as a pass
        // (Codex T03); asked for explicitly, a missing lab is a failure.
        let spec = std::env::var("BASTION_RDP_TEST").expect("live test run without BASTION_RDP_TEST: start the fixture (docs/TESTING.md)");
        let parts: Vec<&str> = spec.splitn(4, ':').collect();
        let c = |s: &str| CString::new(s).unwrap();
        let (host, port, user, pw) = (c(parts[0]), parts[1].parse::<u16>().unwrap(), c(parts[2]), c(parts[3]));
        let connect = |fp: *const c_char, pw: &CString| unsafe {
            let s = bastion_rdp_new(ptr::null_mut());
            let mut err = ptr::null_mut();
            let rc = bastion_rdp_connect(s, host.as_ptr(), port, user.as_ptr(), ptr::null(), 1024, 768, fp, pw.as_ptr(), &mut err);
            let text = if err.is_null() { String::new() } else { CStr::from_ptr(err).to_string_lossy().into_owned() };
            bastion_rdp_string_free(err);
            (s, rc, text)
        };
        unsafe {
            let (s, rc, fingerprint) = connect(ptr::null(), &pw);
            assert_eq!(rc, RDP_CERTIFICATE_UNKNOWN, "{fingerprint}");
            assert_eq!(fingerprint.len(), 64);
            bastion_rdp_free(s);
            let fp = c(&fingerprint);

            let (s, rc, text) = connect(fp.as_ptr(), &c("wrong-password"));
            // Servers without NLA (xrdp) finish the RDP handshake before checking the login, then end the
            // session; NLA servers refuse it during connect.
            if rc == RDP_OK {
                std::thread::sleep(std::time::Duration::from_secs(5));
                let reason = bastion_rdp_close_reason(s);
                let why = if reason.is_null() { String::new() } else { CStr::from_ptr(reason).to_string_lossy().into_owned() };
                bastion_rdp_string_free(reason);
                eprintln!("wrong password: state {} reason {why:?}", bastion_rdp_state(s));
            } else {
                eprintln!("wrong password: rc {rc} {text}");
            }
            bastion_rdp_free(s);

            let (s, rc, text) = connect(fp.as_ptr(), &pw);
            assert_eq!(rc, RDP_OK, "{text}");
            std::thread::sleep(std::time::Duration::from_secs(3));
            assert_eq!(bastion_rdp_state(s), 2);
            let (mut w, mut h, mut serial) = (0u16, 0u16, 0u64);
            assert_eq!(bastion_rdp_frame(s, 0, ptr::null_mut(), 0, &mut w, &mut h, &mut serial), -1);
            let mut buf = vec![0u8; w as usize * h as usize * 4];
            assert_eq!(bastion_rdp_frame(s, 0, buf.as_mut_ptr(), buf.len(), &mut w, &mut h, &mut serial), 1);
            assert!(serial > 0 && buf.iter().any(|&b| b != 0), "blank desktop");
            assert_eq!(bastion_rdp_frame(s, serial, buf.as_mut_ptr(), buf.len(), &mut w, &mut h, &mut serial), 0);
            bastion_rdp_mouse_move(s, 100, 100);
            bastion_rdp_mouse_button(s, 0, 1);
            bastion_rdp_mouse_button(s, 0, 0);
            for (code, down) in [(0x2e, 1), (0x2e, 0), (0x1c, 1), (0x1c, 0)] {
                bastion_rdp_key(s, code, 0, down);
            }
            std::thread::sleep(std::time::Duration::from_millis(500));
            assert_eq!(bastion_rdp_state(s), 2, "input broke the session");
            bastion_rdp_close(s);
            std::thread::sleep(std::time::Duration::from_secs(1));
            assert_eq!(bastion_rdp_state(s), 3);
            bastion_rdp_free(s);
        }
    }

    #[test]
    fn clipboard_exports_take_server_text_once_and_tolerate_null() {
        unsafe {
            assert!(bastion_rdp_take_remote_clipboard(ptr::null()).is_null());
            bastion_rdp_set_local_clipboard(ptr::null(), ptr::null());
            let s = bastion_rdp_new(ptr::null_mut());
            assert!(bastion_rdp_take_remote_clipboard(s).is_null(), "nothing copied on the server yet");
            let text = CString::new("from windows").unwrap();
            bastion_rdp_set_local_clipboard(s, text.as_ptr()); // not connected: dropped, no panic
            bastion_rdp_set_local_clipboard(s, ptr::null());
            (*s).shared.lock().unwrap().remote_clipboard = Some("héllo\0 ✓".into()); // as the session loop stores it
            let got = bastion_rdp_take_remote_clipboard(s);
            assert_eq!(CStr::from_ptr(got).to_str().unwrap(), "héllo  ✓");
            bastion_rdp_string_free(got);
            assert!(bastion_rdp_take_remote_clipboard(s).is_null(), "taken once");
            bastion_rdp_free(s);
        }
    }

    #[test]
    fn missing_argument_is_rejected() {
        unsafe {
            let s = bastion_rdp_new(ptr::null_mut());
            let mut err = ptr::null_mut();
            let rc = bastion_rdp_connect(
                s, ptr::null(), 3389, ptr::null(), ptr::null(), 800, 600, ptr::null(), ptr::null(), &mut err,
            );
            assert_eq!(rc, RDP_FAILED);
            bastion_rdp_string_free(err);
            bastion_rdp_free(s);
        }
    }

    #[test]
    fn rdp_options_layout_is_fixed() {
        use std::mem::{offset_of, size_of};
        assert_eq!(offset_of!(BastionRdpOptions, struct_size), 0);
        assert_eq!(offset_of!(BastionRdpOptions, nla_only), 4);
        assert_eq!(offset_of!(BastionRdpOptions, clipboard), 5);
        assert_eq!(offset_of!(BastionRdpOptions, audio), 6);
        assert_eq!(offset_of!(BastionRdpOptions, gateway_port), 8);
        assert_eq!(offset_of!(BastionRdpOptions, color_depth), 12);
        assert_eq!(offset_of!(BastionRdpOptions, shared_folder), 16);
        assert_eq!(size_of::<BastionRdpOptions>(), 24);
    }

    #[test]
    fn rdp_options_are_validated() {
        let ok = |o: &BastionRdpOptions| unsafe { options(o) };
        let base = BastionRdpOptions { struct_size: 24, nla_only: 0, clipboard: 1, audio: 1, _reserved0: 0, gateway_port: 13389, _reserved1: 0, color_depth: 16, shared_folder: ptr::null() };
        assert_eq!(ok(&base).unwrap(), (false, Some(13389), true, None, true, 16));
        assert_eq!(unsafe { options(ptr::null()) }.unwrap(), DEFAULT_OPTIONS, "NULL keeps the old defaults");
        assert_eq!(ok(&BastionRdpOptions { gateway_port: 0, ..base }).unwrap().1, None, "0 is direct TCP");
        for depth in [0, 8, 31, 48] {
            assert!(ok(&BastionRdpOptions { color_depth: depth, ..base }).is_err(), "{depth} refused");
        }
        assert!(ok(&BastionRdpOptions { struct_size: 16, ..base }).is_err(), "too small a struct");
        assert!(ok(&BastionRdpOptions { nla_only: 2, ..base }).is_err());
        let dir = std::env::temp_dir();
        let folder = CString::new(dir.to_str().unwrap()).unwrap();
        assert_eq!(ok(&BastionRdpOptions { shared_folder: folder.as_ptr(), ..base }).unwrap().3.as_deref(), dir.to_str());
        let relative = CString::new("relative/dir").unwrap();
        assert!(ok(&BastionRdpOptions { shared_folder: relative.as_ptr(), ..base }).is_err());
        let missing = CString::new(dir.join("no-such-bastion-dir").to_str().unwrap()).unwrap();
        assert!(ok(&BastionRdpOptions { shared_folder: missing.as_ptr(), ..base }).is_err());
    }

    #[test]
    fn invalid_options_fail_before_connecting() {
        let s = unsafe { bastion_rdp_new(ptr::null_mut()) };
        let c = |v: &str| CString::new(v).unwrap();
        let (h, u, p) = (c("127.0.0.1"), c("u"), c("p"));
        let bad = BastionRdpOptions { struct_size: 24, nla_only: 1, clipboard: 0, audio: 0, _reserved0: 0, gateway_port: 0, _reserved1: 0, color_depth: 7, shared_folder: ptr::null() };
        let mut err = ptr::null_mut();
        let r = unsafe { bastion_rdp_connect_with_options(s, h.as_ptr(), 1, u.as_ptr(), ptr::null(), 800, 600, ptr::null(), p.as_ptr(), &bad, &mut err) };
        assert_eq!(r, RDP_FAILED);
        let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
        assert!(msg.contains("color_depth"), "{msg}");
        unsafe {
            bastion_rdp_string_free(err);
            bastion_rdp_free(s);
        }
    }
}