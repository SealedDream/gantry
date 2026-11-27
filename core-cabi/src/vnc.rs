//! VNC over the C ABI: one viewer per tab, on the core's `vnc` module (RFB, VNC password auth).
//!
//! `bastion_vnc_connect` blocks on the network, so hosts call it off the UI thread; the other calls
//! are cheap. The password is used once, only if the server asks for one, and never kept. RFB has
//! no transport encryption here (see SECURITY.md). Free a viewer with [`bastion_vnc_free`].
use std::ffi::c_char;
use std::sync::Arc;

use bastion_ffi::{FfiError, VncButton, VncViewer};

use crate::{guarded, optional, required, to_c};

/// Opaque handle for one VNC viewer.
pub struct BastionVnc(Arc<VncViewer>);


/// Connect to `host:port`. On success writes the viewer to `*out` and returns 0; otherwise returns
/// -1 (or [`crate::CONNECT_AUTH_FAILED`] when the server refused the password) and sets `*err`.
///
/// # Safety
/// `host` valid NUL-terminated UTF-8; `password` NULL or valid; `out` writable; `err` NULL or writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_connect(
    host: *const c_char,
    port: u16,
    password: *const c_char,
    out: *mut *mut BastionVnc,
    err: *mut *mut c_char,
) -> i32 {
    if !out.is_null() {
        *out = std::ptr::null_mut();
    }
    let mut auth = false;
    let rc = guarded(err, -1, || {
        if out.is_null() {
            return Err("out is required".into());
        }
        let host = required(host, "host")?;
        let password = optional(password, "password")?.filter(|p| !p.is_empty());
        match bastion_ffi::vnc_connect(host, port, password) {
            Ok(v) => {
                *out = Box::into_raw(Box::new(BastionVnc(v)));
                Ok(0)
            }
            Err(FfiError::AuthFailed) => {
                auth = true;
                Err("authentication failed".into())
            }
            Err(e) => Err(e.to_string()),
        }
    });
    if auth { crate::CONNECT_AUTH_FAILED } else { rc }
}

unsafe fn vnc<'a>(v: *const BastionVnc) -> Option<&'a VncViewer> {
    v.as_ref().map(|v| &*v.0)
}

/// 1 once the server or network ended the session (or for a NULL handle), else 0.
///
/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_is_closed(v: *const BastionVnc) -> i32 {
    vnc(v).map_or(1, |v| v.is_closed() as i32)
}

/// Why the session closed, or NULL. Free with [`crate::bastion_string_free`].
///
/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_close_reason(v: *const BastionVnc) -> *mut c_char {
    vnc(v).and_then(VncViewer::close_reason).map(to_c).unwrap_or(std::ptr::null_mut())
}

/// Copies the current BGRA picture into `buf` when it changed since `after_serial`.
/// 1 copied, 0 unchanged, -1 `buf_len` too small (`width`/`height` set), -2 NULL handle.
///
/// # Safety
/// `v` NULL or live; `buf` writable for `buf_len` bytes (or NULL with 0); out pointers writable.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_frame(
    v: *const BastionVnc,
    after_serial: u64,
    buf: *mut u8,
    buf_len: usize,
    width: *mut u16,
    height: *mut u16,
    serial: *mut u64,
) -> i32 {
    let Some(v) = vnc(v) else { return -2 };
    let Some(f) = v.frame(after_serial) else { return 0 };
    *width = f.width;
    *height = f.height;
    if buf.is_null() || buf_len < f.bgra.len() {
        return -1;
    }
    std::ptr::copy_nonoverlapping(f.bgra.as_ptr(), buf, f.bgra.len());
    *serial = f.serial;
    1
}

/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_mouse_move(v: *const BastionVnc, x: u16, y: u16) {
    if let Some(v) = vnc(v) {
        v.mouse_move(x, y);
    }
}

/// `button`: 0 left, 1 middle, 2 right, 3 wheel up, 4 wheel down.
///
/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_mouse_button(v: *const BastionVnc, button: u8, down: u8) {
    let b = match button {
        0 => VncButton::Left,
        1 => VncButton::Middle,
        2 => VncButton::Right,
        3 => VncButton::WheelUp,
        4 => VncButton::WheelDown,
        _ => return,
    };
    if let Some(v) = vnc(v) {
        v.mouse_button(b, down != 0);
    }
}

/// An X11 keysym (RFC 6143 §7.5.4).
///
/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_key(v: *const BastionVnc, keysym: u32, down: u8) {
    if let Some(v) = vnc(v) {
        v.key(keysym, down != 0);
    }
}

/// ABI 129 (RDP-VNC-FIT): asks the server to resize its desktop to the view (ExtendedDesktopSize,
/// SetDesktopSize). A server that refuses or lacks the extension keeps its size; nothing is reported.
///
/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_resize(v: *const BastionVnc, width: u16, height: u16) {
    if let Some(v) = vnc(v) {
        v.resize(width, height);
    }
}

/// # Safety
/// `v` NULL or live.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_close(v: *const BastionVnc) {
    if let Some(v) = vnc(v) {
        v.close();
    }
}

/// # Safety
/// `v` NULL or a handle from [`bastion_vnc_connect`], not used afterwards.
#[no_mangle]
pub unsafe extern "C" fn bastion_vnc_free(v: *mut BastionVnc) {
    if !v.is_null() {
        let v = Box::from_raw(v);
        v.0.close();
    }
}
