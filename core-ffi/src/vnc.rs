//! VNC bridge: one `VncViewer` per tab. `vnc_connect` blocks on the shared runtime, so the UI
//! calls it off the main thread; the other calls are cheap and safe from the main thread.
use std::sync::Arc;

use bastion_core::vnc::{self, VncSession};

use crate::terminal::RUNTIME;
use crate::FfiResult;

/// A full copy of the desktop in BGRA order (what CoreGraphics wants for little-endian 32-bit).
#[derive(uniffi::Record)]
pub struct VncFrame {
    pub width: u16,
    pub height: u16,
    pub serial: u64,
    pub bgra: Vec<u8>,
}

#[derive(uniffi::Enum)]
pub enum VncButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
}

#[derive(uniffi::Object)]
pub struct VncViewer {
    session: VncSession,
}

/// Connects to `host:port`. The password is used once, only if the server asks for one.
#[uniffi::export]
pub fn vnc_connect(host: String, port: u16, password: Option<String>) -> FfiResult<Arc<VncViewer>> {
    crate::policy::policy_check_protocol("vnc".into())?;
    let session = RUNTIME.block_on(VncSession::connect(&host, port, password))?;
    Ok(Arc::new(VncViewer { session }))
}

#[uniffi::export]
impl VncViewer {
    pub fn is_closed(&self) -> bool {
        self.session.state() == vnc::VncState::Closed
    }

    pub fn close_reason(&self) -> Option<String> {
        self.session.close_reason()
    }

    /// The current picture, or nil when nothing changed since `after_serial`.
    pub fn frame(&self, after_serial: u64) -> Option<VncFrame> {
        self.session.frame(after_serial).map(|f| VncFrame { width: f.width, height: f.height, serial: f.serial, bgra: f.bgra })
    }

    pub fn mouse_move(&self, x: u16, y: u16) {
        self.session.mouse_move(x, y);
    }

    pub fn mouse_button(&self, button: VncButton, down: bool) {
        let button = match button {
            VncButton::Left => vnc::VncButton::Left,
            VncButton::Middle => vnc::VncButton::Middle,
            VncButton::Right => vnc::VncButton::Right,
            VncButton::WheelUp => vnc::VncButton::WheelUp,
            VncButton::WheelDown => vnc::VncButton::WheelDown,
        };
        self.session.mouse_button(button, down);
    }

    /// Sends an X11 keysym.
    pub fn key(&self, keysym: u32, down: bool) {
        self.session.key(keysym, down);
    }

    /// Asks the server to resize its desktop to the view (ExtendedDesktopSize); refusals are ignored.
    pub fn resize(&self, width: u16, height: u16) {
        self.session.resize(width, height);
    }

    pub fn close(&self) {
        self.session.close();
    }
}
