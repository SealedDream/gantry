//! VNC (RFB) client built on `vnc-rs`. A session keeps one BGRA copy of the remote framebuffer
//! that the frontend polls, and forwards pointer and key input.
//!
//! Security: classic VNC authentication is a DES challenge and the RFB stream is not encrypted,
//! so connections should go through an SSH tunnel when they leave a trusted network
//! (see SECURITY.md). The password is used once per connect and never stored.
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;
use vnc::{PixelFormat, VncConnector, VncEncoding, VncEvent, X11Event};

use crate::{CoreError, Result};

/// How often the server is asked for an incremental update.
const REFRESH_INTERVAL: Duration = Duration::from_millis(33);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BYTES_PER_PIXEL: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VncState {
    Connected,
    Closed,
}

/// A full copy of the desktop, 4 bytes per pixel in B, G, R, A order.
#[derive(Debug, Clone)]
pub struct VncFrame {
    pub width: u16,
    pub height: u16,
    /// Increases whenever the picture changed.
    pub serial: u64,
    pub bgra: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VncButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
}

impl VncButton {
    /// RFB pointer mask bit (RFC 6143 §7.5.5).
    fn mask(self) -> u8 {
        match self {
            VncButton::Left => 1,
            VncButton::Middle => 2,
            VncButton::Right => 4,
            VncButton::WheelUp => 8,
            VncButton::WheelDown => 16,
        }
    }
}

/// Largest clipboard text exchanged with a VNC server, either way.
pub const MAX_VNC_CLIPBOARD: usize = 64 * 1024;

enum Input {
    Pointer { x: u16, y: u16, buttons: u8 },
    Key { keysym: u32, down: bool },
    CutText(String),
    Close,
}

#[derive(Default)]
struct Framebuffer {
    width: u16,
    height: u16,
    serial: u64,
    bgra: Vec<u8>,
    closed: Option<String>,
    /// The server's latest clipboard text (ServerCutText), until the UI takes it.
    server_text: Option<String>,
}

impl Framebuffer {
    fn resize(&mut self, width: u16, height: u16) {
        self.width = width;
        self.height = height;
        self.bgra = vec![0; width as usize * height as usize * BYTES_PER_PIXEL];
        self.serial += 1;
    }

    /// Copies a decoded rectangle in; rectangles that do not fit are ignored, not trusted.
    fn blit(&mut self, rect: vnc::Rect, data: &[u8]) {
        let (x, y, w, h) = (rect.x as usize, rect.y as usize, rect.width as usize, rect.height as usize);
        let stride = self.width as usize * BYTES_PER_PIXEL;
        if x + w > self.width as usize || y + h > self.height as usize || data.len() < w * h * BYTES_PER_PIXEL {
            return;
        }
        for row in 0..h {
            let src = &data[row * w * BYTES_PER_PIXEL..(row + 1) * w * BYTES_PER_PIXEL];
            let start = (y + row) * stride + x * BYTES_PER_PIXEL;
            self.bgra[start..start + src.len()].copy_from_slice(src);
        }
        self.serial += 1;
    }

    fn copy(&mut self, dst: vnc::Rect, src: vnc::Rect) {
        let (w, h) = (src.width as usize, src.height as usize);
        let fits = |r: vnc::Rect| r.x as usize + w <= self.width as usize && r.y as usize + h <= self.height as usize;
        if !fits(src) || !fits(dst) {
            return;
        }
        let stride = self.width as usize * BYTES_PER_PIXEL;
        let mut rows = Vec::with_capacity(w * h * BYTES_PER_PIXEL);
        for row in 0..h {
            let start = (src.y as usize + row) * stride + src.x as usize * BYTES_PER_PIXEL;
            rows.extend_from_slice(&self.bgra[start..start + w * BYTES_PER_PIXEL]);
        }
        self.blit(vnc::Rect { width: src.width, height: src.height, ..dst }, &rows);
    }
}

/// One VNC connection. Its background task runs on the runtime that called `connect`.
pub struct VncSession {
    shared: Arc<Mutex<Framebuffer>>,
    input: mpsc::UnboundedSender<Input>,
    /// Newest desktop size wanted by the view, for `resize_loop`.
    size: tokio::sync::watch::Sender<Option<(u16, u16)>>,
    buttons: Mutex<u8>,
    position: Mutex<(u16, u16)>,
}

impl VncSession {
    /// Connects and completes the RFB handshake. `password` is only used if the server asks.
    pub async fn connect(host: &str, port: u16, password: Option<String>) -> Result<Self> {
        Self::connect_within(CONNECT_TIMEOUT, host, port, password).await
    }

    /// One deadline covers TCP connect and the whole RFB handshake, so a server that accepts
    /// and then stalls cannot hang the caller; the socket is dropped on expiry.
    async fn connect_within(limit: Duration, host: &str, port: u16, password: Option<String>) -> Result<Self> {
        tokio::time::timeout(limit, Self::handshake(host, port, password)).await.map_err(|_| CoreError::Timeout)?
    }

    async fn handshake(host: &str, port: u16, password: Option<String>) -> Result<Self> {
        let tcp = tokio::net::TcpStream::connect((host, port)).await?;
        let client = VncConnector::new(tcp)
            .set_auth_method(async move { password.ok_or(vnc::VncError::NoPassword) })
            .add_encoding(VncEncoding::Zrle)
            .add_encoding(VncEncoding::CopyRect)
            .add_encoding(VncEncoding::Raw)
            .add_encoding(VncEncoding::DesktopSizePseudo)
            .add_encoding(VncEncoding::ExtendedDesktopSizePseudo)
            .allow_shared(true)
            .set_pixel_format(PixelFormat::bgra())
            .build()
            .map_err(vnc_error)?
            .try_start()
            .await
            .map_err(vnc_error)?
            .finish()
            .map_err(vnc_error)?;
        let shared = Arc::new(Mutex::new(Framebuffer::default()));
        let (tx, rx) = mpsc::unbounded_channel();
        let (size_tx, size_rx) = tokio::sync::watch::channel(None);
        let client = Arc::new(client);
        let task_shared = Arc::clone(&shared);
        let resizer = tokio::spawn(resize_loop(Arc::clone(&client), size_rx));
        tokio::spawn(async move {
            let reason = run(client, rx, Arc::clone(&task_shared)).await;
            resizer.abort();
            task_shared.lock().unwrap().closed = Some(reason);
        });
        Ok(Self { shared, input: tx, size: size_tx, buttons: Mutex::new(0), position: Mutex::new((0, 0)) })
    }

    pub fn state(&self) -> VncState {
        if self.shared.lock().unwrap().closed.is_some() { VncState::Closed } else { VncState::Connected }
    }

    /// Why the session ended, once it has.
    pub fn close_reason(&self) -> Option<String> {
        self.shared.lock().unwrap().closed.clone()
    }

    /// The current picture, or `None` when nothing changed since `after_serial`.
    pub fn frame(&self, after_serial: u64) -> Option<VncFrame> {
        let fb = self.shared.lock().unwrap();
        if fb.serial == after_serial || fb.bgra.is_empty() {
            return None;
        }
        Some(VncFrame { width: fb.width, height: fb.height, serial: fb.serial, bgra: fb.bgra.clone() })
    }

    pub fn mouse_move(&self, x: u16, y: u16) {
        *self.position.lock().unwrap() = (x, y);
        let buttons = *self.buttons.lock().unwrap();
        let _ = self.input.send(Input::Pointer { x, y, buttons });
    }

    pub fn mouse_button(&self, button: VncButton, down: bool) {
        let buttons = {
            let mut mask = self.buttons.lock().unwrap();
            *mask = if down { *mask | button.mask() } else { *mask & !button.mask() };
            *mask
        };
        let (x, y) = *self.position.lock().unwrap();
        let _ = self.input.send(Input::Pointer { x, y, buttons });
    }

    /// Sends an X11 keysym; the frontend maps platform keys to keysyms.
    pub fn key(&self, keysym: u32, down: bool) {
        let _ = self.input.send(Input::Key { keysym, down });
    }

    /// Asks the server to resize its desktop (RFB ExtendedDesktopSize, SetDesktopSize). Only the
    /// latest size is sent; a server that refuses or lacks the extension keeps its size.
    pub fn resize(&self, width: u16, height: u16) {
        let (w, h) = desktop_size(width, height);
        self.size.send_replace(Some((w, h)));
    }

    pub fn close(&self) {
        let _ = self.input.send(Input::Close);
    }

    /// Send local clipboard text to the server (ClientCutText). Text over the size limit is refused.
    pub fn send_clipboard(&self, text: &str) -> Result<()> {
        if text.len() > MAX_VNC_CLIPBOARD {
            return Err(CoreError::Invalid("clipboard text is too large to send".into()));
        }
        self.input.send(Input::CutText(text.to_string())).map_err(|_| CoreError::Invalid("VNC session is closed".into()))
    }

    /// The server's clipboard text received since the last call, if any.
    pub fn take_server_clipboard(&self) -> Option<String> {
        self.shared.lock().unwrap().server_text.take()
    }
}

impl Drop for VncSession {
    fn drop(&mut self) {
        self.close();
    }
}

fn vnc_error(e: vnc::VncError) -> CoreError {
    match e {
        vnc::VncError::WrongPassword | vnc::VncError::NoPassword => CoreError::AuthFailed,
        // RFB 3.8 servers (x11vnc) follow a failed SecurityResult with their own reason string, which vnc-rs
        // passes on as a general error ("password check failed!").
        vnc::VncError::General(m) if is_auth_reason(&m) => CoreError::AuthFailed,
        e => CoreError::Invalid(format!("VNC: {e}")),
    }
}

fn is_auth_reason(message: &str) -> bool {
    let m = message.to_ascii_lowercase();
    m.contains("password") || m.contains("authentication") || m.contains("auth failed")
}

fn apply(event: VncEvent, fb: &Mutex<Framebuffer>) -> Option<String> {
    let mut fb = fb.lock().unwrap();
    match event {
        VncEvent::SetResolution(screen) => fb.resize(screen.width, screen.height),
        // ExtendedDesktopSize: a resize (ours or another client's) that the server applied.
        VncEvent::DesktopUpdate(vnc::DesktopUpdate { layout: Some(layout), .. }) if (layout.width, layout.height) != (fb.width, fb.height) => {
            fb.resize(layout.width, layout.height)
        }
        VncEvent::RawImage(rect, data) => fb.blit(rect, &data),
        VncEvent::Copy(dst, src) => fb.copy(dst, src),
        VncEvent::Error(message) => return Some(message),
        VncEvent::Text(text) if text.len() <= MAX_VNC_CLIPBOARD => fb.server_text = Some(text),
        _ => {}
    }
    None
}

/// Applies server updates and forwards input until the link ends; returns why it ended.
/// Smallest and largest side asked of a server; RFB sides are u16 and tiny desktops are useless.
const MIN_SIDE: u16 = 200;
const MAX_SIDE: u16 = 8192;

fn desktop_size(width: u16, height: u16) -> (u16, u16) {
    (width.clamp(MIN_SIDE, MAX_SIDE), height.clamp(MIN_SIDE, MAX_SIDE))
}

/// Wait before asking again while the server has not yet announced ExtendedDesktopSize support
/// (it does so in its first update) or another resize is still pending.
const RESIZE_RETRY: Duration = Duration::from_millis(500);
/// Retries per requested size; a server that never announces support keeps its size.
const RESIZE_ATTEMPTS: u32 = 10;

/// Sends one SetDesktopSize at a time, always for the newest requested size. Refusals are
/// final for that size: the server keeps its size and the view scales it.
async fn resize_loop(client: Arc<vnc::VncClient>, mut sizes: tokio::sync::watch::Receiver<Option<(u16, u16)>>) {
    let mut retry: Option<((u16, u16), u32)> = None;
    loop {
        let (size, attempt) = match retry.take() {
            Some((size, attempt)) => {
                tokio::select! {
                    changed = sizes.changed() => {
                        if changed.is_err() { return; }
                        match *sizes.borrow_and_update() { Some(s) => (s, 0), None => continue }
                    }
                    _ = tokio::time::sleep(RESIZE_RETRY) => (size, attempt),
                }
            }
            None => {
                if sizes.changed().await.is_err() { return; }
                match *sizes.borrow_and_update() { Some(s) => (s, 0), None => continue }
            }
        };
        match client.resize_desktop(size.0, size.1).await {
            Err(vnc::ResizeError::Unsupported | vnc::ResizeError::Busy) if attempt + 1 < RESIZE_ATTEMPTS => {
                retry = Some((size, attempt + 1));
            }
            _ => {}
        }
    }
}

async fn run(client: Arc<vnc::VncClient>, mut input: mpsc::UnboundedReceiver<Input>, shared: Arc<Mutex<Framebuffer>>) -> String {
    let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
    loop {
        tokio::select! {
            event = client.recv_event() => match event {
                Ok(event) => if let Some(reason) = apply(event, &shared) {
                    let _ = client.close().await;
                    return reason;
                },
                Err(e) => return format!("connection lost: {e}"),
            },
            msg = input.recv() => {
                let event = match msg {
                    Some(Input::Pointer { x, y, buttons }) => X11Event::PointerEvent((x, y, buttons).into()),
                    Some(Input::Key { keysym, down }) => X11Event::KeyEvent((keysym, down).into()),
                    Some(Input::CutText(text)) => X11Event::CopyText(text),
                    Some(Input::Close) | None => {
                        let _ = client.close().await;
                        return "closed".into();
                    }
                };
                if let Err(e) = client.input(event).await {
                    return format!("connection lost: {e}");
                }
            }
            _ = refresh.tick() => {
                if let Err(e) = client.input(X11Event::Refresh).await {
                    return format!("connection lost: {e}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Codex R01: a server that accepts and never sends the RFB greeting times out.
    #[tokio::test]
    async fn stalled_handshake_times_out() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let started = std::time::Instant::now();
        let r = super::VncSession::connect_within(Duration::from_millis(300), "127.0.0.1", port, None).await;
        assert!(matches!(r, Err(CoreError::Timeout)), "expected timeout");
        assert!(started.elapsed() < Duration::from_secs(5));
        server.abort();
    }

    use super::*;

    fn rect(x: u16, y: u16, width: u16, height: u16) -> vnc::Rect {
        vnc::Rect { x, y, width, height }
    }

    #[test]
    fn server_clipboard_is_kept_once_and_bounded() {
        let fb = Mutex::new(Framebuffer::default());
        apply(VncEvent::Text("from server".into()), &fb);
        assert_eq!(fb.lock().unwrap().server_text.take().as_deref(), Some("from server"));
        assert_eq!(fb.lock().unwrap().server_text.take(), None);
        apply(VncEvent::Text("x".repeat(MAX_VNC_CLIPBOARD + 1)), &fb);
        assert_eq!(fb.lock().unwrap().server_text, None, "oversized text is dropped");
    }

    #[test]
    fn blit_writes_rows_at_offset_and_bumps_serial() {
        let mut fb = Framebuffer::default();
        fb.resize(3, 2);
        let before = fb.serial;
        fb.blit(rect(1, 1, 2, 1), &[1, 1, 1, 1, 2, 2, 2, 2]);
        assert_eq!(&fb.bgra[16..24], &[1, 1, 1, 1, 2, 2, 2, 2]);
        assert_eq!(&fb.bgra[..16], &[0; 16]);
        assert_eq!(fb.serial, before + 1);
    }

    #[test]
    fn blit_ignores_rectangles_outside_the_desktop() {
        let mut fb = Framebuffer::default();
        fb.resize(2, 2);
        let before = fb.serial;
        fb.blit(rect(1, 1, 2, 2), &[9; 16]);
        fb.blit(rect(0, 0, 2, 2), &[9; 4]);
        assert!(fb.bgra.iter().all(|&b| b == 0));
        assert_eq!(fb.serial, before);
    }

    #[test]
    fn copy_moves_a_rectangle() {
        let mut fb = Framebuffer::default();
        fb.resize(2, 1);
        fb.blit(rect(0, 0, 1, 1), &[7, 7, 7, 7]);
        fb.copy(rect(1, 0, 0, 0), rect(0, 0, 1, 1));
        assert_eq!(fb.bgra, vec![7; 8]);
    }

    #[test]
    fn requested_desktop_size_is_clamped() {
        assert_eq!(super::desktop_size(1600, 900), (1600, 900));
        assert_eq!(super::desktop_size(10, 10), (200, 200));
        assert_eq!(super::desktop_size(9000, 9000), (8192, 8192));
    }

    #[test]
    fn applied_desktop_update_resizes_the_picture() {
        let fb = Mutex::new(Framebuffer::default());
        fb.lock().unwrap().resize(1024, 768);
        let layout = vnc::DesktopLayout { width: 1300, height: 700, screens: Vec::new() };
        let update = vnc::DesktopUpdate { reason: vnc::DesktopReason::ThisClient, status: vnc::DesktopStatus::Success, layout: Some(layout) };
        assert!(apply(VncEvent::DesktopUpdate(update), &fb).is_none());
        let fb = fb.lock().unwrap();
        assert_eq!((fb.width, fb.height), (1300, 700));
    }

    #[test]
    fn button_masks_follow_rfb() {
        assert_eq!(VncButton::Left.mask() | VncButton::Middle.mask() | VncButton::Right.mask(), 7);
        assert_eq!(VncButton::WheelDown.mask(), 16);
    }

    /// Live check against a server: `BASTION_VNC_ADDR=127.0.0.1:59000 BASTION_VNC_PASSWORD=…
    /// cargo test --lib vnc::tests::live -- --ignored` (see docs/TESTING.md).
    #[tokio::test]
    #[ignore]
    async fn live_server_sends_a_desktop() {
        let addr = std::env::var("BASTION_VNC_ADDR").expect("BASTION_VNC_ADDR");
        let (host, port) = addr.rsplit_once(':').expect("host:port");
        let password = std::env::var("BASTION_VNC_PASSWORD").ok();
        let session = VncSession::connect(host, port.parse().unwrap(), password).await.unwrap();
        let mut frame = None;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            frame = session.frame(0).filter(|f| f.bgra.iter().any(|&b| b != 0));
            if frame.is_some() {
                break;
            }
        }
        let frame = frame.expect("no picture within 5 s");
        assert!(frame.width > 0 && frame.height > 0);
        session.close();
    }

    /// RDP-VNC-FIT: a server with ExtendedDesktopSize (TigerVNC Xvnc) follows the requested size.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs BASTION_VNC_ADDR of a server that accepts SetDesktopSize"]
    async fn live_server_follows_resize() {
        let addr = std::env::var("BASTION_VNC_ADDR").expect("BASTION_VNC_ADDR");
        let (host, port) = addr.rsplit_once(':').expect("host:port");
        let password = std::env::var("BASTION_VNC_PASSWORD").ok();
        let session = VncSession::connect(host, port.parse().unwrap(), password).await.unwrap();
        for (w, h) in [(1300u16, 700u16), (900, 600)] {
            session.resize(w, h);
            let mut size = (0, 0);
            for _ in 0..80 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                if let Some(f) = session.frame(0) { size = (f.width, f.height); }
                if size == (w, h) { break; }
            }
            assert_eq!(size, (w, h), "desktop did not follow the resize");
        }
        session.close();
    }

    #[test]
    fn wrong_password_maps_to_auth_failed() {
        assert!(matches!(vnc_error(vnc::VncError::General("password check failed!".into())), CoreError::AuthFailed));
        assert!(matches!(vnc_error(vnc::VncError::General("too many clients".into())), CoreError::Invalid(_)));
        assert!(matches!(vnc_error(vnc::VncError::WrongPassword), CoreError::AuthFailed));
    }
}
