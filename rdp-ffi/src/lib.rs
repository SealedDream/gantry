//! RDP adapter (IronRDP) exposed to the native frontends over UniFFI.
//!
//! This crate is deliberately separate from `bastion-core`: IronRDP's dependency graph cannot
//! resolve together with russh (see ARCHITECTURE.md). It therefore keeps its own small
//! connect/run loop instead of `core::session::spawn_supervised`; the frontend owns reconnect.
//!
//! Secrets: the password is passed in for one `connect` call and never stored or returned.
use std::sync::{Arc, Mutex};

use ironrdp_connector::connection_activation::{ConnectionActivationFactory, ConnectionActivationState};
use ironrdp_connector::{ClientConnector, ConnectionOutcome};
use ironrdp_dvc::DrdynvcClient;
use ironrdp_egfx::client::{GraphicsPipelineClient, GraphicsPipelineHandler};
use ironrdp_egfx::decode::{H264Decoder, OpenH264Decoder};
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_input::{Database, MouseButton, MousePosition, Operation, Scancode};
use ironrdp_session::image::DecodedImage;
use ironrdp_session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput};
use sha2::{Digest, Sha256};
use ironrdp_tokio::FramedWrite as _;
use tokio::sync::mpsc;

mod cabi;
mod channels;
mod config;
mod frame;
pub mod openh264;
mod tls;

pub use frame::{RdpDirtyRect, RdpFrameUpdate};
use frame::Picture;

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RdpError {
    #[error("{message}")]
    Failed { message: String },
    /// The server's TLS certificate is not trusted yet. Show the fingerprint, let the user
    /// verify it, then retry with `trusted_fingerprint` set to it.
    #[error("unknown certificate {fingerprint}")]
    CertificateUnknown { fingerprint: String },
    #[error("authentication failed")]
    AuthFailed,
}

fn failed(e: impl std::fmt::Display) -> RdpError {
    RdpError::Failed { message: e.to_string() }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct RdpTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub domain: Option<String>,
    pub width: u16,
    pub height: u16,
    /// SHA-256 (hex) of the server certificate the user accepted earlier, if any.
    pub trusted_fingerprint: Option<String>,
    /// Offer only Network Level Authentication (CredSSP): a server that wants plain TLS
    /// security, where the password is typed on its login screen, is refused.
    pub nla_only: bool,
    /// Set when the connection goes through a gateway: TCP goes to this loopback port (the
    /// gateway's forward) while `host` stays the name the certificate pin and CredSSP use.
    pub via_loopback_port: Option<u16>,
    /// Share text copied on either side (CLIPRDR, Unicode text only).
    pub clipboard: bool,
    /// An absolute path of a folder on this Mac to share with the server as drive "Gantry".
    pub shared_folder: Option<String>,
    /// Play the server's sound on this Mac.
    pub audio: bool,
    /// Bits per pixel the server should send: 15, 16, 24 or 32 (anything else is 32).
    #[uniffi(default = 32)]
    pub color_depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RdpState {
    Idle,
    Connecting,
    Connected,
    Closed,
}

/// A full copy of the desktop in BGRA order (what CoreGraphics wants for little-endian 32-bit).
#[derive(Debug, Clone, uniffi::Record)]
pub struct RdpFrame {
    pub width: u16,
    pub height: u16,
    /// Increases whenever the picture changed; the view skips redraws when it did not.
    pub serial: u64,
    pub bgra: Vec<u8>,
}

#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum RdpPointerButton {
    Left,
    Right,
    Middle,
}

enum Input {
    Move { x: u16, y: u16 },
    Button { button: RdpPointerButton, down: bool },
    Key { scancode: u16, extended: bool, down: bool },
    /// A typed character sent as a Unicode keyboard event (layout-independent).
    Unicode { ch: char, down: bool },
    /// Release every key the server still thinks is down (focus left the view).
    ReleaseAll,
    /// Text copied on this Mac, offered to the server.
    Clipboard(String),
    /// The view's new size in pixels, sent over Display Control.
    Resize { width: u32, height: u32 },
    Close,
}

struct Shared {
    state: RdpState,
    reason: Option<String>,
    picture: Picture,
    /// Text copied on the server, waiting for the app to put it on the Mac's pasteboard.
    remote_clipboard: Option<String>,
    /// Whether this connection shares the clipboard (set at connect).
    clipboard: bool,
}

/// Counters the channels update outside `Shared`.
#[derive(Default)]
struct Counters {
    audio_bytes: Arc<std::sync::atomic::AtomicU64>,
}

/// One RDP connection. Create it, `connect`, poll `frame`, feed input, `close`.
#[derive(uniffi::Object)]
pub struct RdpSession {
    runtime: tokio::runtime::Runtime,
    shared: Arc<Mutex<Shared>>,
    input: Mutex<Option<mpsc::UnboundedSender<Input>>>,
    counters: Counters,
}

#[uniffi::export]
impl RdpSession {
    #[uniffi::constructor]
    pub fn new() -> Result<Arc<Self>, RdpError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(failed)?;
        let shared = Shared { state: RdpState::Idle, reason: None, picture: Picture::default(), remote_clipboard: None, clipboard: false };
        Ok(Arc::new(Self { runtime, shared: Arc::new(Mutex::new(shared)), input: Mutex::new(None), counters: Counters::default() }))
    }

    /// Connects and authenticates, then keeps the session running in the background.
    /// Blocks until the desktop is up, or returns the reason it could not be reached.
    pub fn connect(&self, target: RdpTarget, password: String) -> Result<(), RdpError> {
        self.set_state(RdpState::Connecting, None);
        let (clip_tx, clip_rx) = mpsc::unbounded_channel();
        let (stage, framed, image, activation) = match self.runtime.block_on(with_deadline(establish(&target, password, clip_tx, self.counters.audio_bytes.clone()))) {
            Ok(parts) => parts,
            Err(e) => {
                self.set_state(RdpState::Closed, Some(e.to_string()));
                return Err(e);
            }
        };
        let (tx, rx) = mpsc::unbounded_channel();
        *self.input.lock().unwrap() = Some(tx);
        {
            let mut s = self.shared.lock().unwrap();
            s.picture.replace(image.width(), image.height(), image.data());
            s.state = RdpState::Connected;
            s.clipboard = target.clipboard;
        }
        let shared = Arc::clone(&self.shared);
        self.runtime.spawn(async move {
            let reason = run(stage, framed, image, activation, rx, clip_rx, Arc::clone(&shared)).await;
            let mut s = shared.lock().unwrap();
            s.state = RdpState::Closed;
            s.reason = Some(reason);
        });
        Ok(())
    }

    pub fn state(&self) -> RdpState {
        self.shared.lock().unwrap().state
    }

    /// Why the session closed, once it has.
    pub fn close_reason(&self) -> Option<String> {
        self.shared.lock().unwrap().reason.clone()
    }

    /// The current picture, or `None` when nothing changed since `after_serial`.
    /// Copies the whole desktop; views that redraw often should use `frame_update`.
    pub fn frame(&self, after_serial: u64) -> Option<RdpFrame> {
        let s = self.shared.lock().unwrap();
        let p = &s.picture;
        if p.serial == after_serial || p.is_empty() {
            return None;
        }
        Some(RdpFrame { width: p.width, height: p.height, serial: p.serial, bgra: p.bgra() })
    }

    /// Only the regions that changed since `after_serial` (the serial of the last update this
    /// caller applied), or the whole desktop when `full` is set. One consumer per session.
    pub fn frame_update(&self, after_serial: u64) -> Option<RdpFrameUpdate> {
        self.shared.lock().unwrap().picture.take_update(after_serial)
    }

    pub fn mouse_move(&self, x: u16, y: u16) {
        self.send(Input::Move { x, y });
    }

    pub fn mouse_button(&self, button: RdpPointerButton, down: bool) {
        self.send(Input::Button { button, down });
    }

    /// Sends a PC/AT set-1 scancode; the frontend maps platform key codes to scancodes.
    pub fn key(&self, scancode: u8, extended: bool, down: bool) {
        self.send(Input::Key { scancode: scancode.into(), extended, down });
    }

    /// Types `text` as Unicode keyboard events: each character down then up. The server's
    /// keyboard layout and modifier state do not change what arrives, so "." is always ".".
    pub fn type_text(&self, text: String) {
        for ch in text.chars() {
            self.send(Input::Unicode { ch, down: true });
            self.send(Input::Unicode { ch, down: false });
        }
    }

    /// Releases every key and modifier the session sent as down and not yet released.
    pub fn release_all_keys(&self) {
        self.send(Input::ReleaseAll);
    }

    /// Text copied on this Mac: offered to the server (when the clipboard is shared).
    /// Ask the server to resize the desktop to the view (MS-RDPEDISP). Width and height are
    /// clamped to 200..=8192 and the width made even, as the protocol requires. A server
    /// without Display Control keeps its size; the view then scales the picture.
    pub fn resize(&self, width: u32, height: u32) {
        let (width, height) = display_size(width, height);
        self.send(Input::Resize { width, height });
    }

    pub fn set_local_clipboard(&self, text: String) {
        if let Some(tx) = self.input.lock().unwrap().as_ref() {
            let _ = tx.send(Input::Clipboard(text));
        }
    }

    /// Whether text copied on either side is shared with the server.
    pub fn shares_clipboard(&self) -> bool {
        self.shared.lock().unwrap().clipboard
    }

    /// Sound received from the server so far, in bytes (0 when audio is off).
    pub fn audio_bytes(&self) -> u64 {
        self.counters.audio_bytes.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Text copied on the server since the last call, taken once.
    pub fn take_remote_clipboard(&self) -> Option<String> {
        self.shared.lock().unwrap().remote_clipboard.take()
    }

    pub fn close(&self) {
        self.send(Input::Close);
    }
}

impl RdpSession {
    fn set_state(&self, state: RdpState, reason: Option<String>) {
        let mut s = self.shared.lock().unwrap();
        s.state = state;
        s.reason = reason;
    }

    fn send(&self, input: Input) {
        if let Some(tx) = self.input.lock().unwrap().as_ref() {
            let _ = tx.send(input);
        }
    }
}

type Tls = ironrdp_tls::TlsStream<tokio::net::TcpStream>;
type Framed = ironrdp_tokio::TokioFramed<Tls>;

/// Lower-case hex SHA-256 of a DER certificate: the identity the user pins.
#[uniffi::export]
pub fn certificate_fingerprint(der: Vec<u8>) -> String {
    Sha256::digest(&der).iter().map(|b| format!("{b:02x}")).collect()
}

/// Cisco's prebuilt OpenH264 library, loaded at runtime so Bastion ships no H.264 code.
static OPENH264_PATH: Mutex<Option<std::path::PathBuf>> = Mutex::new(None);

/// Sets the OpenH264 dylib used by later sessions. `from_library_path` rejects any file whose
/// SHA-256 is not a known Cisco release; with no usable library, H.264 is not offered.
#[uniffi::export]
pub fn set_openh264_library_path(path: Option<String>) {
    *OPENH264_PATH.lock().unwrap() = path.map(std::path::PathBuf::from);
}

/// EGFX surface events are composited by `ActiveStage`; nothing to do per callback here.
struct GraphicsEvents;

impl GraphicsPipelineHandler for GraphicsEvents {}

/// The graphics pipeline channel. With an H.264 decoder Windows sends AVC420/AVC444 video;
/// without one it falls back to RemoteFX progressive, ClearCodec and planar.
fn graphics_pipeline() -> GraphicsPipelineClient {
    let decoder = OPENH264_PATH
        .lock()
        .unwrap()
        .as_deref()
        .and_then(|path| OpenH264Decoder::from_library_path(path).ok())
        .map(|d| Box::new(d) as Box<dyn H264Decoder>);
    GraphicsPipelineClient::new(Box::new(GraphicsEvents), decoder)
}

/// Graphics and Display Control are registered as factories: xrdp closes and reopens its graphics
/// channel after each Display Control resize, and a one-shot channel would be refused on reopen
/// (NO_LISTENER), leaving every later resize ignored.
fn dynamic_channels() -> DrdynvcClient {
    DrdynvcClient::new()
        .with_dynamic_channel_factory(ironrdp_egfx::CHANNEL_NAME, graphics_pipeline)
        .with_dynamic_channel_factory(ironrdp_displaycontrol::CHANNEL_NAME, || {
            ironrdp_displaycontrol::client::DisplayControlClient::new(|_| Ok(Vec::new()))
        })
}

/// Connect + TLS/CredSSP + activation must finish within this (Codex R01): a server that
/// accepts and stalls cannot hang the caller.
const ESTABLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

async fn with_deadline<T>(f: impl std::future::Future<Output = Result<T, RdpError>>) -> Result<T, RdpError> {
    tokio::time::timeout(ESTABLISH_TIMEOUT, f).await.map_err(|_| failed("timed out while connecting"))?
}

async fn establish(
    target: &RdpTarget,
    password: String,
    clip_tx: mpsc::UnboundedSender<channels::ClipEvent>,
    audio_bytes: Arc<std::sync::atomic::AtomicU64>,
) -> Result<(ActiveStage, Framed, DecodedImage, ConnectionActivationFactory), RdpError> {
    let stream = match target.via_loopback_port {
        Some(port) => tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await,
        None => tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await,
    }
    .map_err(failed)?;
    let client_addr = stream.local_addr().map_err(failed)?;
    let mut framed = ironrdp_tokio::TokioFramed::new(stream);
    let connector = ClientConnector::new(config::build(target, password), client_addr)
        .with_static_channel(
            dynamic_channels(),
        );
    let mut connector = channels::attach(connector, target, clip_tx, audio_bytes)?;
    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector)
        .await
        .map_err(|e| failed(negotiation_error(&e, target.nla_only)))?;
    let tcp = framed.into_inner_no_leftover();

    // RDP servers almost always present self-signed certificates, so trust is pinned per host
    // the way SSH host keys are: the user accepts a fingerprint once, later connects must match.
    let (tls, der) = tls::upgrade(tcp, &target.host, target.trusted_fingerprint.clone()).await.map_err(|e| match e {
        tls::UpgradeError::Unpinned(fingerprint) => RdpError::CertificateUnknown { fingerprint },
        tls::UpgradeError::Other(message) => RdpError::Failed { message },
    })?;
    let public_key = server_public_key(&der)?;
    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);
    let mut framed = ironrdp_tokio::TokioFramed::new(tls);
    let outcome = ironrdp_tokio::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut NoNetwork,
        target.host.clone().into(),
        public_key,
        None,
    )
    .await
    .map_err(|e| {
        let text = format!("{e:#}");
        let lower = text.to_ascii_lowercase();
        if lower.contains("logon") || lower.contains("credssp") || lower.contains("authentication") {
            RdpError::AuthFailed
        } else {
            failed(text)
        }
    })?;
    let result = match outcome {
        ConnectionOutcome::Connected(result) => result,
        _ => return Err(failed("server redirection is not supported yet")),
    };
    let (w, h) = config::checked_desktop(result.desktop_size.width, result.desktop_size.height).map_err(failed)?;
    let image = DecodedImage::new(PixelFormat::RgbA32, w, h);
    let stage = ActiveStageBuilder {
        static_channels: result.static_channels,
        user_channel_id: result.user_channel_id,
        io_channel_id: result.io_channel_id,
        message_channel_id: result.message_channel_id,
        share_id: result.share_id,
        compression_type: result.compression_type,
        enable_server_pointer: result.enable_server_pointer,
        pointer_software_rendering: result.pointer_software_rendering,
    }
    .build();
    Ok((stage, framed, image, result.activation_factory))
}

/// MS-RDPEDISP 2.2.2.2.1: 200..=8192 pixels each way, width even.
fn display_size(width: u32, height: u32) -> (u32, u32) {
    let w = width.clamp(200, 8192) & !1;
    (w, height.clamp(200, 8192))
}

/// The subject public key CredSSP binds to (MS-CSSP `pubKeyAuth`).
fn server_public_key(der: &[u8]) -> Result<Vec<u8>, RdpError> {
    use x509_cert::der::Decode as _;
    let cert = x509_cert::Certificate::from_der(der).map_err(failed)?;
    ironrdp_tls::extract_tls_server_public_key(&cert)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| failed("server certificate has no public key"))
}

/// CredSSP only needs a network client for Kerberos KDC traffic; NTLM never calls it.
struct NoNetwork;

impl ironrdp_tokio::NetworkClient for NoNetwork {
    async fn send(
        &mut self,
        _: &ironrdp_connector::sspi::generator::NetworkRequest,
    ) -> ironrdp_connector::ConnectorResult<Vec<u8>> {
        Err(ironrdp_connector::general_err!("Kerberos is not supported yet"))
    }
}

fn operation(input: Input) -> Option<Operation> {
    Some(match input {
        Input::Close | Input::Clipboard(_) | Input::Resize { .. } | Input::ReleaseAll => return None,
        Input::Unicode { ch, down } => {
            if down { Operation::UnicodeKeyPressed(ch) } else { Operation::UnicodeKeyReleased(ch) }
        }
        Input::Move { x, y } => Operation::MouseMove(MousePosition { x, y }),
        Input::Button { button, down } => {
            let b = match button {
                RdpPointerButton::Left => MouseButton::Left,
                RdpPointerButton::Right => MouseButton::Right,
                RdpPointerButton::Middle => MouseButton::Middle,
            };
            if down { Operation::MouseButtonPressed(b) } else { Operation::MouseButtonReleased(b) }
        }
        Input::Key { scancode, extended, down } => {
            let code = Scancode::from_u8(extended, scancode as u8);
            if down { Operation::KeyPressed(code) } else { Operation::KeyReleased(code) }
        }
    })
}

/// The size to ask for again after a reactivation: the view's size, unless the server already
/// came back at it.
fn resize_after_reactivation(wanted: Option<(u32, u32)>, desktop: (u32, u32)) -> Option<(u32, u32)> {
    wanted.filter(|&w| w != desktop)
}

/// Sends the held resize once the server has opened Display Control; until then it stays held.
/// A size the encoder rejects is dropped, and the view keeps scaling the old desktop.
async fn send_pending_resize(stage: &mut ActiveStage, framed: &mut Framed, pending: &mut Option<(u32, u32)>) -> Result<(), String> {
    let Some((width, height)) = *pending else { return Ok(()) };
    match stage.encode_resize(width, height, None, None) {
        None => Ok(()),
        Some(Ok(frame)) => {
            *pending = None;
            if frame.is_empty() { return Ok(()); }
            framed.write_all(&frame).await.map_err(|e| format!("connection lost: {e}"))
        }
        Some(Err(_)) => {
            *pending = None;
            Ok(())
        }
    }
}

/// Pumps server PDUs into the image and user input to the server until the link ends.
async fn run(
    mut stage: ActiveStage,
    mut framed: Framed,
    mut image: DecodedImage,
    activation: ConnectionActivationFactory,
    mut input: mpsc::UnboundedReceiver<Input>,
    mut clip_events: mpsc::UnboundedReceiver<channels::ClipEvent>,
    shared: Arc<Mutex<Shared>>,
) -> String {
    let mut keys = Database::new();
    // Text copied on this Mac most recently, served when the server pastes.
    let mut local_clipboard: Option<String> = None;
    // A tab size asked for before the server opened Display Control (MS-RDPEDISP).
    let mut pending_resize: Option<(u32, u32)> = None;
    // The size the view last asked for. A reactivation (Windows does one around logon) resets the
    // desktop to the connect size, so it is asked for again afterwards.
    let mut wanted_size: Option<(u32, u32)> = None;
    loop {
        let outputs = tokio::select! {
            pdu = framed.read_pdu() => match pdu {
                Ok((action, payload)) => {
                    let out = stage.process(&mut image, action, &payload, None);
                    if pending_resize.is_some() {
                        if let Err(e) = send_pending_resize(&mut stage, &mut framed, &mut pending_resize).await {
                            return e;
                        }
                    }
                    out
                }
                Err(e) => return format!("connection lost: {e}"),
            },
            Some(event) = clip_events.recv() => {
                channels::trace(&event.label());
                match clipboard_event(&mut stage, event, local_clipboard.as_deref(), &shared) {
                    Ok(frame) if frame.is_empty() => continue,
                    Ok(frame) => match { channels::trace(&format!("sent {} bytes", frame.len())); framed.write_all(&frame).await } {
                        Ok(()) => continue,
                        Err(e) => return format!("connection lost: {e}"),
                    },
                    Err(e) => return format!("clipboard channel error: {e}"),
                }
            }
            event = input.recv() => match event {
                Some(Input::Clipboard(text)) => {
                    let ready = channels::clip_ready(&mut stage);
                    channels::trace(&format!("local copy: {} chars, channel ready: {ready}", text.chars().count()));
                    local_clipboard = Some(text);
                    // Held until the channel is ready; ClipEvent::Ready announces it then.
                    if !ready { continue; }
                    let formats = channels::announced(local_clipboard.as_deref());
                    match channels::clip_frames(&mut stage, |c| c.initiate_copy(&formats)) {
                        Ok(frame) if !frame.is_empty() => {
                            channels::trace(&format!("format list sent, {} bytes", frame.len()));
                            if let Err(e) = framed.write_all(&frame).await {
                                return format!("connection lost: {e}");
                            }
                        }
                        Ok(_) => {}
                        Err(e) => return format!("clipboard channel error: {e}"),
                    }
                    continue;
                }
                Some(Input::ReleaseAll) => {
                    let events = keys.release_all();
                    if events.is_empty() { continue; }
                    stage.process_fastpath_input(&mut image, &events)
                }
                Some(Input::Resize { width, height }) => {
                    // Held until Display Control opens; the newest size wins.
                    pending_resize = Some((width, height));
                    wanted_size = pending_resize;
                    if let Err(e) = send_pending_resize(&mut stage, &mut framed, &mut pending_resize).await {
                        return e;
                    }
                    continue;
                }
                event => match event.and_then(operation) {
                Some(op) => {
                    let events = keys.apply([op]);
                    stage.process_fastpath_input(&mut image, &events)
                }
                None => {
                    if let Ok(frames) = stage.graceful_shutdown() {
                        let _ = write_outputs(&mut framed, frames).await;
                    }
                    return "closed".into();
                }
                },
            },
        };
        let outputs = match outputs {
            Ok(o) => o,
            Err(e) => return format!("protocol error: {e}"),
        };
        let deactivated = outputs.iter().any(|o| matches!(o, ActiveStageOutput::DeactivateAll));
        let terminate = outputs.iter().find_map(|o| match o {
            ActiveStageOutput::Terminate(reason) => Some(reason.to_string()),
            _ => None,
        });
        if let Err(e) = write_outputs(&mut framed, outputs).await {
            return format!("connection lost: {e}");
        }
        publish(&mut stage, &image, &shared);
        if let Some(reason) = terminate {
            return reason;
        }
        if deactivated {
            if let Err(e) = reactivate(&mut stage, &mut framed, &mut image, &activation).await {
                return format!("reactivation failed: {e}");
            }
            let mut s = shared.lock().unwrap();
            s.picture.replace(image.width(), image.height(), image.data());
            drop(s);
            pending_resize = resize_after_reactivation(wanted_size, (u32::from(image.width()), u32::from(image.height())));
        }
    }
}

/// Answers one clipboard channel event; returns the frame to send (empty for none).
fn clipboard_event(stage: &mut ActiveStage, event: channels::ClipEvent, local: Option<&str>, shared: &Mutex<Shared>) -> Result<Vec<u8>, String> {
    use channels::ClipEvent;
    use ironrdp_cliprdr::pdu::ClipboardFormatId;
    match event {
        ClipEvent::RequestFormatList => {
            let formats = channels::announced(local);
            channels::clip_frames(stage, |c| c.initiate_copy(&formats))
        }
        // The first format list (sent at Monitor Ready) may predate a copy made during start-up.
        ClipEvent::Ready if local.is_some() => {
            let formats = channels::announced(local);
            channels::clip_frames(stage, |c| c.initiate_copy(&formats))
        }
        ClipEvent::Ready => Ok(Vec::new()),
        ClipEvent::RemoteCopy(true) => channels::clip_frames(stage, |c| c.initiate_paste(ClipboardFormatId::CF_UNICODETEXT)),
        ClipEvent::RemoteCopy(false) => Ok(Vec::new()),
        ClipEvent::DataRequest(format) => {
            let data = channels::data_for(format, local);
            channels::clip_frames(stage, |c| c.submit_format_data(data))
        }
        ClipEvent::Data(text) => {
            if let Some(text) = text {
                shared.lock().unwrap().remote_clipboard = Some(text);
            }
            Ok(Vec::new())
        }
    }
}

/// Copies what the last processing call changed into the shared picture. A size change (EGFX
/// `ResetGraphics`) replaces the picture outright.
fn publish(stage: &mut ActiveStage, image: &DecodedImage, shared: &Mutex<Shared>) {
    let regions = stage.take_damage_regions();
    let mut s = shared.lock().unwrap();
    if (s.picture.width, s.picture.height) != (image.width(), image.height()) {
        s.picture.replace(image.width(), image.height(), image.data());
    } else if !regions.is_empty() {
        s.picture.apply(image.data(), &regions);
    }
}

/// Runs the Deactivation-Reactivation Sequence (MS-RDPBCGR 1.3.1.3) after a Deactivate All
/// PDU: Windows sends one on logon, resolution and session changes. Without it the session
/// stops drawing.
async fn reactivate(
    stage: &mut ActiveStage,
    framed: &mut Framed,
    image: &mut DecodedImage,
    activation: &ConnectionActivationFactory,
) -> Result<(), String> {
    use ironrdp_connector::{Sequence, Written};
    let mut sequence = activation.create();
    let mut buf = ironrdp_pdu::WriteBuf::new();
    loop {
        if sequence.next_pdu_hint().is_some() {
            let (action, payload) = framed.read_pdu().await.map_err(|e| e.to_string())?;
            // xrdp keeps its virtual channels busy while it reactivates (it closes and reopens the
            // graphics channel), so frames for other channels and fast-path updates arrive before
            // the Demand Active. The activation sequence would decode them as Share Control and
            // fail; the active stage handles them as it does outside reactivation.
            if !for_io_channel(action, &payload, activation.io_channel_id()) {
                let outputs = stage.process(image, action, &payload, None).map_err(|e| e.to_string())?;
                write_outputs(framed, outputs).await.map_err(|e| e.to_string())?;
                continue;
            }
            buf.clear();
            let written = sequence.step(&payload, framed.last_read_at(), &mut buf).map_err(|e| e.to_string())?;
            if let Written::Size(n) = written {
                framed.write_all(&buf[..n.get()]).await.map_err(|e| e.to_string())?;
            }
        } else {
            ironrdp_tokio::single_sequence_step(framed, &mut sequence, &mut buf).await.map_err(|e| e.to_string())?;
        }
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            static_channel_chunk_size,
            enable_server_pointer,
            pointer_software_rendering,
            ..
        } = sequence.connection_activation_state()
        {
            if (desktop_size.width, desktop_size.height) != (image.width(), image.height()) {
                let (w, h) = config::checked_desktop(desktop_size.width, desktop_size.height)?;
                *image = DecodedImage::new(PixelFormat::RgbA32, w, h);
            }
            let ok = stage.reactivate(
                activation.io_channel_id(),
                activation.user_channel_id(),
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
                static_channel_chunk_size,
            );
            return if ok { Ok(()) } else { Err("server sent an invalid virtual channel chunk size".into()) };
        }
    }
}

/// Whether a frame read during reactivation belongs to the activation sequence: an X.224 frame
/// on the I/O channel (or one that is not MCS data, such as a redirection the sequence decodes).
fn for_io_channel(action: ironrdp_pdu::Action, payload: &[u8], io_channel_id: u16) -> bool {
    action == ironrdp_pdu::Action::X224
        && ironrdp_pdu::mcs::decode_send_data_indication(payload).map_or(true, |ctx| ctx.channel_id == io_channel_id)
}

async fn write_outputs(framed: &mut Framed, outputs: Vec<ActiveStageOutput>) -> std::io::Result<()> {
    for out in outputs {
        if let ActiveStageOutput::ResponseFrame(frame) = out {
            framed.write_all(&frame).await?;
        }
    }
    Ok(())
}

/// Describes a failure before the TLS upgrade. Only an answer from the server that refuses the
/// requested security (a negotiation failure code, or a different protocol chosen) is reported as a
/// missing Network Level Authentication; a reset, an early close or malformed data is not.
fn negotiation_error(e: &ironrdp_connector::ConnectorError, nla_only: bool) -> String {
    use ironrdp_connector::ConnectorErrorKind;
    let refused_security = match e.kind() {
        ConnectorErrorKind::Negotiation(_) => true,
        ConnectorErrorKind::Reason(reason) => reason.contains("server selected"),
        _ => false,
    };
    match (refused_security, nla_only) {
        (true, true) => format!("The server does not accept Network Level Authentication, which this connection requires ({e})."),
        (true, false) => format!("The server refused the connection's security settings ({e})."),
        (false, _) => format!("The RDP connection failed while negotiating with the server ({e})."),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_a_server_refusal_is_reported_as_missing_nla() {
        use ironrdp_connector::{ConnectorError, ConnectorErrorKind, NegotiationFailure};
        use ironrdp_pdu::nego::FailureCode;
        let refused = ConnectorError::new(
            "negotiation failure",
            ConnectorErrorKind::Negotiation(NegotiationFailure::from(FailureCode::SSL_REQUIRED_BY_SERVER)),
        );
        let other_protocol = ConnectorError::new(
            "Initiation",
            ConnectorErrorKind::Reason("client advertised HYBRID, but server selected SSL".into()),
        );
        let early_close = ConnectorError::new("read frame", ConnectorErrorKind::General);
        let reset = ConnectorError::new("read frame", ConnectorErrorKind::Custom);
        let malformed = ConnectorError::new("connection confirm", ConnectorErrorKind::Reason("unexpected X.224 code".into()));

        for e in [&refused, &other_protocol] {
            assert!(super::negotiation_error(e, true).starts_with("The server does not accept Network Level Authentication"));
            assert!(super::negotiation_error(e, false).starts_with("The server refused"));
        }
        for e in [&early_close, &reset, &malformed] {
            for nla_only in [true, false] {
                let message = super::negotiation_error(e, nla_only);
                assert!(message.starts_with("The RDP connection failed while negotiating"), "{message}");
                assert!(!message.contains("Network Level Authentication"), "{message}");
            }
        }
    }

    #[test]
    fn reactivation_routes_other_channels_to_the_stage() {
        use ironrdp_core::encode_vec;
        use ironrdp_pdu::mcs::SendDataIndication;
        use ironrdp_pdu::x224::X224;
        let frame = |channel_id| {
            let pdu = SendDataIndication { initiator_id: 1002, channel_id, user_data: std::borrow::Cow::Borrowed(&[0u8; 4][..]) };
            encode_vec(&X224(pdu)).unwrap()
        };
        assert!(super::for_io_channel(ironrdp_pdu::Action::X224, &frame(1003), 1003));
        assert!(!super::for_io_channel(ironrdp_pdu::Action::X224, &frame(1007), 1003));
        assert!(!super::for_io_channel(ironrdp_pdu::Action::FastPath, &[0u8; 4], 1003));
    }

    #[test]
    fn graphics_and_display_control_channels_reopen() {
        use ironrdp_core::encode_vec;
        use ironrdp_dvc::pdu::{CapabilitiesRequestPdu, CapsVersion, ClosePdu, CreateRequestPdu, DrdynvcServerPdu};
        use ironrdp_svc::SvcProcessor;

        let mut client = super::dynamic_channels();
        let mut send = |pdu: DrdynvcServerPdu| {
            client.process(&encode_vec(&pdu).unwrap()).unwrap();
        };
        send(DrdynvcServerPdu::Capabilities(CapabilitiesRequestPdu::new(CapsVersion::V3, None)));
        let mut next_id = 1;
        for _ in 0..3 {
            for name in [ironrdp_egfx::CHANNEL_NAME, ironrdp_displaycontrol::CHANNEL_NAME] {
                send(DrdynvcServerPdu::Create(CreateRequestPdu::new(next_id, name.to_owned())));
                next_id += 1;
            }
            send(DrdynvcServerPdu::Close(ClosePdu::new(next_id - 2)));
            send(DrdynvcServerPdu::Close(ClosePdu::new(next_id - 1)));
        }
        drop(send);
        send_and_check(&mut client, next_id);
    }

    /// Opens both channels once more and checks each one reaches its processor by type.
    fn send_and_check(client: &mut ironrdp_dvc::DrdynvcClient, id: u32) {
        use ironrdp_core::encode_vec;
        use ironrdp_dvc::pdu::{CreateRequestPdu, DrdynvcServerPdu};
        use ironrdp_svc::SvcProcessor;
        for (offset, name) in [ironrdp_egfx::CHANNEL_NAME, ironrdp_displaycontrol::CHANNEL_NAME].iter().enumerate() {
            let pdu = DrdynvcServerPdu::Create(CreateRequestPdu::new(id + offset as u32, (*name).to_owned()));
            client.process(&encode_vec(&pdu).unwrap()).unwrap();
        }
        assert!(client.get_dvc::<ironrdp_egfx::client::GraphicsPipelineClient>().is_some());
        assert!(client.get_dvc::<ironrdp_displaycontrol::client::DisplayControlClient>().is_some());
    }

    #[test]
    fn reactivation_asks_again_for_the_wanted_size() {
        assert_eq!(super::resize_after_reactivation(Some((1500, 900)), (1024, 768)), Some((1500, 900)));
        assert_eq!(super::resize_after_reactivation(Some((1500, 900)), (1500, 900)), None);
        assert_eq!(super::resize_after_reactivation(None, (1024, 768)), None);
    }

    #[test]
    fn display_size_is_clamped_and_even() {
        assert_eq!(super::display_size(1281, 801), (1280, 801));
        assert_eq!(super::display_size(10, 10), (200, 200));
        assert_eq!(super::display_size(9000, 9000), (8192, 8192));
    }

    use super::*;

    #[test]
    fn fingerprint_is_lowercase_sha256_hex() {
        assert_eq!(
            certificate_fingerprint(b"abc".to_vec()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn frame_is_none_before_connect() {
        let session = RdpSession::new().unwrap();
        assert_eq!(session.state(), RdpState::Idle);
        assert!(session.frame(0).is_none());
    }

    #[test]
    fn close_input_ends_the_session() {
        assert!(operation(Input::Close).is_none());
        assert!(operation(Input::ReleaseAll).is_none());
        assert!(matches!(operation(Input::Unicode { ch: '.', down: true }), Some(Operation::UnicodeKeyPressed('.'))));
        assert!(matches!(operation(Input::Unicode { ch: '€', down: false }), Some(Operation::UnicodeKeyReleased('€'))));
        assert!(operation(Input::Move { x: 1, y: 2 }).is_some());
    }

    /// Needs Cisco's dylib (the app downloads it into `codecs/`): `BASTION_OPENH264=<file>`.
    #[test]
    #[ignore]
    fn openh264_loads_cisco_binary_and_refuses_others() {
        let path = std::path::PathBuf::from(std::env::var("BASTION_OPENH264").expect("BASTION_OPENH264"));
        assert!(OpenH264Decoder::from_library_path(&path).is_ok());
        let fake = std::env::temp_dir().join("bastion-fake-openh264.dylib");
        std::fs::write(&fake, b"not a codec").unwrap();
        assert!(OpenH264Decoder::from_library_path(&fake).is_err());
        let _ = std::fs::remove_file(&fake);
    }
}
