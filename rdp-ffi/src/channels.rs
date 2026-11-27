//! Optional RDP virtual channels, each chosen per connection: text clipboard (CLIPRDR), one
//! shared folder (RDPDR drive redirection) and sound played on this computer (RDPSND).
//!
//! The clipboard backend only forwards what the server did to the session loop, which owns the
//! channel and answers. Only Unicode text is offered or accepted: no files, images or other
//! formats cross the clipboard.
use std::borrow::Cow;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ironrdp_cliprdr::backend::CliprdrBackend;
use ironrdp_cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest, FileContentsResponse, FormatDataRequest,
    FormatDataResponse, LockDataId, OwnedFormatDataResponse,
};
use ironrdp_cliprdr::CliprdrClient;
use ironrdp_connector::ClientConnector;
use ironrdp_rdpdr::Rdpdr;
#[cfg(unix)]
use ironrdp_rdpdr_native::backend::NixRdpdrBackend;
#[cfg(windows)]
use ironrdp_rdpdr_native::{RedirectedDrive, WindowsRdpdrBackendFactory, FIRST_NAMED_DRIVE_DEVICE_ID};
use ironrdp_rdpsnd::client::{NoopRdpsndBackend, Rdpsnd, RdpsndClientHandler};
use ironrdp_rdpsnd::pdu::{AudioFormat, AudioFormatFlags, PitchPdu, VolumePdu};
use ironrdp_session::ActiveStage;
use tokio::sync::mpsc;

use crate::{failed, RdpError, RdpTarget};

/// Device id of the shared folder; any non-zero id the session does not use otherwise.
/// On Windows ids 1..=26 belong to drive letters, so the folder takes the first named-drive id.
#[cfg(not(windows))]
const DRIVE_ID: u32 = 1;
#[cfg(windows)]
const DRIVE_ID: u32 = FIRST_NAMED_DRIVE_DEVICE_ID;
/// How the folder appears on the server ("Bastion on <client name>" in Explorer).
pub const DRIVE_NAME: &str = "Gantry";
/// Largest text accepted from or sent to the server, in UTF-16 bytes (8 MiB).
pub const MAX_CLIPBOARD_BYTES: usize = 8 * 1024 * 1024;

/// What the clipboard channel reported, handled by the session loop.
#[derive(Debug, PartialEq)]
pub enum ClipEvent {
    /// The server is ready for this side's format list.
    RequestFormatList,
    /// The channel finished its start-up (the server accepted the first format list): text copied
    /// here in the meantime can now be announced.
    Ready,
    /// Something was copied on the server; `true` when it is available as text.
    RemoteCopy(bool),
    /// The server pastes and wants the data in this format.
    DataRequest(ClipboardFormatId),
    /// The text the server sent for our paste request (`None` when it refused or sent garbage).
    Data(Option<String>),
}

impl ClipEvent {
    /// A trace label: names and sizes only, never clipboard content.
    pub fn label(&self) -> String {
        match self {
            ClipEvent::RequestFormatList => "monitor ready: server asks for the format list".into(),
            ClipEvent::Ready => "channel ready: server accepted the first format list".into(),
            ClipEvent::RemoteCopy(text) => format!("server copied (text: {text})"),
            ClipEvent::DataRequest(f) => format!("server pastes, format {}", f.value()),
            ClipEvent::Data(d) => format!("server data: {} chars", d.as_ref().map_or(0, |s| s.chars().count())),
        }
    }
}

/// Opt-in channel trace for lab runs: with `BASTION_RDP_TRACE` set to a file path, one line per
/// clipboard step is appended there. Labels carry names and sizes only, never clipboard text.
pub fn trace(line: &str) {
    use std::io::Write as _;
    let Some(path) = std::env::var_os("BASTION_RDP_TRACE") else { return };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "cliprdr: {line}");
    }
}

#[derive(Debug)]
pub struct ClipBackend {
    tx: mpsc::UnboundedSender<ClipEvent>,
}

ironrdp_core::impl_as_any!(ClipBackend);

impl ClipBackend {
    pub fn new(tx: mpsc::UnboundedSender<ClipEvent>) -> Self {
        Self { tx }
    }

    fn send(&self, e: ClipEvent) {
        let _ = self.tx.send(e);
    }
}

impl CliprdrBackend for ClipBackend {
    fn temporary_directory(&self) -> &str {
        // File copy is never offered, so the server has no reason to use it.
        ""
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::USE_LONG_FORMAT_NAMES
    }

    fn on_ready(&mut self) {
        self.send(ClipEvent::Ready);
    }

    fn on_request_format_list(&mut self) {
        self.send(ClipEvent::RequestFormatList);
    }

    fn on_process_negotiated_capabilities(&mut self, _: ClipboardGeneralCapabilityFlags) {}

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        self.send(ClipEvent::RemoteCopy(available_formats.iter().any(|f| f.id() == ClipboardFormatId::CF_UNICODETEXT)));
    }

    fn on_format_data_request(&mut self, request: FormatDataRequest) {
        self.send(ClipEvent::DataRequest(request.format));
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        self.send(ClipEvent::Data(decode_text(&response)));
    }

    fn on_file_contents_request(&mut self, _: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _: LockDataId) {}

    fn on_unlock(&mut self, _: LockDataId) {}
}

/// UTF-16 text from a paste response, refused when it is an error or too large.
pub fn decode_text(response: &FormatDataResponse<'_>) -> Option<String> {
    if response.is_error() || response.data().len() > MAX_CLIPBOARD_BYTES {
        return None;
    }
    response.to_unicode_string().ok()
}

/// The paste data the server asked for: our text, or an error for any other format or none.
pub fn data_for(format: ClipboardFormatId, local: Option<&str>) -> OwnedFormatDataResponse {
    match local {
        Some(text) if format == ClipboardFormatId::CF_UNICODETEXT && text.len() * 2 <= MAX_CLIPBOARD_BYTES => {
            OwnedFormatDataResponse::new_unicode_string(text)
        }
        _ => OwnedFormatDataResponse::new_error(),
    }
}

/// The formats this side announces: text when there is some, else nothing.
pub fn announced(local: Option<&str>) -> Vec<ClipboardFormat> {
    if local.is_some() { vec![ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)] } else { Vec::new() }
}

/// A folder that may be shared: an existing directory given by an absolute path.
pub fn check_shared_folder(path: &str) -> Result<String, RdpError> {
    let p = Path::new(path);
    if !p.is_absolute() || !p.is_dir() {
        return Err(failed(format!("The shared folder {path} is not an existing folder on this computer.")));
    }
    Ok(p.to_string_lossy().into_owned())
}

/// Plays sound through CoreAudio and counts the audio bytes received, so the app (and the
/// tests) can tell sound is arriving.
#[derive(Debug)]
pub struct CountingPlayer<H> {
    inner: H,
    bytes: Arc<AtomicU64>,
}

impl<H: RdpsndClientHandler> RdpsndClientHandler for CountingPlayer<H> {
    fn get_flags(&self) -> AudioFormatFlags {
        self.inner.get_flags()
    }

    fn get_formats(&self) -> &[AudioFormat] {
        self.inner.get_formats()
    }

    fn choose_formats(&self, server_formats: &[AudioFormat]) -> Vec<AudioFormat> {
        self.inner.choose_formats(server_formats)
    }

    fn wave(&mut self, format: &AudioFormat, ts: u32, data: Cow<'_, [u8]>) {
        self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.inner.wave(format, ts, data);
    }

    fn playback_latency(&self) -> std::time::Duration {
        self.inner.playback_latency()
    }

    fn set_volume(&mut self, volume: VolumePdu) {
        self.inner.set_volume(volume);
    }

    fn set_pitch(&mut self, pitch: PitchPdu) {
        self.inner.set_pitch(pitch);
    }

    fn close(&mut self) {
        self.inner.close();
    }
}

/// Adds the channels the target asks for. The clipboard channel reports to `clip_tx`; audio
/// bytes received are added to `audio_bytes`.
pub fn attach(
    mut connector: ClientConnector,
    target: &RdpTarget,
    clip_tx: mpsc::UnboundedSender<ClipEvent>,
    audio_bytes: Arc<AtomicU64>,
) -> Result<ClientConnector, RdpError> {
    trace(&format!("clipboard channel requested: {}", target.clipboard));
    if target.clipboard {
        connector = connector.with_static_channel(CliprdrClient::new(Box::new(ClipBackend::new(clip_tx))));
    }
    // Windows only plays RDPSND audio when the device redirection channel is present too, so
    // audio alone gets an RDPDR channel with no devices.
    let folder = target.shared_folder.as_deref().map(check_shared_folder).transpose()?;
    if folder.is_some() || target.audio {
        let rdpdr = new_rdpdr(folder.as_deref())?;
        connector = connector.with_static_channel(rdpdr);
    }
    if target.audio {
        let player = CountingPlayer { inner: ironrdp_rdpsnd_native::cpal::RdpsndBackend::new(), bytes: audio_bytes };
        connector = connector.with_static_channel(Rdpsnd::new(Box::new(player)));
    } else if folder.is_some() {
        // The reverse holds too: Windows never opens RDPDR (no Server Announce, so the folder is
        // never announced) unless the RDPSND channel is present. A sound channel that offers no
        // formats keeps the sound on the server while the folder is shared.
        connector = connector.with_static_channel(Rdpsnd::new(Box::new(NoopRdpsndBackend)));
    }
    Ok(connector)
}

/// The device redirection channel, announcing the shared folder when there is one.
#[cfg(unix)]
fn new_rdpdr(folder: Option<&str>) -> Result<Rdpdr, RdpError> {
    let rdpdr = Rdpdr::new(Box::new(NixRdpdrBackend::new(folder.unwrap_or_default().to_owned())), "BASTION".into());
    Ok(match folder {
        Some(_) => rdpdr.with_drives(Some(vec![(DRIVE_ID, DRIVE_NAME.into())])),
        None => rdpdr,
    })
}

/// The device redirection channel, announcing the shared folder when there is one. The Windows
/// backend opens the folder without following reparse points and keeps every path inside it.
#[cfg(windows)]
fn new_rdpdr(folder: Option<&str>) -> Result<Rdpdr, RdpError> {
    let Some(folder) = folder else {
        return Ok(Rdpdr::new(Box::new(ironrdp_rdpdr::backend::noop::NoopRdpdrBackend), "BASTION".into()));
    };
    let drive = RedirectedDrive::new(DRIVE_ID, DRIVE_NAME, folder, false)
        .map_err(|e| failed(format!("The shared folder {folder} cannot be shared: {e}.")))?;
    let factory = WindowsRdpdrBackendFactory::new(drive);
    Ok(Rdpdr::new(Box::new(factory.build()), "BASTION".into()).with_drives(Some(factory.initial_drives())))
}

#[cfg(not(any(unix, windows)))]
fn new_rdpdr(folder: Option<&str>) -> Result<Rdpdr, RdpError> {
    if folder.is_some() {
        return Err(failed("sharing a folder with the server is not available on this system".into()));
    }
    Ok(Rdpdr::new(Box::new(ironrdp_rdpdr::backend::noop::NoopRdpdrBackend), "BASTION".into()))
}

/// Whether the clipboard channel finished its start-up. Before that a local copy must not be
/// announced: ironrdp would send this side's capabilities ahead of the server's Monitor Ready
/// ([MS-RDPECLIP] 1.3.2.1), and the server then never starts the clipboard.
pub fn clip_ready(stage: &mut ActiveStage) -> bool {
    stage.get_svc_processor_mut::<CliprdrClient>().is_some_and(|c| c.is_ready())
}

/// Encodes what the clipboard channel wants to send.
pub fn clip_frames(
    stage: &mut ActiveStage,
    f: impl FnOnce(&mut CliprdrClient) -> ironrdp_pdu::PduResult<ironrdp_cliprdr::CliprdrSvcMessages<ironrdp_cliprdr::Client>>,
) -> Result<Vec<u8>, String> {
    let Some(cliprdr) = stage.get_svc_processor_mut::<CliprdrClient>() else { return Ok(Vec::new()) };
    let messages = f(cliprdr).map_err(|e| e.to_string())?;
    stage.process_svc_processor_messages(messages).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_backend_reports_monitor_ready_and_channel_ready() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut b = ClipBackend::new(tx);
        b.on_request_format_list();
        b.on_ready();
        assert_eq!(rx.try_recv().ok(), Some(ClipEvent::RequestFormatList));
        assert_eq!(rx.try_recv().ok(), Some(ClipEvent::Ready), "a copy held during start-up is announced on Ready");
    }

    #[test]
    fn trace_labels_never_carry_clipboard_text() {
        let label = ClipEvent::Data(Some("s3cret-copied".into())).label();
        assert_eq!(label, "server data: 13 chars");
        assert!(!label.contains("s3cret"));
    }

    #[test]
    fn a_new_clipboard_channel_is_not_ready_before_the_server_starts_it() {
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(!CliprdrClient::new(Box::new(ClipBackend::new(tx))).is_ready());
    }

    #[test]
    fn text_round_trips_through_the_paste_data() {
        let owned = data_for(ClipboardFormatId::CF_UNICODETEXT, Some("héllo ✓"));
        let response = FormatDataResponse::new_data(owned.data().to_vec());
        assert_eq!(decode_text(&response).as_deref(), Some("héllo ✓"));
    }

    #[test]
    fn other_formats_and_empty_clipboard_get_an_error() {
        assert!(data_for(ClipboardFormatId::new(2), Some("x")).is_error(), "bitmaps are never sent");
        assert!(data_for(ClipboardFormatId::CF_UNICODETEXT, None).is_error());
        assert!(decode_text(&FormatDataResponse::new_error()).is_none());
    }

    #[test]
    fn oversized_text_is_refused_both_ways() {
        let big = "a".repeat(MAX_CLIPBOARD_BYTES / 2 + 1);
        assert!(data_for(ClipboardFormatId::CF_UNICODETEXT, Some(&big)).is_error());
        let response = FormatDataResponse::new_data(vec![0u8; MAX_CLIPBOARD_BYTES + 2]);
        assert!(decode_text(&response).is_none());
    }

    #[test]
    fn player_counts_wave_bytes() {
        let bytes = Arc::new(AtomicU64::new(0));
        let mut p = CountingPlayer { inner: ironrdp_rdpsnd::client::NoopRdpsndBackend, bytes: bytes.clone() };
        let format = AudioFormat { format: ironrdp_rdpsnd::pdu::WaveFormat::PCM, n_channels: 2, n_samples_per_sec: 44100, n_avg_bytes_per_sec: 176400, n_block_align: 4, bits_per_sample: 16, data: None };
        p.wave(&format, 0, Cow::Borrowed(&[0u8; 400]));
        p.wave(&format, 1, Cow::Borrowed(&[0u8; 100]));
        assert_eq!(bytes.load(Ordering::Relaxed), 500);
    }

    #[test]
    fn only_text_is_announced() {
        assert_eq!(announced(Some("x")).iter().map(|f| f.id()).collect::<Vec<_>>(), [ClipboardFormatId::CF_UNICODETEXT]);
        assert!(announced(None).is_empty());
    }

    #[test]
    fn backend_reports_text_copies_only() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut b = ClipBackend::new(tx);
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::new(2))]);
        b.on_remote_copy(&[ClipboardFormat::new(ClipboardFormatId::new(2)), ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT)]);
        assert_eq!(rx.try_recv().unwrap(), ClipEvent::RemoteCopy(false));
        assert_eq!(rx.try_recv().unwrap(), ClipEvent::RemoteCopy(true));
    }

    #[test]
    fn a_shared_folder_builds_a_drive_channel_on_this_system() {
        let dir = std::env::temp_dir().join(format!("bastion-rdpdr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let folder = check_shared_folder(dir.to_str().unwrap()).unwrap();
        assert!(new_rdpdr(Some(&folder)).is_ok(), "the folder is shared, not refused");
        assert!(new_rdpdr(None).is_ok(), "sound alone gets an empty channel");
        std::fs::remove_dir_all(dir).ok();
    }

    /// Windows opens RDPDR only when RDPSND is present (seen on Windows 11: no Server Announce
    /// without it), so a shared folder brings a silent sound channel even with audio off.
    #[test]
    fn a_shared_folder_without_audio_still_brings_the_sound_channel() {
        let dir = std::env::temp_dir().join(format!("bastion-rdpsnd-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let target = |folder: Option<String>| RdpTarget {
            host: "h".into(), port: 3389, username: "u".into(), domain: None, width: 1280, height: 800,
            trusted_fingerprint: None, nla_only: false, via_loopback_port: None, clipboard: false,
            shared_folder: folder, audio: false, color_depth: 32,
        };
        let connect = |t: &RdpTarget| {
            let connector = ClientConnector::new(crate::config::build(t, "p".into()), "127.0.0.1:1".parse().unwrap());
            let (tx, _rx) = mpsc::unbounded_channel();
            attach(connector, t, tx, Arc::default()).unwrap()
        };
        let mut shared = connect(&target(Some(dir.to_string_lossy().into_owned())));
        assert!(shared.get_static_channel_processor::<Rdpdr>().is_some());
        assert!(shared.get_static_channel_processor::<Rdpsnd>().is_some(), "RDPDR needs RDPSND beside it");
        let mut plain = connect(&target(None));
        assert!(plain.get_static_channel_processor::<Rdpsnd>().is_none(), "no folder, no audio: no sound channel");
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn shared_folder_must_be_an_existing_absolute_directory() {
        let dir = std::env::temp_dir();
        assert!(check_shared_folder(dir.to_str().unwrap()).is_ok());
        assert!(check_shared_folder("relative/path").is_err());
        assert!(check_shared_folder("/definitely/not/here/bastion").is_err());
        let file = dir.join(format!("bastion-rdp-file-{}", std::process::id()));
        std::fs::write(&file, "x").unwrap();
        assert!(check_shared_folder(file.to_str().unwrap()).is_err(), "a file is not a folder");
        std::fs::remove_file(file).ok();
    }
}
