//! Telnet and serial byte backends for `TerminalSession` (B7, `docs/plans/B7-TELNET-SERIAL.md`).
//! A child module of `terminal`, so it uses the same private `Backend` / `OutputSink` plumbing as
//! the PTY and SSH backends.
use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

use super::{checked_size, Backend, OutputSink, Size, SshBackend, SshCommand, TerminalSession, READ_BUF};
use crate::error::{CoreError, Result};
use crate::serial::{is_idle_read, open_port, SerialSettings};
use crate::session::LinkEnd;
use crate::telnet::{LoginWatcher, TelnetCodec, TelnetOptions};

/// Message the tab shows when a serial device goes away.
pub const PORT_DISCONNECTED: &str = "Port disconnected";

/// Open the TCP connection for a Telnet terminal, bounded by `opts.connect_timeout`.
pub async fn connect_telnet_stream(opts: &TelnetOptions) -> Result<TcpStream> {
    let addr = (opts.host.trim_start_matches('[').trim_end_matches(']').to_string(), opts.port);
    match tokio::time::timeout(opts.connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(CoreError::Io(std::io::Error::new(e.kind(), format!("cannot reach {}:{}: {e}", opts.host, opts.port)))),
        Err(_) => Err(CoreError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, format!("{}:{} did not answer in time", opts.host, opts.port)))),
    }
}

impl TerminalSession {
    /// Run a terminal over a connected Telnet stream. The receiver says how the link ended:
    /// `Finished` (the server closed it: logout) or `Lost` (network error, protocol abuse);
    /// after `Lost` the screen stays and `reattach_telnet` continues on a new stream.
    pub fn attach_telnet(stream: TcpStream, opts: &TelnetOptions, cols: u16, rows: u16, runtime: &tokio::runtime::Handle) -> Result<(TerminalSession, oneshot::Receiver<LinkEnd>)> {
        let size = checked_size(cols, rows)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let backend = Arc::new(SshBackend { tx: Mutex::new(tx) });
        let mut session = TerminalSession::new(size, backend.clone());
        session.telnet = Some(backend);
        let (end_tx, end_rx) = oneshot::channel();
        runtime.spawn(drive_telnet(stream, rx, session.sink(), end_tx, TelnetCodec::new(cols, rows, &opts.term_type), opts.auto_login.clone().map(LoginWatcher::new)));
        Ok((session, end_rx))
    }

    /// Continue a Telnet terminal on a new stream after its link was lost. `opts.auto_login`
    /// applies again (once per connect).
    pub fn reattach_telnet(&self, stream: TcpStream, opts: &TelnetOptions, runtime: &tokio::runtime::Handle) -> Result<oneshot::Receiver<LinkEnd>> {
        let backend = self.telnet.as_ref().ok_or_else(|| CoreError::Invalid("not a Telnet terminal".into()))?;
        let (tx, rx) = mpsc::unbounded_channel();
        *backend.tx.lock().map_err(|_| CoreError::Invalid("telnet backend poisoned".into()))? = tx;
        let (cols, rows) = self.size();
        let (end_tx, end_rx) = oneshot::channel();
        self.alive.store(true, Ordering::SeqCst);
        runtime.spawn(drive_telnet(stream, rx, self.sink(), end_tx, TelnetCodec::new(cols, rows, &opts.term_type), opts.auto_login.clone().map(LoginWatcher::new)));
        Ok(end_rx)
    }

    /// Open a serial port as a terminal. The receiver reports `Lost("Port disconnected")` when the
    /// device goes away (no automatic reopen; `reopen_serial` is the Reopen button) and
    /// `Finished` when the tab closes it.
    pub fn open_serial(settings: &SerialSettings, cols: u16, rows: u16) -> Result<(TerminalSession, oneshot::Receiver<LinkEnd>)> {
        let size = checked_size(cols, rows)?;
        let port = open_port(settings)?;
        let backend = Arc::new(SerialBackend { settings: settings.clone(), port: Mutex::new(None), epoch: Arc::new(AtomicU64::new(0)), closed: Arc::new(AtomicBool::new(false)) });
        let mut session = TerminalSession::new(size, backend.clone());
        session.serial = Some(backend.clone());
        let end = backend.start(port, session.sink())?;
        Ok((session, end))
    }

    /// Reopen a serial terminal's port after it was disconnected (the Reopen button).
    pub fn reopen_serial(&self) -> Result<oneshot::Receiver<LinkEnd>> {
        let backend = self.serial.as_ref().ok_or_else(|| CoreError::Invalid("not a serial terminal".into()))?;
        let port = open_port(&backend.settings)?;
        let end = backend.start(port, self.sink())?;
        self.alive.store(true, Ordering::SeqCst);
        self.generation.bump();
        Ok(end)
    }

    /// `COM3 · 115200 8N1` for a serial terminal's status line; `None` otherwise.
    pub fn serial_status(&self) -> Option<String> {
        self.serial.as_ref().map(|b| b.settings.status_line())
    }
}

async fn drive_telnet(
    mut stream: TcpStream,
    mut rx: mpsc::UnboundedReceiver<SshCommand>,
    sink: OutputSink,
    end: oneshot::Sender<LinkEnd>,
    mut codec: TelnetCodec,
    mut login: Option<LoginWatcher>,
) {
    let mut buf = vec![0u8; READ_BUF];
    let outcome = loop {
        tokio::select! {
            n = stream.read(&mut buf) => match n {
                Ok(0) => break LinkEnd::Finished,
                Err(e) => break LinkEnd::Lost(format!("connection lost: {e}")),
                Ok(n) => {
                    let decoded = match codec.decode(&buf[..n]) {
                        Ok(d) => d,
                        Err(e) => break LinkEnd::Lost(e.to_string()),
                    };
                    if !decoded.reply.is_empty() && stream.write_all(&decoded.reply).await.is_err() {
                        break LinkEnd::Lost("connection lost while sending".into());
                    }
                    if !decoded.data.is_empty() {
                        sink.output(&decoded.data);
                        let typed = login.as_mut().and_then(|w| w.feed(&decoded.data, Instant::now()));
                        if login.as_ref().is_some_and(LoginWatcher::done) {
                            // Drop the saved password as soon as it is no longer needed.
                            login = None;
                        }
                        // Typed by us, never through the output path, so it is never in the session log.
                        if let Some(bytes) = typed {
                            if stream.write_all(&TelnetCodec::encode_input(&bytes)).await.is_err() {
                                break LinkEnd::Lost("connection lost while sending".into());
                            }
                        }
                    }
                }
            },
            cmd = rx.recv() => match cmd {
                Some(SshCommand::Input(bytes)) => {
                    if stream.write_all(&TelnetCodec::encode_input(&bytes)).await.is_err() {
                        break LinkEnd::Lost("connection lost while sending".into());
                    }
                }
                Some(SshCommand::Resize(s)) => {
                    if let Some(naws) = codec.resize(s.cols as u16, s.rows as u16) {
                        let _ = stream.write_all(&naws).await;
                    }
                }
                Some(SshCommand::Close) => {
                    let _ = stream.shutdown().await;
                    break LinkEnd::Finished;
                }
                // Moved to a new stream (reattach); this one is abandoned.
                None => break LinkEnd::Lost("replaced".into()),
            },
        }
    };
    drop(login);
    if outcome == LinkEnd::Finished {
        sink.ended();
    }
    let _ = end.send(outcome);
}

pub(super) struct SerialBackend {
    pub(super) settings: SerialSettings,
    /// The writer handle; `None` after close or disconnect.
    port: Mutex<Option<Box<dyn serialport::SerialPort>>>,
    /// Bumped on each (re)open, so an old reader thread knows it was replaced.
    epoch: Arc<AtomicU64>,
    closed: Arc<AtomicBool>,
}

impl SerialBackend {
    fn start(&self, port: Box<dyn serialport::SerialPort>, sink: OutputSink) -> Result<oneshot::Receiver<LinkEnd>> {
        let reader = port.try_clone().map_err(|e| CoreError::Io(std::io::Error::other(e.to_string())))?;
        *self.port.lock().map_err(|_| CoreError::Invalid("serial port poisoned".into()))? = Some(port);
        self.closed.store(false, Ordering::SeqCst);
        let my_epoch = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        let (epoch, closed) = (self.epoch.clone(), self.closed.clone());
        let (end_tx, end_rx) = oneshot::channel();
        std::thread::Builder::new()
            .name("bastion-serial-reader".into())
            .spawn(move || {
                let outcome = pump_serial(reader, &sink, || closed.load(Ordering::SeqCst), || epoch.load(Ordering::SeqCst) != my_epoch);
                match outcome {
                    // Replaced by a reopen: say nothing.
                    None => {}
                    Some(end) => {
                        sink.ended();
                        let _ = end_tx.send(end);
                    }
                }
            })?;
        Ok(end_rx)
    }
}

/// Read until the port goes away or the tab closes it. `None`: replaced by a reopen.
fn pump_serial(mut reader: Box<dyn serialport::SerialPort>, sink: &OutputSink, closed: impl Fn() -> bool, replaced: impl Fn() -> bool) -> Option<LinkEnd> {
    let mut buf = vec![0u8; READ_BUF];
    pump_reads(|b| reader.read(b), &mut buf, sink, closed, replaced)
}

/// The read loop on its own, so its error handling is unit-tested with a fake reader: a timeout
/// keeps reading; any other error or end of file ends it at once (no retry, no busy loop).
pub(super) fn pump_reads(
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
    buf: &mut [u8],
    sink: &OutputSink,
    closed: impl Fn() -> bool,
    replaced: impl Fn() -> bool,
) -> Option<LinkEnd> {
    let ending = || if replaced() { None } else if closed() { Some(LinkEnd::Finished) } else { Some(LinkEnd::Lost(PORT_DISCONNECTED.into())) };
    loop {
        if closed() || replaced() {
            return ending();
        }
        match read(buf) {
            Ok(0) => return ending(),
            Ok(n) => sink.output(&buf[..n]),
            Err(e) if is_idle_read(&e) => continue,
            Err(_) => return ending(),
        }
    }
}

impl Backend for SerialBackend {
    fn write(&self, bytes: &[u8]) -> Result<()> {
        let enter = self.settings.enter.bytes();
        let mut out = Vec::with_capacity(bytes.len() + 2);
        for &b in bytes {
            if b == b'\r' {
                out.extend_from_slice(enter);
            } else {
                out.push(b);
            }
        }
        let mut guard = self.port.lock().map_err(|_| CoreError::Invalid("serial port poisoned".into()))?;
        let port = guard.as_mut().ok_or_else(|| CoreError::Invalid(PORT_DISCONNECTED.into()))?;
        std::io::Write::write_all(port, &out).map_err(|e| CoreError::Io(std::io::Error::new(e.kind(), format!("{PORT_DISCONNECTED}: {e}"))))?;
        let _ = std::io::Write::flush(port);
        Ok(())
    }

    fn resize(&self, _size: Size) -> Result<()> {
        Ok(())
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        // Drop our handle now; the reader's clone closes within `SERIAL_READ_TIMEOUT`.
        if let Ok(mut p) = self.port.lock() {
            p.take();
        }
    }

    fn local_echo(&self) -> bool {
        self.settings.local_echo
    }
}

#[cfg(test)]
#[path = "terminal_b7_tests.rs"]
mod tests;
