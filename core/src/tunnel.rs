//! Application-owned SSH tunnels: local forwarding and dynamic SOCKS5.
//! A tunnel only ever controls its own listener task and the client connections it accepted;
//! it never touches other processes. Stopping it ends those connections too.
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use crate::error::{CoreError, Result};
use crate::ssh::SshSession;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelKind {
    Local { dest_host: String, dest_port: u16 },
    DynamicSocks,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TunnelStats {
    pub connections: u64,
    /// Bytes sent from this computer through the tunnel, counted when each connection closes.
    pub bytes_up: u64,
    /// Bytes received through the tunnel, counted when each connection closes.
    pub bytes_down: u64,
    pub last_error: Option<String>,
}

pub struct Tunnel {
    pub kind: TunnelKind,
    pub local_addr: SocketAddr,
    stats: Arc<Mutex<TunnelStats>>,
    task: JoinHandle<()>,
    stop: tokio::sync::watch::Sender<bool>,
}

impl Tunnel {
    pub fn stats(&self) -> TunnelStats {
        self.stats.lock().map(|s| s.clone()).unwrap_or_default()
    }
    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
    }
    /// Stop accepting and end every connection already accepted (in the background).
    pub fn stop(&self) {
        let _ = self.stop.send(true);
    }
    /// Stop and wait until the listener is closed and every accepted connection has ended and
    /// released its SSH channel, so its port can be bound again at once.
    pub async fn shutdown(mut self) {
        let _ = self.stop.send(true);
        let _ = (&mut self.task).await;
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        // Aborting the listener drops its JoinSet, which aborts every connection task.
        self.task.abort();
    }
}

/// Accept clients until stopped, running each in a task this listener owns; on stop every
/// one of them is aborted and awaited, so none keeps the SSH session or a channel.
fn serve<F, Fut>(listener: TcpListener, kind: TunnelKind, local_addr: SocketAddr, stats: Arc<Mutex<TunnelStats>>, handle: F) -> Tunnel
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (stop, mut stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = stopped.wait_for(|s| *s) => break,
                Some(_) = clients.join_next(), if !clients.is_empty() => {}
                accepted = listener.accept() => match accepted {
                    Ok((sock, _)) => { clients.spawn(handle(sock)); }
                    Err(_) => break,
                },
            }
        }
        drop(listener);
        clients.shutdown().await;
    });
    Tunnel { kind, local_addr, stats, task, stop }
}

async fn bind(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr).await.map_err(|e| match e.kind() {
        std::io::ErrorKind::AddrInUse => CoreError::Invalid(format!("local port {} is already in use", addr.port())),
        _ => CoreError::Io(e),
    })
}

fn add_bytes(stats: &Mutex<TunnelStats>, moved: std::io::Result<(u64, u64)>) {
    if let (Ok((up, down)), Ok(mut s)) = (moved, stats.lock()) {
        s.bytes_up = s.bytes_up.saturating_add(up);
        s.bytes_down = s.bytes_down.saturating_add(down);
    }
}

fn note(stats: &Mutex<TunnelStats>, err: Option<String>) {
    if let Ok(mut s) = stats.lock() {
        s.connections += 1;
        if err.is_some() {
            s.last_error = err;
        }
    }
}

/// `ssh -L bind:dest_host:dest_port` on a loopback address. Use port 0 to let the OS pick.
pub async fn local_forward(session: Arc<SshSession>, bind_addr: SocketAddr, dest_host: &str, dest_port: u16) -> Result<Tunnel> {
    if !bind_addr.ip().is_loopback() {
        return Err(CoreError::Invalid("tunnel must bind to a loopback address; LAN exposure requires local_forward_exposed".into()));
    }
    local_forward_exposed(session, bind_addr, dest_host, dest_port).await
}

/// Like [`local_forward`] but may bind a non-loopback address, exposing the destination to
/// other machines on the network. Callers must obtain explicit user / policy approval first.
pub async fn local_forward_exposed(session: Arc<SshSession>, bind_addr: SocketAddr, dest_host: &str, dest_port: u16) -> Result<Tunnel> {
    let listener = bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let stats = Arc::new(Mutex::new(TunnelStats::default()));
    let (host, st) = (dest_host.to_string(), stats.clone());
    let kind = TunnelKind::Local { dest_host: dest_host.into(), dest_port };
    Ok(serve(listener, kind, local_addr, stats, move |mut sock| {
        let (session, host, st) = (session.clone(), host.clone(), st.clone());
        async move {
            match session.open_direct_tcpip(&host, dest_port).await {
                Ok(ch) => {
                    note(&st, None);
                    add_bytes(&st, tokio::io::copy_bidirectional(&mut sock, &mut ch.into_stream()).await);
                }
                Err(e) => note(&st, Some(e.to_string())),
            }
        }
    }))
}

/// `ssh -D bind` — SOCKS5, no-auth, CONNECT only. Bind to loopback: no SOCKS auth is offered.
pub async fn dynamic_socks(session: Arc<SshSession>, bind_addr: SocketAddr) -> Result<Tunnel> {
    if !bind_addr.ip().is_loopback() {
        return Err(CoreError::Invalid("SOCKS proxy must bind to a loopback address".into()));
    }
    let listener = bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let stats = Arc::new(Mutex::new(TunnelStats::default()));
    let st = stats.clone();
    Ok(serve(listener, TunnelKind::DynamicSocks, local_addr, stats, move |sock| {
        let (session, st) = (session.clone(), st.clone());
        async move {
            let err = socks_session(session, sock, &st).await.err().map(|e| e.to_string());
            note(&st, err);
        }
    }))
}

const SOCKS_VERSION: u8 = 5;
const REP_SUCCESS: u8 = 0;
const REP_HOST_UNREACHABLE: u8 = 4;
const REP_COMMAND_NOT_SUPPORTED: u8 = 7;

async fn socks_session(session: Arc<SshSession>, mut sock: TcpStream, stats: &Mutex<TunnelStats>) -> Result<()> {
    let mut head = [0u8; 2];
    sock.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        return Err(CoreError::Invalid("not a SOCKS5 client".into()));
    }
    let mut methods = vec![0u8; head[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        sock.write_all(&[SOCKS_VERSION, 0xff]).await?;
        return Err(CoreError::Invalid("SOCKS client requires authentication".into()));
    }
    sock.write_all(&[SOCKS_VERSION, 0]).await?;

    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[1] != 1 {
        reply(&mut sock, REP_COMMAND_NOT_SUPPORTED).await?;
        return Err(CoreError::Invalid("only SOCKS CONNECT is supported".into()));
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => {
            let len = sock.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            sock.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| CoreError::Invalid("bad SOCKS host name".into()))?
        }
        4 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        _ => return Err(CoreError::Invalid("bad SOCKS address type".into())),
    };
    let port = sock.read_u16().await?;
    match session.open_direct_tcpip(&host, port).await {
        Ok(ch) => {
            reply(&mut sock, REP_SUCCESS).await?;
            add_bytes(stats, tokio::io::copy_bidirectional(&mut sock, &mut ch.into_stream()).await);
            Ok(())
        }
        Err(e) => {
            reply(&mut sock, REP_HOST_UNREACHABLE).await?;
            Err(e)
        }
    }
}

async fn reply(sock: &mut TcpStream, code: u8) -> Result<()> {
    sock.write_all(&[SOCKS_VERSION, code, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}
