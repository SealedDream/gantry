//! C11: stopping a tunnel must also end the client connections it already accepted, both
//! SOCKS handshakes still in progress and forwards already carrying data. Hermetic: an
//! in-process russh server accepts any password and echoes direct-tcpip channels.
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::tunnel;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::Channel;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

struct Echo(Arc<AtomicUsize>);
impl server::Handler for Echo {
    type Error = russh::Error;
    async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _host: &str,
        _port: u32,
        _orig: &str,
        _orig_port: u32,
        reply: ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        reply.accept().await;
        tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(channel.into_stream());
            let _ = tokio::io::copy(&mut r, &mut w).await;
        });
        Ok(())
    }
}

async fn session() -> (Arc<SshSession>, Arc<AtomicUsize>, tempfile::TempDir) {
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[3; 32])), "").unwrap();
    let host = key.public_key().to_openssh().unwrap();
    let config = Arc::new(server::Config { keys: vec![key], ..Default::default() });
    let opened = Arc::new(AtomicUsize::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let o = opened.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let (config, o) = (config.clone(), o.clone());
            tokio::spawn(async move {
                if let Ok(s) = server::run_stream(config, sock, Echo(o)).await {
                    let _ = s.await;
                }
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("known_hosts");
    std::fs::write(&kh, format!("[127.0.0.1]:{port} {host}\n")).unwrap();
    let p = SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "u".into(),
        auth: SshAuth::Password(bastion_core::vault::Secret::new("x")),
        known_hosts: kh,
        policy: HostKeyPolicy::Strict,
        connect_timeout: Duration::from_secs(5),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    };
    (Arc::new(SshSession::connect(p).await.unwrap()), opened, dir)
}

fn loopback() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

const CONNECT: [u8; 10] = [5, 1, 0, 1, 10, 0, 0, 9, 0, 80];

/// After shutdown the socket must be closed: a read ends (EOF or reset) instead of hanging.
async fn closed(sock: &mut TcpStream) -> bool {
    let mut buf = [0u8; 64];
    loop {
        match tokio::time::timeout(Duration::from_secs(3), sock.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => return true,
            Ok(Ok(_)) => continue,
            Err(_) => return false,
        }
    }
}

#[tokio::test]
async fn shutdown_ends_a_socks_handshake_in_progress() {
    let (ssh, opened, _dir) = session().await;
    let t = tunnel::dynamic_socks(ssh.clone(), loopback()).await.unwrap();
    let mut c = TcpStream::connect(t.local_addr).await.unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    t.shutdown().await;
    let _ = c.write_all(&CONNECT).await;
    assert!(closed(&mut c).await, "SOCKS client still connected after shutdown");
    assert_eq!(opened.load(Ordering::SeqCst), 0, "a channel was opened after shutdown");
    assert_eq!(Arc::strong_count(&ssh), 1, "tunnel tasks still hold the SSH session");
}

#[tokio::test]
async fn shutdown_ends_active_socks_and_local_forwards() {
    let (ssh, _opened, _dir) = session().await;
    let socks = tunnel::dynamic_socks(ssh.clone(), loopback()).await.unwrap();
    let mut c = TcpStream::connect(socks.local_addr).await.unwrap();
    c.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    c.read_exact(&mut m).await.unwrap();
    c.write_all(&CONNECT).await.unwrap();
    let mut rep = [0u8; 10];
    c.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 0);
    c.write_all(b"ping").await.unwrap();
    let mut echo = [0u8; 4];
    c.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"ping");

    let local = tunnel::local_forward(ssh.clone(), loopback(), "10.0.0.9", 80).await.unwrap();
    let mut l = TcpStream::connect(local.local_addr).await.unwrap();
    l.write_all(b"pong").await.unwrap();
    l.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"pong");

    socks.shutdown().await;
    local.shutdown().await;
    assert!(closed(&mut c).await, "SOCKS forward survived shutdown");
    assert!(closed(&mut l).await, "local forward survived shutdown");
    assert_eq!(Arc::strong_count(&ssh), 1, "tunnel tasks still hold the SSH session");
}
