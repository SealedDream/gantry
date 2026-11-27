//! Audit PR-01: the connect timeout bounds every server-controlled wait — user authentication
//! and a jump host's channel-open reply — not only the transport handshake. In-process russh
//! servers on loopback; generated keys and passwords only.
use std::sync::Arc;
use std::time::{Duration, Instant};

use bastion_core::algorithms::AlgorithmSettings;
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::CoreError;
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::PrivateKey;
use russh::server::{self, Auth, Msg, Session};
use russh::Channel;

const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy)]
enum Stall {
    /// Never answer the password request.
    Auth,
    /// Accept the password, then never answer a direct-tcpip channel-open.
    ChannelOpen,
}

struct Lab(Stall);

impl server::Handler for Lab {
    type Error = russh::Error;

    async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
        match self.0 {
            Stall::Auth => {
                tokio::time::sleep(Duration::from_secs(3_600)).await;
                Ok(Auth::reject())
            }
            Stall::ChannelOpen => Ok(Auth::Accept),
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        _: &str,
        _: u32,
        _: &str,
        _: u32,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<(), Self::Error> {
        // Hold the reply forever: the channel-open is never confirmed or refused.
        std::mem::forget((channel, reply));
        Ok(())
    }
}

/// Serve on loopback behind a TCP proxy; returns the proxy port and a counter of client
/// connections that closed. The proxy sees the client hang up even while the server's handler
/// is stalled inside `auth_password`.
async fn lab(stall: Stall) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[9; 32])), "lab").unwrap();
    let config = Arc::new(server::Config { keys: vec![key], ..Default::default() });
    let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((sock, _)) = server.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(s) = server::run_stream(config, sock, Lab(stall)).await {
                    let _ = s.await;
                }
            });
        }
    });
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    let closed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = closed.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = proxy.accept().await {
            let c = c.clone();
            tokio::spawn(async move {
                let upstream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
                let (mut cr, mut cw) = client.into_split();
                let (mut ur, mut uw) = upstream.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut ur, &mut cw).await;
                });
                let _ = tokio::io::copy(&mut cr, &mut uw).await; // ends when the client closes
                c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
    });
    (port, closed)
}

fn params(port: u16, kh: &std::path::Path) -> SshParams {
    SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "lab".into(),
        auth: SshAuth::Password(bastion_core::vault::Secret::new("generated-lab-password")),
        known_hosts: kh.to_path_buf(),
        policy: HostKeyPolicy::AcceptNew,
        connect_timeout: TIMEOUT,
        keepalive: None, // zero-probe configuration: no keepalive to notice the stall either
        prompter: None,
        algorithms: AlgorithmSettings::default().resolve(false).unwrap(),
    }
}

async fn assert_times_out(result: impl std::future::Future<Output = bastion_core::Result<SshSession>>) {
    let started = Instant::now();
    let r = tokio::time::timeout(TIMEOUT * 5, result).await.expect("the connect outlived its timeout");
    assert!(matches!(r, Err(CoreError::Timeout)), "{:?}", r.err());
    assert!(started.elapsed() < TIMEOUT * 3, "took {:?}", started.elapsed());
}

async fn wait_closed(closed: &std::sync::atomic::AtomicUsize) {
    for _ in 0..50 {
        if closed.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the abandoned connection was not closed");
}

#[tokio::test]
async fn stalled_user_authentication_times_out_and_closes() {
    let (port, closed) = lab(Stall::Auth).await;
    let dir = tempfile::tempdir().unwrap();
    assert_times_out(SshSession::connect(params(port, &dir.path().join("kh")))).await;
    wait_closed(&closed).await;
}

#[tokio::test]
async fn stalled_jump_channel_open_times_out_and_closes_the_jump() {
    let (jump, closed) = lab(Stall::ChannelOpen).await;
    let dir = tempfile::tempdir().unwrap();
    let kh = dir.path().join("kh");
    let target = SshParams { host: "10.255.255.1".into(), port: 22, ..params(jump, &kh) };
    assert_times_out(SshSession::connect_via(vec![params(jump, &kh)], target)).await;
    wait_closed(&closed).await;
}

#[test]
fn an_interactive_prompter_gets_its_own_longer_budget() {
    assert!(bastion_core::ssh::INTERACTIVE_AUTH_TIMEOUT >= Duration::from_secs(60), "a person needs time for an MFA code");
}
