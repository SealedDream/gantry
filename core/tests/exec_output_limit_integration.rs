//! C12: `SshSession::exec` must not keep more than `EXEC_OUTPUT_LIMIT` bytes per stream, however
//! much a command prints; the rest is drained, truncation is recorded and the exit status is
//! still collected. Hermetic: an in-process russh server floods stdout and stderr.
use std::sync::Arc;
use std::time::Duration;

use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession, EXEC_OUTPUT_LIMIT};
use russh::keys::ssh_key::private::{Ed25519Keypair, KeypairData};
use russh::keys::PrivateKey;
use russh::server::{self, Auth, ChannelOpenHandle, Msg, Session};
use russh::{Channel, ChannelId};

const CHUNK: usize = 32 * 1024;

struct Flood {
    bytes: usize,
}
impl server::Handler for Flood {
    type Error = russh::Error;
    async fn auth_password(&mut self, _: &str, _: &str) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }
    async fn channel_open_session(&mut self, _ch: Channel<Msg>, reply: ChannelOpenHandle, _s: &mut Session) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }
    async fn exec_request(&mut self, id: ChannelId, _data: &[u8], session: &mut Session) -> Result<(), Self::Error> {
        let _ = session.channel_success(id);
        let (h, bytes) = (session.handle(), self.bytes);
        tokio::spawn(async move {
            let chunk = vec![b'y'; CHUNK];
            for _ in 0..bytes / CHUNK {
                if h.data(id, chunk.clone()).await.is_err() || h.extended_data(id, 1, chunk.clone()).await.is_err() {
                    return;
                }
            }
            let _ = h.exit_status_request(id, 3).await;
            let _ = h.eof(id).await;
            let _ = h.close(id).await;
        });
        Ok(())
    }
}

async fn connect(bytes: usize) -> (SshSession, tempfile::TempDir) {
    let key = PrivateKey::new(KeypairData::Ed25519(Ed25519Keypair::from_seed(&[5; 32])), "").unwrap();
    let host = key.public_key().to_openssh().unwrap();
    let config = Arc::new(server::Config { keys: vec![key], ..Default::default() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(s) = server::run_stream(config, sock, Flood { bytes }).await {
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
    (SshSession::connect(p).await.unwrap(), dir)
}

#[tokio::test]
async fn exec_output_is_capped_while_reading() {
    let flood = EXEC_OUTPUT_LIMIT + 4 * 1024 * 1024;
    let (s, _dir) = connect(flood).await;
    let out = tokio::time::timeout(Duration::from_secs(120), s.exec("yes")).await.expect("exec finished").unwrap();
    assert_eq!(out.stdout.len(), EXEC_OUTPUT_LIMIT, "stdout kept beyond the limit");
    assert_eq!(out.stderr.len(), EXEC_OUTPUT_LIMIT, "stderr kept beyond the limit");
    assert!(out.truncated);
    assert_eq!(out.exit_status, Some(3), "exit status lost after truncation");
}

#[tokio::test]
async fn small_output_is_kept_whole() {
    let (s, _dir) = connect(4 * CHUNK).await;
    let out = s.exec("echo").await.unwrap();
    assert_eq!((out.stdout.len(), out.stderr.len(), out.truncated, out.exit_status), (4 * CHUNK, 4 * CHUNK, false, Some(3)));
}
