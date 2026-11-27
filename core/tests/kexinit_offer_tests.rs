//! Capture the client's KEXINIT on the wire and check what Bastion actually offers.
//! SHA-1 `ssh-rsa` (host key) and other weak algorithms must be absent by default and appear
//! only after the per-host "Allow for this host" opt-in. Hermetic: a raw loopback listener.
use std::time::Duration;

use bastion_core::algorithms::{AlgoKind, AlgorithmSettings};
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

/// The name-lists of a KEXINIT this test checks, in RFC 4253 order.
#[derive(Debug)]
struct KexInit {
    kex: Vec<String>,
    host_key: Vec<String>,
    cipher_cs: Vec<String>,
    mac_cs: Vec<String>,
}

fn name_list(buf: &[u8], at: &mut usize) -> Vec<String> {
    let len = u32::from_be_bytes(buf[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    let s = std::str::from_utf8(&buf[*at..*at + len]).unwrap();
    *at += len;
    s.split(',').filter(|x| !x.is_empty()).map(str::to_owned).collect()
}

/// Accept one connection, send a banner, return the client's parsed KEXINIT.
async fn capture(a: &AlgorithmSettings) -> KexInit {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut r = BufReader::new(sock);
        r.get_mut().write_all(b"SSH-2.0-capture\r\n").await.unwrap();
        let mut banner = String::new();
        r.read_line(&mut banner).await.unwrap();
        let mut len = [0u8; 4];
        r.read_exact(&mut len).await.unwrap();
        let mut pkt = vec![0u8; u32::from_be_bytes(len) as usize];
        r.read_exact(&mut pkt).await.unwrap();
        // padding_length, msg (20 = KEXINIT), 16-byte cookie
        assert_eq!(pkt[1], 20, "first packet must be KEXINIT");
        let mut at = 2 + 16;
        let kex = name_list(&pkt, &mut at);
        let host_key = name_list(&pkt, &mut at);
        let cipher_cs = name_list(&pkt, &mut at);
        let _cipher_sc = name_list(&pkt, &mut at);
        let mac_cs = name_list(&pkt, &mut at);
        KexInit { kex, host_key, cipher_cs, mac_cs }
    });
    let dir = tempfile::tempdir().unwrap();
    let p = SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "nobody".into(),
        auth: SshAuth::Password(bastion_core::vault::Secret::new("x")),
        known_hosts: dir.path().join("known_hosts"),
        policy: HostKeyPolicy::Strict,
        connect_timeout: Duration::from_secs(2),
        keepalive: None,
        prompter: None,
        algorithms: a.resolve(false).unwrap(),
    };
    let _ = SshSession::connect(p).await; // the capture server never answers; a timeout is expected
    server.await.unwrap()
}

#[tokio::test]
async fn default_kexinit_offers_no_sha1() {
    let k = capture(&AlgorithmSettings::default()).await;
    assert!(!k.host_key.iter().any(|n| n == "ssh-rsa"), "ssh-rsa offered: {:?}", k.host_key);
    for want in ["rsa-sha2-512", "rsa-sha2-256", "ssh-ed25519"] {
        assert!(k.host_key.iter().any(|n| n == want), "{want} missing: {:?}", k.host_key);
    }
    assert!(!k.kex.iter().any(|n| n.ends_with("-sha1")), "{:?}", k.kex);
    assert!(!k.mac_cs.iter().any(|n| n.starts_with("hmac-sha1")), "{:?}", k.mac_cs);
    assert!(!k.cipher_cs.iter().any(|n| n.ends_with("-cbc") || n == "none"), "{:?}", k.cipher_cs);
}

#[tokio::test]
async fn ssh_rsa_offered_only_after_allow_for_this_host() {
    let allowed = AlgorithmSettings { allow_weak: true, ..Default::default() }.allowing(AlgoKind::HostKey, &["ssh-rsa".to_string()]);
    let k = capture(&allowed).await;
    assert_eq!(k.host_key.last().map(String::as_str), Some("ssh-rsa"), "{:?}", k.host_key);
    assert!(k.host_key.iter().any(|n| n == "rsa-sha2-256"), "{:?}", k.host_key);
}
