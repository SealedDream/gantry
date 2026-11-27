//! Forced offline mode in its own test binary: `set_offline` is process-global, so no other test
//! may share this process (Codex T02). A guard resets the flag even if an assertion panics.
//! Offline guarantee: in offline mode (the internet-blocked test run) optional online features
//! fail at once without a packet leaving the LAN, and LAN destinations still work. Outside it,
//! an unreachable network still fails within the connect budget.
use std::time::{Duration, Instant};

use bastion_core::offline;
use bastion_core::ssh::{HostKeyPolicy, SshAuth, SshParams, SshSession};
use bastion_core::update::github::ReleaseFetcher;
use bastion_core::CoreError;

fn ssh(host: &str) -> SshParams {
    SshParams {
        host: host.into(),
        port: 22,
        username: "nobody".into(),
        auth: SshAuth::Password(bastion_core::vault::Secret::new("x")),
        known_hosts: std::env::temp_dir().join("bastion-offline-test-known_hosts"),
        policy: HostKeyPolicy::Strict,
        connect_timeout: Duration::from_secs(10),
        keepalive: None,
        prompter: None,
        algorithms: Default::default(),
    }
}

struct ResetOffline;
impl Drop for ResetOffline {
    fn drop(&mut self) {
        offline::set_offline(false);
    }
}

#[tokio::test]
async fn offline_mode_refuses_the_internet_at_once_and_allows_the_lan() {
    offline::set_offline(true);
    let _reset = ResetOffline;

    let t = Instant::now();
    let e = tokio::task::spawn_blocking(|| ReleaseFetcher::github().check_latest("SealedDream/gantry", &[], "stable", "0.0.0", 0)).await.unwrap().unwrap_err();
    assert!(matches!(e, CoreError::Offline(_)), "{e:?}");
    let e = bastion_core::update::check("https://example.com/update-manifest.json", &[], "stable", "0.0.0", 0).unwrap_err();
    assert!(matches!(e, CoreError::Offline(_)), "{e:?}");
    let e = SshSession::connect(ssh("1.1.1.1")).await.err().unwrap();
    assert!(matches!(e, CoreError::Offline(_)), "{e:?}");
    let refused = t.elapsed();
    eprintln!("offline refusals (update x2 + ssh): {refused:?}");
    assert!(refused < Duration::from_millis(500), "{refused:?}");

    for lan in ["127.0.0.1", "localhost", "192.168.1.20", "10.0.0.5", "[::1]"] {
        offline::check_host(lan, 22).unwrap_or_else(|e| panic!("{lan}: {e}"));
    }
    offline::check_url("http://127.0.0.1:8080/m.json").unwrap();
    assert!(offline::check_url("https://user@github.com:443/x").is_err());
    assert!(offline::check_url("https://[2001:4860::8888]/").is_err());
}

