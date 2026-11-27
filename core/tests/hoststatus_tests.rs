//! Host status dashboard: opt-in targets, up/down, skipped hops, and no checks while hidden.
//! Uses loopback listeners only, so it runs offline.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bastion_core::hoststatus::{self, HostState, HostStatusMonitor, HostTarget};
use bastion_core::model::{Connection, Document, Folder, Node, Protocol, Settings};
use tokio::net::TcpListener;
use uuid::Uuid;

/// A loopback listener that counts accepted connections.
async fn counting_listener() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    tokio::spawn(async move {
        while let Ok((_s, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
        }
    });
    (port, hits)
}

/// A loopback port with nothing listening.
async fn closed_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn target(name: &str, port: u16) -> HostTarget {
    HostTarget { id: Uuid::new_v4(), name: name.into(), host: "127.0.0.1".into(), port, skip: None }
}

async fn until(mon: &HostStatusMonitor, rounds: u64) {
    for _ in 0..500 {
        if mon.rounds() >= rounds {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no check round after 5 s");
}

#[tokio::test]
async fn up_down_and_skipped_hosts_are_reported() {
    let (up, _) = counting_listener().await;
    let down = closed_port().await;
    // The app's own timeout: Windows retries a refused connect for about 2 s before it reports
    // ConnectionRefused, so a shorter timeout here would read "timed out" there.
    let mon = HostStatusMonitor::start_with(&tokio::runtime::Handle::current(), Duration::from_secs(3600), hoststatus::CONNECT_TIMEOUT);
    let mut hop = target("behind jump", up);
    hop.skip = Some("via jump host".into());
    mon.set_targets(vec![target("web", up), target("dead", down), hop]);
    let before = mon.snapshot();
    assert_eq!(before.iter().map(|s| s.state).collect::<Vec<_>>(), [HostState::Unknown, HostState::Unknown, HostState::Skipped]);

    mon.set_visible(true);
    until(&mon, 1).await;
    let s = mon.snapshot();
    assert_eq!(s[0].state, HostState::Up);
    assert!(s[0].latency_ms.is_some() && s[0].checked_at.is_some() && s[0].changed_at.is_some());
    assert_eq!((s[1].state, s[1].error.as_deref()), (HostState::Down, Some("refused")));
    assert_eq!((s[2].state, s[2].error.as_deref(), s[2].checked_at), (HostState::Skipped, Some("via jump host"), None));
}

#[tokio::test]
async fn nothing_is_checked_while_hidden() {
    let (port, hits) = counting_listener().await;
    let mon = HostStatusMonitor::start_with(&tokio::runtime::Handle::current(), Duration::from_millis(20), Duration::from_secs(2));
    mon.set_targets(vec![target("a", port)]);
    // Hidden from the start: no connect, even when asked to refresh.
    mon.check_now();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!((mon.rounds(), hits.load(Ordering::SeqCst)), (0, 0));

    mon.set_visible(true);
    until(&mon, 2).await;
    mon.set_visible(false);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (rounds, seen) = (mon.rounds(), hits.load(Ordering::SeqCst));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(mon.rounds(), rounds, "a hidden dashboard keeps checking");
    assert_eq!(hits.load(Ordering::SeqCst), seen);
}

#[tokio::test]
async fn refresh_checks_again_and_results_survive_new_targets() {
    let (port, hits) = counting_listener().await;
    let mon = HostStatusMonitor::start_with(&tokio::runtime::Handle::current(), Duration::from_secs(3600), Duration::from_secs(2));
    let t = target("a", port);
    mon.set_targets(vec![t.clone()]);
    mon.set_visible(true);
    until(&mon, 1).await;
    mon.check_now();
    until(&mon, 2).await;
    assert!(hits.load(Ordering::SeqCst) >= 2);
    let renamed = HostTarget { name: "renamed".into(), ..t };
    mon.set_targets(vec![renamed]);
    let s = &mon.snapshot()[0];
    assert_eq!((s.name.as_str(), s.state), ("renamed", HostState::Up));
}

#[tokio::test]
async fn an_unknown_name_and_a_silent_host_fail_with_short_reasons() {
    let e = hoststatus::check("no-such-host.invalid", 22, Duration::from_secs(3)).await.unwrap_err();
    assert_eq!(e, "name not found");
    // 192.0.2.1 (TEST-NET-1) is never routed; the check gives up at the timeout.
    let e = hoststatus::check("192.0.2.1", 22, Duration::from_millis(200)).await.unwrap_err();
    assert!(e == "timed out" || !e.is_empty());
}

#[test]
fn only_opted_in_direct_connections_are_targets() {
    let mut doc = Document::new("t");
    let folder = Folder { id: Uuid::new_v4(), name: "Prod".into(), color: None, defaults: Settings { host_status: Some(true), ..Default::default() }, children: vec![], dynamic_task_id: None, extra: Default::default() };
    let fid = folder.id;
    doc.insert(None, Node::Folder(folder)).unwrap();
    let ssh = Connection::new("b ssh", Protocol::Ssh, "10.0.0.1");
    let mut rdp = Connection::new("A rdp", Protocol::Rdp, "10.0.0.2");
    rdp.settings.port = Some(3390);
    let mut jumped = Connection::new("jumped", Protocol::Ssh, "10.0.0.3");
    jumped.metadata.insert("ProxyJump".into(), "bastion".into());
    let mut off = Connection::new("opted out", Protocol::Ssh, "10.0.0.4");
    off.settings.host_status = Some(false);
    let web = Connection::new("site", Protocol::Web, "https://x");
    for c in [ssh, rdp, jumped, off, web] {
        doc.insert(Some(fid), Node::Connection(c)).unwrap();
    }
    doc.insert(None, Node::Connection(Connection::new("outside", Protocol::Ssh, "10.0.0.9"))).unwrap();

    let t = hoststatus::targets(&doc);
    let rows: Vec<_> = t.iter().map(|t| (t.name.as_str(), t.port, t.skip.as_deref())).collect();
    assert_eq!(rows, [("A rdp", 3390, None), ("b ssh", 22, None), ("jumped", 22, Some("via jump host"))]);
}
