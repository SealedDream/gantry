//! Auto-reconnect on network change and keep-alive defaults (ABI 62).
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bastion_core::model::Settings;
use bastion_core::session::{spawn_supervised, AttemptError, Link, LinkEnd, ReconnectPolicy, SessionEvent, SessionState, DEFAULT_KEEPALIVE};

/// A link that stays up until the supervisor drops it.
struct Forever;
impl Link for Forever {
    fn closed(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = LinkEnd> + Send + '_>> {
        Box::pin(std::future::pending())
    }
}

fn on() -> ReconnectPolicy {
    ReconnectPolicy { enabled: true, max_attempts: 3, initial: Duration::from_secs(10), max_delay: Duration::from_secs(60) }
}

async fn wait_for(rx: &mut tokio::sync::watch::Receiver<SessionState>, want: impl Fn(&SessionState) -> bool) {
    while !want(&rx.borrow_and_update()) {
        rx.changed().await.expect("supervisor stopped");
    }
}

#[tokio::test(start_paused = true)]
async fn network_change_replaces_a_live_link_at_once() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let sup = spawn_supervised(on(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, AttemptError>(Forever) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    let before = tokio::time::Instant::now();
    sup.events.send(SessionEvent::NetworkChanged).unwrap();
    // The watch may coalesce Failed/Reconnecting; the second connect call is the proof.
    while calls.load(Ordering::SeqCst) < 2 {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(before.elapsed() < Duration::from_secs(1), "no back-off on a network change");
}

#[tokio::test(start_paused = true)]
async fn network_change_is_ignored_without_reconnect() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let sup = spawn_supervised(ReconnectPolicy::default(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, AttemptError>(Forever) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    sup.events.send(SessionEvent::NetworkChanged).unwrap();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(*st.borrow(), SessionState::Connected);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn network_change_cuts_a_backoff_short() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let sup = spawn_supervised(on(), move || {
        let n = c.fetch_add(1, Ordering::SeqCst);
        async move {
            if n == 0 {
                Err(AttemptError { reason: "no route".into(), auth: false })
            } else {
                Ok(Forever)
            }
        }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| matches!(s, SessionState::Reconnecting { .. })).await;
    let before = tokio::time::Instant::now();
    sup.events.send(SessionEvent::NetworkChanged).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    assert!(before.elapsed() < Duration::from_secs(10), "retried before the 10 s back-off");
}

#[tokio::test(start_paused = true)]
async fn network_change_while_suspended_waits_for_wake() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let sup = spawn_supervised(on(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, AttemptError>(Forever) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    sup.events.send(SessionEvent::Sleep).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Suspended).await;
    sup.events.send(SessionEvent::NetworkChanged).unwrap();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(*st.borrow(), SessionState::Suspended);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn policy_and_keepalive_follow_settings() {
    let mut s = Settings::default();
    // On unless turned off (owner point W25).
    assert!(ReconnectPolicy::from_settings(&s).enabled);
    assert_eq!(ReconnectPolicy::keepalive_for(&s), Some(DEFAULT_KEEPALIVE));
    s.auto_reconnect = Some(false);
    assert!(!ReconnectPolicy::from_settings(&s).enabled);
    assert_eq!(ReconnectPolicy::keepalive_for(&s), None);
    s.auto_reconnect = Some(true);
    assert!(ReconnectPolicy::from_settings(&s).enabled);
    assert_eq!(ReconnectPolicy::keepalive_for(&s), Some(DEFAULT_KEEPALIVE));
    s.keepalive_secs = Some(15);
    assert_eq!(ReconnectPolicy::keepalive_for(&s), Some(Duration::from_secs(15)));
    s.keepalive_secs = Some(0);
    assert_eq!(ReconnectPolicy::keepalive_for(&s), None);
}
