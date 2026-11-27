//! Supervised session lifecycle: reconnect back-off, auth failures, cancel, sleep/wake.
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bastion_core::session::{spawn_supervised, AttemptError, Link, LinkEnd, ReconnectPolicy, SessionEvent, SessionState};
use tokio::sync::oneshot;

/// A link that drops when its sender fires (or never, if the sender is kept).
struct TestLink(Option<oneshot::Receiver<LinkEnd>>);

impl Link for TestLink {
    fn closed(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = LinkEnd> + Send + '_>> {
        Box::pin(async move {
            match self.0.take() {
                Some(rx) => rx.await.unwrap_or_else(|_| LinkEnd::Lost("dropped".into())),
                None => std::future::pending().await,
            }
        })
    }
}

fn policy() -> ReconnectPolicy {
    ReconnectPolicy { enabled: true, max_attempts: 3, initial: Duration::from_secs(1), max_delay: Duration::from_secs(8) }
}

async fn wait_for(rx: &mut tokio::sync::watch::Receiver<SessionState>, want: impl Fn(&SessionState) -> bool) -> SessionState {
    let s = tokio::time::timeout(Duration::from_secs(600), rx.wait_for(|s| want(s))).await.expect("timed out").unwrap().clone();
    s
}

#[tokio::test(start_paused = true)]
async fn connects_then_cancel_closes() {
    let sup = spawn_supervised(policy(), || async { Ok::<_, AttemptError>(TestLink(None)) });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    sup.events.send(SessionEvent::Cancel).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Closed).await;
}

#[tokio::test(start_paused = true)]
async fn auth_failure_is_never_retried() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let sup = spawn_supervised(policy(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        async { Err::<TestLink, _>(AttemptError { reason: "denied".into(), auth: true }) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| matches!(s, SessionState::Failed(_))).await;
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(matches!(*st.borrow(), SessionState::Failed(_)));
}

#[tokio::test(start_paused = true)]
async fn network_failures_back_off_then_give_up() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let sup = spawn_supervised(policy(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        async { Err::<TestLink, _>(AttemptError { reason: "refused".into(), auth: false }) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Reconnecting { attempt: 3 }).await;
    tokio::time::sleep(Duration::from_secs(120)).await;
    // First attempt plus max_attempts retries.
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert!(matches!(*st.borrow(), SessionState::Failed(_)));
}

#[tokio::test(start_paused = true)]
async fn dropped_link_reconnects() {
    let calls = Arc::new(AtomicU32::new(0));
    let (drop_tx, drop_rx) = oneshot::channel();
    let first = Arc::new(std::sync::Mutex::new(Some(drop_rx)));
    let c = calls.clone();
    let sup = spawn_supervised(policy(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        let rx = first.lock().unwrap().take();
        async move { Ok::<_, AttemptError>(TestLink(rx)) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    drop_tx.send(LinkEnd::Lost("eof".into())).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Reconnecting { attempt: 1 }).await;
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn sleep_suspends_and_wake_reconnects() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let sup = spawn_supervised(policy(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, AttemptError>(TestLink(None)) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    sup.events.send(SessionEvent::Sleep).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Suspended).await;
    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no reconnect while asleep");
    sup.events.send(SessionEvent::Wake).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn cancel_during_backoff_stops_retrying() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let sup = spawn_supervised(policy(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        async { Err::<TestLink, _>(AttemptError { reason: "refused".into(), auth: false }) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Reconnecting { attempt: 1 }).await;
    sup.events.send(SessionEvent::Cancel).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Closed).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn cancel_mid_connect_abandons_attempt() {
    let sup = spawn_supervised(policy(), || async {
        std::future::pending::<()>().await;
        Ok::<_, AttemptError>(TestLink(None))
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connecting).await;
    sup.events.send(SessionEvent::Cancel).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Closed).await;
}

#[tokio::test(start_paused = true)]
async fn finished_link_closes_without_reconnect() {
    let calls = Arc::new(AtomicU32::new(0));
    let (end_tx, end_rx) = oneshot::channel();
    let first = Arc::new(std::sync::Mutex::new(Some(end_rx)));
    let c = calls.clone();
    let sup = spawn_supervised(policy(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        let rx = first.lock().unwrap().take();
        async move { Ok::<_, AttemptError>(TestLink(rx)) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    end_tx.send(LinkEnd::Finished).unwrap();
    wait_for(&mut st, |s| *s == SessionState::Closed).await;
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn sleep_is_ignored_without_opt_in_reconnect() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let off = ReconnectPolicy { enabled: false, ..policy() };
    let sup = spawn_supervised(off, move || {
        c.fetch_add(1, Ordering::SeqCst);
        async { Ok::<_, AttemptError>(TestLink(None)) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    sup.events.send(SessionEvent::Sleep).unwrap();
    sup.events.send(SessionEvent::Wake).unwrap();
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(*st.borrow(), SessionState::Connected);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

/// With reconnect off, a dropped link must show as failed (it used to stay "connected": the
/// Connected -> Failed transition was missing, so the UI never learned the link was gone).
#[tokio::test(start_paused = true)]
async fn a_dropped_link_without_reconnect_is_failed_not_connected() {
    let calls = Arc::new(AtomicU32::new(0));
    let c = calls.clone();
    let (drop_tx, drop_rx) = oneshot::channel();
    let mut drop_rx = Some(drop_rx);
    let sup = spawn_supervised(ReconnectPolicy::default(), move || {
        c.fetch_add(1, Ordering::SeqCst);
        let link = TestLink(drop_rx.take());
        async move { Ok::<_, AttemptError>(link) }
    });
    let mut st = sup.state.clone();
    wait_for(&mut st, |s| *s == SessionState::Connected).await;
    drop_tx.send(LinkEnd::Lost("peer closed".into())).unwrap();
    assert_eq!(wait_for(&mut st, |s| matches!(s, SessionState::Failed(_))).await, SessionState::Failed("peer closed".into()));
    tokio::time::sleep(Duration::from_secs(120)).await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "no reconnect when the policy is off");
}
