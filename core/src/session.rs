//! Explicit connection lifecycle state machine with validated transitions and a bounded
//! exponential reconnect schedule. Protocol adapters drive it; the UI observes it.
use std::time::Duration;

use crate::error::{CoreError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Idle,
    Connecting,
    Authenticating,
    Connected,
    Reconnecting { attempt: u32 },
    /// The host went to sleep (or the network went away); the link was dropped on purpose.
    Suspended,
    Disconnecting,
    Closed,
    Failed(String),
}

impl SessionState {
    fn may_become(&self, next: &SessionState) -> bool {
        use SessionState::*;
        matches!(
            (self, next),
            (Idle, Connecting)
                | (Connecting, Authenticating)
                // Connected -> Failed: the link dropped and reconnecting is off or not allowed.
                | (Connecting | Authenticating | Connected | Reconnecting { .. }, Failed(_))
                | (Authenticating, Connected)
                | (Connected, Reconnecting { .. })
                | (Reconnecting { .. }, Reconnecting { .. })
                | (Reconnecting { .. }, Authenticating)
                | (Failed(_), Reconnecting { .. })
                | (Failed(_) | Closed, Connecting)
                | (Connected | Reconnecting { .. } | Failed(_), Suspended)
                | (Suspended, Reconnecting { .. })
                | (Connecting | Authenticating | Connected | Reconnecting { .. } | Suspended | Failed(_), Disconnecting)
                | (Disconnecting, Closed)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectPolicy {
    pub enabled: bool,
    pub max_attempts: u32,
    pub initial: Duration,
    pub max_delay: Duration,
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        ReconnectPolicy { enabled: false, max_attempts: 10, initial: Duration::from_secs(1), max_delay: Duration::from_secs(60) }
    }
}

/// Keep-alive interval used when reconnect is on but the connection sets none: without probes
/// a dead link on an idle shell is never noticed, so reconnect would never start.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(30);
/// Unanswered keep-alive probes before the link counts as lost.
pub const KEEPALIVE_MAX_MISSED: usize = 3;

impl ReconnectPolicy {
    /// Policy for a connection's resolved settings: on unless `auto_reconnect` is turned off (owner point W25:
    /// Tabby-style, a dropped link keeps retrying, 1 s doubling to 60 s, ten attempts, about five minutes).
    pub fn from_settings(settings: &crate::model::Settings) -> Self {
        ReconnectPolicy { enabled: settings.auto_reconnect.unwrap_or(true), ..ReconnectPolicy::default() }
    }

    /// Keep-alive interval for `settings`: the configured one, else [`DEFAULT_KEEPALIVE`] when
    /// reconnect is on, else none. `Some(0)` turns probes off explicitly.
    pub fn keepalive_for(settings: &crate::model::Settings) -> Option<Duration> {
        match settings.keepalive_secs {
            Some(0) => None,
            Some(s) => Some(Duration::from_secs(s.into())),
            None if settings.auto_reconnect != Some(false) => Some(DEFAULT_KEEPALIVE),
            None => None,
        }
    }

    /// Delay before `attempt` (1-based), or `None` when reconnecting should stop.
    /// Authentication failures never auto-retry (avoids lockouts and password spraying).
    pub fn delay(&self, attempt: u32, last_error_was_auth: bool) -> Option<Duration> {
        if !self.enabled || last_error_was_auth || attempt == 0 || attempt > self.max_attempts {
            return None;
        }
        let factor = 2u32.saturating_pow(attempt - 1);
        Some(self.initial.saturating_mul(factor).min(self.max_delay))
    }
}

#[derive(Debug)]
pub struct Lifecycle {
    state: SessionState,
    history: Vec<SessionState>,
}

impl Default for Lifecycle {
    fn default() -> Self {
        Lifecycle { state: SessionState::Idle, history: vec![SessionState::Idle] }
    }
}

impl Lifecycle {
    pub fn state(&self) -> &SessionState {
        &self.state
    }
    pub fn history(&self) -> &[SessionState] {
        &self.history
    }
    pub fn transition(&mut self, next: SessionState) -> Result<()> {
        if !self.state.may_become(&next) {
            return Err(CoreError::Invalid(format!("illegal session transition {:?} -> {next:?}", self.state)));
        }
        self.history.push(next.clone());
        self.state = next;
        Ok(())
    }
}

/// Why an attempt failed; authentication failures are never retried automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttemptError {
    pub reason: String,
    pub auth: bool,
}

/// External events a running session reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionEvent {
    /// The system is about to sleep: drop the link without counting it as a failure.
    Sleep,
    /// The system woke up: reconnect if the session was suspended.
    Wake,
    /// The user closed the session: stop at once, including mid-connect or mid-backoff.
    Cancel,
    /// The network path changed (Wi-Fi switch, VPN up/down, new address). With reconnect on, a
    /// live link is replaced at once (its TCP flow is usually dead and keep-alive would take
    /// tens of seconds to notice) and a pending back-off is cut short. Ignored while suspended.
    NetworkChanged,
}

/// How a live link ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEnd {
    /// The connection dropped (network, server restart): eligible for reconnect.
    Lost(String),
    /// The remote side finished on purpose (the shell exited): the session closes, no reconnect.
    Finished,
}

/// A live protocol connection. `closed` resolves when the link ends.
pub trait Link: Send {
    fn closed(&mut self) -> std::pin::Pin<Box<dyn std::future::Future<Output = LinkEnd> + Send + '_>>;
}

/// Handle to a supervised session: send events, observe state.
pub struct Supervisor {
    pub events: tokio::sync::mpsc::UnboundedSender<SessionEvent>,
    pub state: tokio::sync::watch::Receiver<SessionState>,
}

/// Drives one session through the lifecycle: connect, watch the link, reconnect with
/// `policy` back-off, suspend on sleep, resume on wake, and stop promptly on cancel.
/// `connect` is called for every attempt; the adapter does its own authentication.
pub fn spawn_supervised<F, Fut, L>(policy: ReconnectPolicy, connect: F) -> Supervisor
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = std::result::Result<L, AttemptError>> + Send + 'static,
    L: Link + 'static,
{
    let (events_tx, events_rx) = tokio::sync::mpsc::unbounded_channel();
    let (state_tx, state_rx) = tokio::sync::watch::channel(SessionState::Idle);
    tokio::spawn(supervise(policy, connect, events_rx, state_tx));
    Supervisor { events: events_tx, state: state_rx }
}

enum Next {
    Attempt(u32),
    /// Retry at once, skipping the back-off (network change).
    Now(u32),
    Suspend,
    Stop,
    /// Retrying is not allowed or exhausted: remain `Failed` for the UI to show.
    GiveUp,
}

/// One supervised session's state while it runs: the lifecycle, the attempt counter and the
/// event inbox. Each phase of `supervise` is one method (H18).
struct Run<'a> {
    policy: &'a ReconnectPolicy,
    life: Lifecycle,
    state: &'a tokio::sync::watch::Sender<SessionState>,
    events: &'a mut tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
    attempt: u32,
}

impl Run<'_> {
    fn set(&mut self, s: SessionState) {
        // Transitions below are all legal by construction; a bug here must not wedge the task.
        if self.life.transition(s.clone()).is_ok() {
            let _ = self.state.send(s);
        }
    }

    fn close(&mut self) {
        self.set(SessionState::Disconnecting);
        self.set(SessionState::Closed);
    }

    /// One connection attempt, abandoned immediately on Cancel (`None`). Sleep/Wake during an
    /// attempt are ignored: the attempt's own outcome decides what follows.
    async fn attempt<Fut, L>(&mut self, attempt_fut: Fut) -> Option<std::result::Result<L, AttemptError>>
    where
        Fut: std::future::Future<Output = std::result::Result<L, AttemptError>>,
    {
        tokio::pin!(attempt_fut);
        loop {
            tokio::select! {
                r = &mut attempt_fut => return Some(r),
                e = self.events.recv() => match e {
                    Some(SessionEvent::Cancel) | None => return None,
                    Some(_) => continue,
                },
            }
        }
    }

    /// Watch a live link until it ends or an event decides what happens next.
    async fn connected<L: Link>(&mut self, link: &mut L) -> Next {
        self.set(SessionState::Authenticating);
        self.set(SessionState::Connected);
        self.attempt = 0;
        loop {
            tokio::select! {
                end = link.closed() => match end {
                    LinkEnd::Finished => return Next::Stop,
                    LinkEnd::Lost(reason) => {
                        self.set(SessionState::Failed(reason));
                        return retry(self.policy, &mut self.attempt, false);
                    }
                },
                e = self.events.recv() => match e {
                    Some(SessionEvent::Cancel) | None => return Next::Stop,
                    // Without opt-in reconnect the link is left alone: it may survive a short sleep,
                    // and dropping it would end the user's session for good.
                    Some(SessionEvent::Sleep) if self.policy.enabled => return Next::Suspend,
                    Some(SessionEvent::NetworkChanged) if self.policy.enabled => {
                        self.set(SessionState::Failed("the network changed".into()));
                        self.attempt = 1;
                        return Next::Now(self.attempt);
                    }
                    Some(SessionEvent::Sleep | SessionEvent::Wake | SessionEvent::NetworkChanged) => continue,
                },
            }
        }
    }

    /// Suspended until Wake (true) or Cancel (false, already closed).
    async fn suspended(&mut self) -> bool {
        self.set(SessionState::Suspended);
        loop {
            match self.events.recv().await {
                Some(SessionEvent::Wake) => break,
                Some(SessionEvent::Sleep | SessionEvent::NetworkChanged) => continue,
                Some(SessionEvent::Cancel) | None => {
                    self.close();
                    return false;
                }
            }
        }
        self.attempt = 1;
        self.set(SessionState::Reconnecting { attempt: self.attempt });
        true
    }

    /// Back-off before attempt `n`; false when cancelled. Sleep/Wake keep waiting; a network
    /// change retries now.
    async fn back_off(&mut self, n: u32) -> bool {
        self.set(SessionState::Reconnecting { attempt: n });
        let delay = tokio::time::sleep(self.policy.delay(n, false).unwrap_or_default());
        tokio::pin!(delay);
        loop {
            tokio::select! {
                _ = &mut delay => return true,
                e = self.events.recv() => match e {
                    Some(SessionEvent::Cancel) | None => return false,
                    Some(SessionEvent::NetworkChanged) => return true,
                    Some(_) => continue,
                },
            }
        }
    }
}

async fn supervise<F, Fut, L>(
    policy: ReconnectPolicy,
    mut connect: F,
    mut events: tokio::sync::mpsc::UnboundedReceiver<SessionEvent>,
    state: tokio::sync::watch::Sender<SessionState>,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<L, AttemptError>>,
    L: Link,
{
    let mut run = Run { policy: &policy, life: Lifecycle::default(), state: &state, events: &mut events, attempt: 0 };
    run.set(SessionState::Connecting);
    loop {
        let next = match run.attempt(connect()).await {
            None => Next::Stop,
            Some(Ok(mut link)) => run.connected(&mut link).await,
            Some(Err(err)) => {
                run.set(SessionState::Failed(err.reason.clone()));
                retry(run.policy, &mut run.attempt, err.auth)
            }
        };
        match next {
            Next::Stop => break,
            Next::GiveUp => return,
            Next::Suspend => {
                if !run.suspended().await {
                    return;
                }
            }
            Next::Attempt(n) => {
                if !run.back_off(n).await {
                    break;
                }
            }
            Next::Now(n) => run.set(SessionState::Reconnecting { attempt: n }),
        }
    }
    run.close();
}

/// Next attempt number, or `GiveUp` when retrying is not allowed.
fn retry(policy: &ReconnectPolicy, attempt: &mut u32, auth: bool) -> Next {
    *attempt += 1;
    if policy.delay(*attempt, auth).is_some() {
        Next::Attempt(*attempt)
    } else {
        Next::GiveUp
    }
}
