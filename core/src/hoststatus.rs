//! Host status dashboard: an opt-in, low-frequency reachability check of chosen connections.
//!
//! - Opt-in per connection or folder (`Settings::host_status`, inherited); nothing is checked
//!   unless the user turned it on.
//! - Zero cost while hidden: with the dashboard not visible the checker task is parked on a
//!   channel, with no timer and no socket. It checks again when the dashboard is shown.
//! - Low frequency: every [`DEFAULT_INTERVAL`] (clamped to [`MIN_INTERVAL`]..[`MAX_INTERVAL`]),
//!   at most [`CONCURRENCY`] connects at a time, each bounded by [`CONNECT_TIMEOUT`].
//! - A check is a plain TCP connect, closed at once: no login, no banner, no secret. Hosts behind
//!   a jump host or gateway are listed as skipped (this computer cannot reach them directly).
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::net::TcpStream;
use tokio::sync::{watch, Notify, Semaphore};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::model::{Document, Protocol};

pub const MIN_INTERVAL: Duration = Duration::from_secs(30);
pub const MAX_INTERVAL: Duration = Duration::from_secs(3600);
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(120);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
pub const CONCURRENCY: usize = 8;
pub const MAX_TARGETS: usize = 500;

/// A connection to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTarget {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port: u16,
    /// Why it is not checked directly (jump host, gateway), if so.
    pub skip: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    /// Not checked yet.
    Unknown,
    Up,
    Down,
    /// Not reachable directly from this computer, so not checked.
    Skipped,
}

impl HostState {
    pub fn as_str(self) -> &'static str {
        match self {
            HostState::Unknown => "unknown",
            HostState::Up => "up",
            HostState::Down => "down",
            HostState::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStatus {
    pub id: Uuid,
    pub name: String,
    pub state: HostState,
    pub latency_ms: Option<u32>,
    /// Short reason for `down` or `skipped`.
    pub error: Option<String>,
    /// Unix seconds of the last check.
    pub checked_at: Option<u64>,
    /// Unix seconds of the last change of state.
    pub changed_at: Option<u64>,
}

/// The opted-in connections of `doc` that have a host and port, by name.
pub fn targets(doc: &Document) -> Vec<HostTarget> {
    let mut out: Vec<HostTarget> = doc
        .connections()
        .into_iter()
        .filter(|r| r.effective.host_status == Some(true))
        .filter(|r| !matches!(r.connection.protocol, Protocol::Web | Protocol::Serial | Protocol::Local) && !r.connection.host.trim().is_empty())
        .filter_map(|r| {
            let port = r.effective.port.or(r.connection.protocol.default_port())?;
            let skip = if r.effective.gateway_id.is_some() {
                Some("via gateway".to_string())
            } else if r.connection.metadata.contains_key("ProxyJump") {
                Some("via jump host".to_string())
            } else {
                None
            };
            Some(HostTarget { id: r.connection.id, name: r.connection.name.clone(), host: r.connection.host.trim().to_string(), port, skip })
        })
        .collect();
    out.sort_by_key(|t| t.name.to_lowercase());
    out.truncate(MAX_TARGETS);
    out
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn fresh(t: &HostTarget) -> HostStatus {
    let (state, error) = match &t.skip {
        Some(why) => (HostState::Skipped, Some(why.clone())),
        None => (HostState::Unknown, None),
    };
    HostStatus { id: t.id, name: t.name.clone(), state, latency_ms: None, error, checked_at: None, changed_at: None }
}

/// One TCP connect, closed at once: `Ok(latency)` or a short reason.
pub async fn check(host: &str, port: u16, timeout: Duration) -> Result<Duration, String> {
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect((host, port))).await {
        Ok(Ok(_stream)) => Ok(started.elapsed()),
        Ok(Err(e)) if e.kind() == std::io::ErrorKind::ConnectionRefused => Err("refused".into()),
        Ok(Err(e)) => Err(short(&e)),
        Err(_) => Err("timed out".into()),
    }
}

fn short(e: &std::io::Error) -> String {
    let s = e.to_string();
    if s.contains("lookup") || s.contains("nodename nor servname") || s.contains("No such host") {
        return "name not found".into();
    }
    s.chars().take(80).collect()
}

struct Inner {
    targets: Mutex<Vec<HostTarget>>,
    results: Mutex<HashMap<Uuid, HostStatus>>,
    interval: Mutex<Duration>,
    timeout: Duration,
    visible: watch::Sender<bool>,
    wake: Notify,
    rounds: AtomicU64,
}

/// The dashboard's checker. Starts hidden; dropping it ends the task.
pub struct HostStatusMonitor {
    inner: Arc<Inner>,
    task: JoinHandle<()>,
}

impl Drop for HostStatusMonitor {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn clamp(interval: Duration) -> Duration {
    interval.clamp(MIN_INTERVAL, MAX_INTERVAL)
}

impl HostStatusMonitor {
    /// A monitor on `rt`, hidden, checking every `interval` (clamped) while visible.
    pub fn start(rt: &tokio::runtime::Handle, interval: Duration) -> Self {
        Self::start_with(rt, clamp(interval), CONNECT_TIMEOUT)
    }

    /// As [`start`](Self::start) without clamping, for tests.
    #[doc(hidden)]
    pub fn start_with(rt: &tokio::runtime::Handle, interval: Duration, timeout: Duration) -> Self {
        let inner = Arc::new(Inner {
            targets: Mutex::default(),
            results: Mutex::default(),
            interval: Mutex::new(interval),
            timeout,
            visible: watch::channel(false).0,
            wake: Notify::new(),
            rounds: AtomicU64::new(0),
        });
        let task = rt.spawn(run(inner.clone()));
        HostStatusMonitor { inner, task }
    }

    /// Replace what is checked; results of hosts still listed are kept.
    pub fn set_targets(&self, mut targets: Vec<HostTarget>) {
        targets.truncate(MAX_TARGETS);
        {
            let mut results = self.inner.results.lock().unwrap_or_else(|e| e.into_inner());
            let old = std::mem::take(&mut *results);
            for t in &targets {
                let kept = old.get(&t.id).filter(|r| t.skip.is_none() && r.state != HostState::Skipped).cloned();
                results.insert(t.id, kept.map(|r| HostStatus { name: t.name.clone(), ..r }).unwrap_or_else(|| fresh(t)));
            }
        }
        *self.inner.targets.lock().unwrap_or_else(|e| e.into_inner()) = targets;
    }

    /// Show (checks at once, then every interval) or hide (stops checking) the dashboard.
    pub fn set_visible(&self, visible: bool) {
        self.inner.visible.send_replace(visible);
    }

    pub fn set_interval(&self, interval: Duration) {
        *self.inner.interval.lock().unwrap_or_else(|e| e.into_inner()) = clamp(interval);
    }

    /// Check again now (Refresh). Has no effect while hidden.
    pub fn check_now(&self) {
        if *self.inner.visible.borrow() {
            self.inner.wake.notify_one();
        }
    }

    /// Completed check rounds, for tests and diagnostics.
    pub fn rounds(&self) -> u64 {
        self.inner.rounds.load(Ordering::SeqCst)
    }

    /// Current status of every target, in target order.
    pub fn snapshot(&self) -> Vec<HostStatus> {
        let targets = self.inner.targets.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let results = self.inner.results.lock().unwrap_or_else(|e| e.into_inner());
        targets.iter().map(|t| results.get(&t.id).cloned().unwrap_or_else(|| fresh(t))).collect()
    }
}

async fn run(inner: Arc<Inner>) {
    let mut visible = inner.visible.subscribe();
    loop {
        // Hidden: parked here, with no timer and no socket.
        if visible.wait_for(|v| *v).await.is_err() {
            return;
        }
        round(&inner).await;
        inner.rounds.fetch_add(1, Ordering::SeqCst);
        let interval = *inner.interval.lock().unwrap_or_else(|e| e.into_inner());
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = inner.wake.notified() => {}
            // Hidden again: drop the timer and wait above.
            _ = visible.wait_for(|v| !*v) => {}
        }
    }
}

async fn round(inner: &Arc<Inner>) {
    let targets: Vec<HostTarget> = inner.targets.lock().unwrap_or_else(|e| e.into_inner()).iter().filter(|t| t.skip.is_none()).cloned().collect();
    let gate = Arc::new(Semaphore::new(CONCURRENCY));
    let mut jobs = tokio::task::JoinSet::new();
    for t in targets {
        let (gate, timeout) = (gate.clone(), inner.timeout);
        jobs.spawn(async move {
            let _permit = gate.acquire_owned().await;
            (t.id, check(&t.host, t.port, timeout).await)
        });
    }
    while let Some(Ok((id, r))) = jobs.join_next().await {
        let at = now_secs();
        let mut results = inner.results.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = results.get_mut(&id) else { continue };
        let (state, latency, error) = match r {
            Ok(d) => (HostState::Up, Some(u32::try_from(d.as_millis()).unwrap_or(u32::MAX)), None),
            Err(e) => (HostState::Down, None, Some(e)),
        };
        if s.state != state {
            s.changed_at = Some(at);
        }
        (s.state, s.latency_ms, s.error, s.checked_at) = (state, latency, error, Some(at));
    }
}
