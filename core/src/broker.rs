//! Credential broker: short-lived unlock leases for secrets (key passphrases, passwords).
//!
//! - Two independent timers start at unlock: inactivity (default 15 min, reset by use) and an
//!   absolute lifetime (default 60 min, never extended by use).
//! - Leases are keyed by credential identity *and* customer scope, and every lookup runs
//!   `Policy::check_credential_scope`, so a lease is never reused across customers.
//! - Expired or locked secrets are dropped, which zeroizes them (`Secret` is `ZeroizeOnDrop`).
//! - The broker holds no session handles: expiry or `lock_all` never tears down a live session.
//!   It only means the next connection that needs the secret must unlock again.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{CoreError, Result};
use crate::model::Connection;
use crate::policy::Policy;
use crate::vault::Secret;

pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Manually advanced clock for tests.
pub struct ManualClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl Default for ManualClock {
    fn default() -> Self {
        ManualClock { base: Instant::now(), offset: Mutex::new(Duration::ZERO) }
    }
}

impl ManualClock {
    pub fn advance(&self, d: Duration) {
        if let Ok(mut o) = self.offset.lock() {
            *o += d;
        }
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.base + self.offset.lock().map(|o| *o).unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseLimits {
    pub inactivity: Duration,
    pub absolute: Duration,
    /// When false, nothing is cached: every use needs a fresh unlock.
    pub allow_caching: bool,
}

pub const DEFAULT_INACTIVITY: Duration = Duration::from_secs(15 * 60);
pub const DEFAULT_ABSOLUTE: Duration = Duration::from_secs(60 * 60);

impl Default for LeaseLimits {
    fn default() -> Self {
        LeaseLimits { inactivity: DEFAULT_INACTIVITY, absolute: DEFAULT_ABSOLUTE, allow_caching: true }
    }
}

impl LeaseLimits {
    /// Combine with a managed policy: each limit takes the stricter value.
    pub fn with_managed(&self, managed: &LeaseLimits) -> LeaseLimits {
        LeaseLimits {
            inactivity: self.inactivity.min(managed.inactivity),
            absolute: self.absolute.min(managed.absolute),
            allow_caching: self.allow_caching && managed.allow_caching,
        }
    }

    /// The limits a policy requires (audit TM-03): its `inactivity_lock_secs`, when set, bounds
    /// the inactivity timer (0 = cache nothing); the absolute limit stays independent.
    pub fn for_policy(policy: &Policy) -> LeaseLimits {
        match policy.inactivity_lock_secs {
            Some(0) => LeaseLimits { allow_caching: false, ..LeaseLimits::default() },
            Some(secs) => LeaseLimits::default().with_managed(&LeaseLimits { inactivity: Duration::from_secs(secs), ..LeaseLimits::default() }),
            None => LeaseLimits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeaseKey {
    /// Stable credential identity (vault UUID, keychain item, key file path…).
    pub credential: String,
    /// Customer the credential belongs to.
    pub scope: Option<String>,
}

struct Lease {
    secret: Secret,
    unlocked_at: Instant,
    last_used: Instant,
}

/// What the security UI shows: no secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseStatus {
    pub key: LeaseKey,
    pub remaining_inactivity: Duration,
    pub remaining_absolute: Duration,
}

pub struct Broker {
    limits: LeaseLimits,
    policy: Policy,
    clock: Arc<dyn Clock>,
    leases: Mutex<HashMap<LeaseKey, Lease>>,
}

impl Broker {
    pub fn new(limits: LeaseLimits, policy: Policy, clock: Arc<dyn Clock>) -> Broker {
        Broker { limits, policy, clock, leases: Mutex::new(HashMap::new()) }
    }

    /// The broker every host uses: lease limits derived from `policy` itself, so a managed
    /// inactivity limit is what actually expires leases (TM-03).
    pub fn for_policy(policy: Policy, clock: Arc<dyn Clock>) -> Broker {
        Broker::new(LeaseLimits::for_policy(&policy), policy, clock)
    }

    pub fn limits(&self) -> LeaseLimits {
        self.limits
    }

    fn table(&self) -> Result<std::sync::MutexGuard<'_, HashMap<LeaseKey, Lease>>> {
        self.leases.lock().map_err(|_| CoreError::Invalid("credential broker state poisoned".into()))
    }

    fn expired(&self, l: &Lease, now: Instant) -> bool {
        now.duration_since(l.unlocked_at) >= self.limits.absolute || now.duration_since(l.last_used) >= self.limits.inactivity
    }

    /// Record a freshly unlocked secret. Does nothing when policy forbids caching.
    pub fn unlock(&self, key: LeaseKey, secret: Secret) -> Result<()> {
        if !self.limits.allow_caching {
            return Ok(());
        }
        let now = self.clock.now();
        self.table()?.insert(key, Lease { secret, unlocked_at: now, last_used: now });
        Ok(())
    }

    /// Fetch a cached secret for `connection`. Enforces customer isolation first, then expiry.
    /// A hit counts as activity (resets inactivity only).
    pub fn get(&self, key: &LeaseKey, connection: &Connection) -> Result<Option<Secret>> {
        self.policy.check_credential_scope(key.scope.as_deref(), connection)?;
        let now = self.clock.now();
        let mut t = self.table()?;
        let Some(lease) = t.get_mut(key) else { return Ok(None) };
        if self.expired(lease, now) {
            t.remove(key);
            return Ok(None);
        }
        lease.last_used = now;
        Ok(Some(lease.secret.clone()))
    }

    /// Drop expired leases; returns how many were removed.
    pub fn sweep(&self) -> Result<usize> {
        let now = self.clock.now();
        let mut t = self.table()?;
        let before = t.len();
        t.retain(|_, l| !self.expired(l, now));
        Ok(before - t.len())
    }

    pub fn lock(&self, key: &LeaseKey) -> Result<bool> {
        Ok(self.table()?.remove(key).is_some())
    }

    /// "Lock Credentials": drop every lease immediately. Live sessions are unaffected.
    pub fn lock_all(&self) -> Result<usize> {
        let mut t = self.table()?;
        let n = t.len();
        t.clear();
        Ok(n)
    }

    pub fn status(&self) -> Result<Vec<LeaseStatus>> {
        self.sweep()?;
        let now = self.clock.now();
        let mut out: Vec<LeaseStatus> = self
            .table()?
            .iter()
            .map(|(k, l)| LeaseStatus {
                key: k.clone(),
                remaining_inactivity: self.limits.inactivity.saturating_sub(now.duration_since(l.last_used)),
                remaining_absolute: self.limits.absolute.saturating_sub(now.duration_since(l.unlocked_at)),
            })
            .collect();
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
    }
}
