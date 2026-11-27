//! Bridge for the host status dashboard (`bastion_core::hoststatus`): opt-in, low-frequency TCP
//! checks of the library's opted-in connections, and nothing at all while the dashboard is hidden.
use std::sync::Arc;
use std::time::Duration;

use bastion_core::hoststatus::{self, HostStatus, HostStatusMonitor};

use crate::terminal::RUNTIME;
use crate::{FfiResult, Library};

#[derive(uniffi::Record, Clone, Debug, PartialEq)]
pub struct HostStatusView {
    pub id: String,
    pub name: String,
    /// `unknown`, `up`, `down` or `skipped`.
    pub state: String,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
    /// Unix seconds.
    pub checked_at: Option<u64>,
    pub changed_at: Option<u64>,
}

impl From<HostStatus> for HostStatusView {
    fn from(s: HostStatus) -> Self {
        HostStatusView {
            id: s.id.to_string(),
            name: s.name,
            state: s.state.as_str().into(),
            latency_ms: s.latency_ms,
            error: s.error,
            checked_at: s.checked_at,
            changed_at: s.changed_at,
        }
    }
}

/// The dashboard's checker. Starts hidden: call `set_visible(true)` while it is on screen.
#[derive(uniffi::Object)]
pub struct HostStatusDashboard {
    monitor: HostStatusMonitor,
}

#[uniffi::export]
impl HostStatusDashboard {
    /// Checks every `interval_secs` (30–3600) while visible.
    #[uniffi::constructor]
    pub fn new(interval_secs: u32) -> Arc<Self> {
        Arc::new(HostStatusDashboard { monitor: HostStatusMonitor::start(RUNTIME.handle(), Duration::from_secs(interval_secs.into())) })
    }

    /// Take the opted-in connections from `library` (call again after edits). Returns how many.
    pub fn load(&self, library: Arc<Library>) -> FfiResult<u32> {
        let targets = library.with_doc(|d| Ok(hoststatus::targets(d)))?;
        let n = u32::try_from(targets.len()).unwrap_or(u32::MAX);
        self.monitor.set_targets(targets);
        Ok(n)
    }

    pub fn set_visible(&self, visible: bool) {
        self.monitor.set_visible(visible)
    }

    pub fn set_interval(&self, interval_secs: u32) {
        self.monitor.set_interval(Duration::from_secs(interval_secs.into()))
    }

    /// Refresh now; has no effect while hidden.
    pub fn check_now(&self) {
        self.monitor.check_now()
    }

    pub fn snapshot(&self) -> Vec<HostStatusView> {
        self.monitor.snapshot().into_iter().map(Into::into).collect()
    }
}
