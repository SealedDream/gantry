//! Wake-on-LAN bridge (`bastion_core::wol`). Settings are ordinary properties (`wol_mac`,
//! `wol_broadcast`, `wol_port`, `wol_secureon`, `wol_before_connect`, `wol_wait_secs`) set with
//! `set_property`; this adds the Wake action and the wait before a connect. Nothing is sent
//! unless one of these calls is made.
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use bastion_core::wol::{self, WakeOutcome};

use crate::{parse_id, FfiResult, Library};

/// What waking a connection would do. The SecureOn password itself is never returned.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct WolPlanView {
    pub mac: String,
    pub broadcast: String,
    pub port: u16,
    pub has_secureon: bool,
    pub before_connect: bool,
    pub wait_secs: u32,
    /// Host and port checked after the packet goes out.
    pub host: String,
    pub check_port: u16,
}

/// Result of `wake_before_connect`.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeResult {
    /// No MAC, or "Wake before connect" is off: connect straight away.
    NotNeeded,
    /// The host answered after this many milliseconds.
    Up { after_ms: u64 },
    /// The wait ran out; the connect may still be tried.
    TimedOut,
    Cancelled,
}

/// Cancels a running `wake_before_connect` (the user pressed Cancel or closed the tab).
#[derive(uniffi::Object, Default)]
pub struct WakeCancel {
    flag: AtomicBool,
}

#[uniffi::export]
impl WakeCancel {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(WakeCancel::default())
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Relaxed);
    }
}

pub(crate) fn plan_view(p: &wol::WakePlan) -> WolPlanView {
    WolPlanView {
        mac: p.target.mac.to_string(),
        broadcast: p.target.broadcast.to_string(),
        port: p.target.port,
        has_secureon: p.target.secureon.is_some(),
        before_connect: p.before_connect,
        wait_secs: p.wait.as_secs() as u32,
        host: p.host.clone(),
        check_port: p.port,
    }
}

pub(crate) fn result_view(o: Option<WakeOutcome>) -> WakeResult {
    match o {
        None => WakeResult::NotNeeded,
        Some(WakeOutcome::Up(d)) => WakeResult::Up { after_ms: d.as_millis() as u64 },
        Some(WakeOutcome::TimedOut) => WakeResult::TimedOut,
        Some(WakeOutcome::Cancelled) => WakeResult::Cancelled,
    }
}

impl Library {
    /// The connection's wake plan, or `None` when no MAC is set. Same rules as `wol::plan_for`.
    pub(crate) fn wake_plan(&self, id: &str) -> FfiResult<Option<wol::WakePlan>> {
        let id = parse_id(id)?;
        self.with_doc(|d| wol::plan_for(d, id))
    }
}

#[uniffi::export]
impl Library {
    /// Production, customer-sensitive or privileged infrastructure (the connection's own
    /// classification): broadcast input and multi-host exec ask before sending to these.
    pub fn connection_sensitive(&self, id: String) -> FfiResult<bool> {
        Ok(self.resolve(parse_id(&id)?)?.classification.is_sensitive())
    }

    /// For the host context menu: `None` hides or disables Wake.
    pub fn wol_plan(&self, id: String) -> FfiResult<Option<WolPlanView>> {
        Ok(self.wake_plan(&id)?.as_ref().map(plan_view))
    }

    /// Wake action: send the magic packet now.
    pub fn wake(&self, id: String) -> FfiResult<()> {
        let plan = self.wake_plan(&id)?;
        let plan = plan.ok_or_else(|| bastion_core::CoreError::Invalid("Wake-on-LAN: set the host's MAC address first.".into()))?;
        Ok(wol::send(&plan.target)?)
    }

    /// Before connecting: wakes the host and waits for it when "Wake before connect" is on.
    /// Blocks up to the wait (≤ 300 s); call it off the main thread. The library is not locked
    /// while waiting.
    pub fn wake_before_connect(&self, id: String, cancel: Arc<WakeCancel>) -> FfiResult<WakeResult> {
        let outcome = match self.wake_plan(&id)? {
            Some(p) if p.before_connect => Some(wol::wake_and_wait(&p.target, &p.host, p.port, p.wait, &cancel.flag)?),
            _ => None,
        };
        Ok(result_view(outcome))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn views_map_outcomes() {
        assert_eq!(result_view(None), WakeResult::NotNeeded);
        assert_eq!(result_view(Some(WakeOutcome::Up(std::time::Duration::from_millis(1500)))), WakeResult::Up { after_ms: 1500 });
        assert_eq!(result_view(Some(WakeOutcome::TimedOut)), WakeResult::TimedOut);
        assert_eq!(result_view(Some(WakeOutcome::Cancelled)), WakeResult::Cancelled);
    }
}
