//! Result data held by the core (spec section 5, "Caps"; T18.4).
//!
//! Capped at 256 MiB per view, 256 MiB across one plugin's views and 512 MiB in total. When a
//! view would pass a cap, the plugin gets a bare `invalid("result too large")` with no names;
//! only the core's own UI names the tabs that hold the most (tab names are entry names, often
//! customer names, and never go to a plugin: T18.16, boundary 7).

use std::collections::BTreeMap;

use super::Failure;

pub const MAX_RESULT_BYTES_PER_VIEW: u64 = 256 * 1024 * 1024;
pub const MAX_RESULT_BYTES_PER_PLUGIN: u64 = 256 * 1024 * 1024;
pub const MAX_RESULT_BYTES_TOTAL: u64 = 512 * 1024 * 1024;

/// The bare failure a plugin gets.
pub fn result_too_large() -> Failure {
    Failure::Invalid("result too large".into())
}

/// A refused reservation: what the plugin gets, and what the core shows in its own UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TooLarge {
    /// For the plugin: always [`result_too_large`].
    pub plugin_failure: Failure,
    /// For the core's own message only: the views holding the most result data, largest first
    /// (at most three). Never handed to a plugin.
    pub core_largest_views: Vec<(u64, u64)>,
}

/// The core's ledger of result data, keyed by (view id, plugin id), so a view id can never
/// carry another plugin's bytes.
#[derive(Debug, Default)]
pub struct ResultLedger {
    views: BTreeMap<(u64, String), u64>,
}

impl ResultLedger {
    pub fn new() -> ResultLedger {
        ResultLedger::default()
    }

    fn plugin_total(&self, plugin_id: &str) -> u64 {
        self.views.iter().filter(|((_, p), _)| p == plugin_id).map(|(_, b)| *b).sum()
    }

    fn total(&self) -> u64 {
        self.views.values().sum()
    }

    /// Reserve `bytes` more for `view_id` of `plugin_id`.
    pub fn reserve(&mut self, view_id: u64, plugin_id: &str, bytes: u64) -> Result<(), TooLarge> {
        let key = (view_id, plugin_id.to_string());
        let held = self.views.get(&key).copied().unwrap_or(0);
        let over = held.saturating_add(bytes) > MAX_RESULT_BYTES_PER_VIEW
            || self.plugin_total(plugin_id).saturating_add(bytes) > MAX_RESULT_BYTES_PER_PLUGIN
            || self.total().saturating_add(bytes) > MAX_RESULT_BYTES_TOTAL;
        if over {
            let mut largest: Vec<(u64, u64)> = self.views.iter().map(|((v, _), b)| (*v, *b)).filter(|(_, b)| *b > 0).collect();
            largest.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            largest.truncate(3);
            return Err(TooLarge { plugin_failure: result_too_large(), core_largest_views: largest });
        }
        *self.views.entry(key).or_insert(0) += bytes;
        Ok(())
    }

    /// The view dropped its results (a new query) or closed.
    pub fn release_view(&mut self, view_id: u64) {
        self.views.retain(|(v, _), _| *v != view_id);
    }

    pub fn held(&self, view_id: u64) -> u64 {
        self.views.iter().filter(|((v, _), _)| *v == view_id).map(|(_, b)| *b).sum()
    }
}
