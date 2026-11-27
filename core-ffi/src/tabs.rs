//! Tab groups bridge (`bastion_core::tabgroups`). The strip and each operation cross as JSON,
//! the same shapes the C ABI takes, so every app shares one set of rules.
use bastion_core::tabgroups::{StripOp, TabStrip};

use crate::{FfiError, FfiResult, Library};

fn parse<T: serde::de::DeserializeOwned>(what: &str, json: &str) -> FfiResult<T> {
    serde_json::from_str(json).map_err(|e| FfiError::failed(format!("invalid {what}: {e}")))
}

fn to_json<T: serde::Serialize>(v: &T) -> FfiResult<String> {
    serde_json::to_string(v).map_err(|e| FfiError::failed(e.to_string()))
}

/// Apply one strip operation (`{"op":"newGroup",…}`) to `strip_json`
/// (`{"tabs":[{"id","connection","group","detached"}],"groups":[{"id","name","color","collapsed","folder"}]}`).
/// Returns `{"strip":…,"closed":[tab ids the app must close]}`.
#[uniffi::export]
pub fn tab_strip_apply(strip_json: String, op_json: String) -> FfiResult<String> {
    let strip: TabStrip = parse("tab strip", &strip_json)?;
    let op: StripOp = parse("tab operation", &op_json)?;
    to_json(&strip.apply(&op)?)
}

/// The eight group colours as `[[id, label]]`, in menu order.
#[uniffi::export]
pub fn tab_group_colors() -> Vec<Vec<String>> {
    bastion_core::tabgroups::GROUP_COLORS.iter().map(|(id, label)| vec![id.to_string(), label.to_string()]).collect()
}

#[uniffi::export]
impl Library {
    /// Folder auto-grouping over this library (setting `tabs.auto-group` → `enabled`).
    /// Returns the new strip as JSON.
    pub fn tab_strip_auto_group(&self, strip_json: String, enabled: bool) -> FfiResult<String> {
        let strip: TabStrip = parse("tab strip", &strip_json)?;
        let grouped = strip.auto_grouped(&self.lock(), enabled)?;
        to_json(&grouped)
    }
}
